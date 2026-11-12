package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Server-side limits for repo_property_filters (agent-api
// validateAndNormalizeRunPolicyScope); checking them here fails at plan time
// instead of as a 400 on apply.
const (
	maxRepoPropertyFilters      = 10
	maxRepoPropertyFilterValues = 50
	maxRepoPropertyTokenLength  = 75
)

// repoPropertyFilterObjectType is the element type of repo_property_filters.
var repoPropertyFilterObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"name":   types.StringType,
	"values": types.SetType{ElemType: types.StringType},
	"match":  types.StringType,
	"join":   types.StringType,
}}

// repoPropertyFilterModel mirrors one repo_property_filters element.
type repoPropertyFilterModel struct {
	Name   types.String `tfsdk:"name"`
	Values types.Set    `tfsdk:"values"`
	Match  types.String `tfsdk:"match"`
	Join   types.String `tfsdk:"join"`
}

func repoPropertyFiltersSchemaAttribute() schema.ListNestedAttribute {
	token := []validator.String{
		// Characters, not bytes: GitHub and the backend cap names and values
		// at 75 characters, so a non-ASCII value must not count per byte.
		stringvalidator.UTF8LengthBetween(1, maxRepoPropertyTokenLength),
		noSurroundingWhitespace,
		trimmedToken{},
	}
	return schema.ListNestedAttribute{
		Optional: true,
		MarkdownDescription: "Applies the policy to repositories whose GitHub custom properties match this rule, " +
			"including repositories tagged later. Rows are combined in order: each row after the first says how it " +
			"joins the previous one (`and` or `or`), and `and` binds before `or`. Property names ignore case; values " +
			"match exactly. Cannot be combined with `all_repos`, `repositories` or `all_orgs`. When a run's " +
			"repository properties cannot be resolved, the policy is not applied to that run.",
		Validators: []validator.List{
			listvalidator.SizeBetween(1, maxRepoPropertyFilters),
		},
		NestedObject: schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"name": schema.StringAttribute{
					Required:            true,
					MarkdownDescription: "The custom property name (case-insensitive).",
					Validators:          token,
				},
				"values": schema.SetAttribute{
					ElementType:         types.StringType,
					Required:            true,
					MarkdownDescription: "Values to match exactly (case-sensitive).",
					Validators: []validator.Set{
						setvalidator.SizeBetween(1, maxRepoPropertyFilterValues),
						setvalidator.ValueStringsAre(token...),
					},
				},
				"match": schema.StringAttribute{
					Optional:            true,
					Computed:            true,
					Default:             stringdefault.StaticString("any"),
					MarkdownDescription: "`any` (default): the repository has at least one of `values`. `all`: it has every value (multi-select properties).",
					Validators:          []validator.String{stringvalidator.OneOf("any", "all")},
				},
				"join": schema.StringAttribute{
					Optional:            true,
					Computed:            true,
					MarkdownDescription: "How this row combines with the previous row: `and` (default) or `or`. Omit on the first row.",
					Validators:          []validator.String{stringvalidator.OneOf("and", "or")},
				},
			},
		},
	}
}

// validateRepoPropertyFiltersConfig reports the scope combinations and rule
// shapes the backend rejects.
func validateRepoPropertyFiltersConfig(ctx context.Context, cfg githubRunPolicyResourceModel, diags *diag.Diagnostics) {
	if cfg.RepoPropertyFilters.IsNull() || cfg.RepoPropertyFilters.IsUnknown() {
		return
	}
	attrPath := path.Root("repo_property_filters")
	if cfg.AllRepos.ValueBool() || cfg.AllOrgs.ValueBool() ||
		(!cfg.Repositories.IsNull() && !cfg.Repositories.IsUnknown() && len(cfg.Repositories.Elements()) > 0) {
		diags.AddAttributeError(attrPath, "Conflicting repository scope",
			"repo_property_filters cannot be combined with all_repos, repositories or all_orgs.")
	}

	seen := map[string]bool{}
	// Elements may be unknown at validate time (built from other resources);
	// skip those rather than failing the conversion.
	for i, elem := range cfg.RepoPropertyFilters.Elements() {
		obj, ok := elem.(types.Object)
		if !ok || obj.IsNull() || obj.IsUnknown() {
			continue
		}
		var row repoPropertyFilterModel
		if d := obj.As(ctx, &row, basetypes.ObjectAsOptions{}); d.HasError() {
			diags.Append(d...)
			return
		}
		if i == 0 && !row.Join.IsNull() && !row.Join.IsUnknown() {
			diags.AddAttributeError(attrPath.AtListIndex(0).AtName("join"), "Invalid join on the first row",
				"join says how a row combines with the previous row, so it must be omitted on the first row.")
		}
		if row.Name.IsNull() || row.Name.IsUnknown() {
			continue
		}
		key := strings.ToLower(row.Name.ValueString())
		if seen[key] {
			diags.AddAttributeError(attrPath.AtListIndex(i).AtName("name"), "Duplicate property",
				fmt.Sprintf("property %q appears in more than one row; property names are case-insensitive.", row.Name.ValueString()))
		}
		seen[key] = true
	}
}

// expandRepoPropertyFilters converts the planned rule into API rows. A null
// rule becomes an empty, non-nil slice so an update clears a stored rule.
func expandRepoPropertyFilters(ctx context.Context, list types.List, diags *diag.Diagnostics) []stepsecurityapi.RepoPropertyFilter {
	out := []stepsecurityapi.RepoPropertyFilter{}
	if list.IsNull() || list.IsUnknown() {
		return out
	}
	var rows []repoPropertyFilterModel
	diags.Append(list.ElementsAs(ctx, &rows, false)...)
	for _, row := range rows {
		var values []string
		diags.Append(row.Values.ElementsAs(ctx, &values, false)...)
		out = append(out, stepsecurityapi.RepoPropertyFilter{
			Name:   row.Name.ValueString(),
			Values: values,
			Match:  row.Match.ValueString(),
			Join:   row.Join.ValueString(),
		})
	}
	return out
}

// flattenRepoPropertyFilters converts the stored rule to state. The backend
// clears join on the first row, which lands as null to match the config.
func flattenRepoPropertyFilters(filters []stepsecurityapi.RepoPropertyFilter, diags *diag.Diagnostics) types.List {
	if len(filters) == 0 {
		return types.ListNull(repoPropertyFilterObjectType)
	}
	rows := make([]attr.Value, 0, len(filters))
	for i, f := range filters {
		join := types.StringNull()
		if i > 0 {
			join = types.StringValue(f.Join)
		}
		match := f.Match
		if match == "" {
			match = "any"
		}
		row, d := types.ObjectValue(repoPropertyFilterObjectType.AttrTypes, map[string]attr.Value{
			"name":   types.StringValue(f.Name),
			"values": stringSetValueOrNull(f.Values, diags),
			"match":  types.StringValue(match),
			"join":   join,
		})
		diags.Append(d...)
		rows = append(rows, row)
	}
	list, d := types.ListValue(repoPropertyFilterObjectType, rows)
	diags.Append(d...)
	return list
}

func (r *githubRunPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg githubRunPolicyResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	validateRepoPropertyFiltersConfig(ctx, cfg, &resp.Diagnostics)
}

// trimmedToken rejects names and values the API would trim. strings.TrimSpace
// is Unicode-aware, so it also catches non-breaking and em spaces that the
// shared \S-based validator lets through.
type trimmedToken struct{}

func (trimmedToken) Description(context.Context) string {
	return "must not have leading or trailing whitespace"
}

func (v trimmedToken) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v trimmedToken) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if s := req.ConfigValue.ValueString(); s != strings.TrimSpace(s) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", v.Description(ctx))
	}
}

var _ resource.ResourceWithModifyPlan = &githubRunPolicyResource{}

// ModifyPlan resolves an omitted join to what the API stores: null on the
// first row and "and" on later rows. join is Optional+Computed, so without
// this a removed join keeps its prior value and the plan shows no change.
func (r *githubRunPolicyResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	attrPath := path.Root("repo_property_filters")
	var cfg, planned types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, attrPath, &cfg)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, attrPath, &planned)...)
	if resp.Diagnostics.HasError() || cfg.IsNull() || cfg.IsUnknown() || planned.IsNull() || planned.IsUnknown() {
		return
	}
	cfgRows, planRows := cfg.Elements(), planned.Elements()
	if len(cfgRows) != len(planRows) {
		return
	}
	rows := make([]attr.Value, len(planRows))
	changed := false
	for i, el := range planRows {
		rows[i] = el
		row, ok := el.(types.Object)
		cfgRow, cfgOK := cfgRows[i].(types.Object)
		if !ok || !cfgOK || row.IsNull() || row.IsUnknown() || cfgRow.IsNull() || cfgRow.IsUnknown() {
			continue
		}
		if j, ok := cfgRow.Attributes()["join"]; !ok || !j.IsNull() {
			continue
		}
		want := types.StringValue("and")
		if i == 0 {
			want = types.StringNull()
		}
		attrs := make(map[string]attr.Value, len(row.Attributes()))
		for k, v := range row.Attributes() {
			attrs[k] = v
		}
		if attrs["join"].Equal(want) {
			continue
		}
		attrs["join"] = want
		obj, d := types.ObjectValue(repoPropertyFilterObjectType.AttrTypes, attrs)
		resp.Diagnostics.Append(d...)
		rows[i] = obj
		changed = true
	}
	if !changed || resp.Diagnostics.HasError() {
		return
	}
	list, d := types.ListValue(repoPropertyFilterObjectType, rows)
	resp.Diagnostics.Append(d...)
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, attrPath, list)...)
	// The framework only marks computed fields unknown when the plan already
	// differed from state; this change can be the only one, so the update
	// stamps must be marked here or apply reports an inconsistent result.
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("last_updated_at"), types.StringUnknown())...)
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("last_updated_by"), types.StringUnknown())...)
}
