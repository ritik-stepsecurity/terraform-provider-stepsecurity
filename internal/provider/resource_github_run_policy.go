package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &githubRunPolicyResource{}
	_ resource.ResourceWithConfigure      = &githubRunPolicyResource{}
	_ resource.ResourceWithImportState    = &githubRunPolicyResource{}
	_ resource.ResourceWithValidateConfig = &githubRunPolicyResource{}
)

// NewGithubRunPolicyResource is a helper function to simplify the provider implementation.
func NewGithubRunPolicyResource() resource.Resource {
	return &githubRunPolicyResource{}
}

// githubRunPolicyResource is the resource implementation.
type githubRunPolicyResource struct {
	client stepsecurityapi.Client
}

// githubRunPolicyResourceModel maps the resource schema data.
type githubRunPolicyResourceModel struct {
	Owner               types.String `tfsdk:"owner"`
	Name                types.String `tfsdk:"name"`
	PolicyID            types.String `tfsdk:"policy_id"`
	AllRepos            types.Bool   `tfsdk:"all_repos"`
	AllOrgs             types.Bool   `tfsdk:"all_orgs"`
	Repositories        types.List   `tfsdk:"repositories"`
	RepoPropertyFilters types.List   `tfsdk:"custom_property_rule"`
	PolicyConfig        types.Object `tfsdk:"policy_config"`
	CreatedBy           types.String `tfsdk:"created_by"`
	CreatedAt           types.String `tfsdk:"created_at"`
	LastUpdatedBy       types.String `tfsdk:"last_updated_by"`
	LastUpdatedAt       types.String `tfsdk:"last_updated_at"`
}

// policyConfigModel maps the policy configuration data.
type policyConfigModel struct {
	Owner                          types.String `tfsdk:"owner"`
	Name                           types.String `tfsdk:"name"`
	EnableActionPolicy             types.Bool   `tfsdk:"enable_action_policy"`
	AllowedActions                 types.Map    `tfsdk:"allowed_actions"`
	EnableHardenRunnerPolicy       types.Bool   `tfsdk:"enable_harden_runner_policy"`
	HardenRunnerTargetLabels       types.Set    `tfsdk:"harden_runner_target_labels"`
	HardenRunnerExcludedLabels     types.Set    `tfsdk:"harden_runner_excluded_labels"`
	HardenRunnerCustomActions      types.Set    `tfsdk:"harden_runner_custom_actions"`
	EnableRunsOnPolicy             types.Bool   `tfsdk:"enable_runs_on_policy"`
	DisallowedRunnerLabels         types.Set    `tfsdk:"disallowed_runner_labels"`
	EnableStandardRunnerLabels     types.Bool   `tfsdk:"enable_standard_runner_labels"`
	EnableSecretsPolicy            types.Bool   `tfsdk:"enable_secrets_policy"`
	EnableCompromisedActionsPolicy types.Bool   `tfsdk:"enable_compromised_actions_policy"`
	RequirePinnedActions           types.Bool   `tfsdk:"require_pinned_actions"`
	PinnedActionsExemptions        types.Set    `tfsdk:"actions_to_exempt_while_pinning"`
	IsDryRun                       types.Bool   `tfsdk:"is_dry_run"`
	ExemptedUsers                  types.Set    `tfsdk:"exempted_users"`
	BulkSecretsOnlyMode            types.Bool   `tfsdk:"bulk_secrets_only_mode"`
	PrCommentTemplate              types.String `tfsdk:"pr_comment_template"`
	RunsOnMode                     types.String `tfsdk:"runs_on_mode"`
	AllowedRunnerLabels            types.Set    `tfsdk:"allowed_runner_labels"`
	AllowedRunnerConstraints       types.Map    `tfsdk:"allowed_runner_constraints"`
	RequirePolicyStore             types.Bool   `tfsdk:"require_policy_store"`
	BlockJobContainer              types.Bool   `tfsdk:"block_job_container"`
	SecretsAnalyzeDefaultBranch    types.Bool   `tfsdk:"secrets_analyze_default_branch"`
	EnforceMethod                  types.String `tfsdk:"enforce_method"`
	PrejobAllowedRunnerLabels      types.Set    `tfsdk:"prejob_allowed_runner_labels"`
	PrejobDisallowedRunnerLabels   types.Set    `tfsdk:"prejob_disallowed_runner_labels"`
	RunnerLabelRequirements        types.List   `tfsdk:"runner_label_requirements"`
}

// runnerLabelRequirementObjectType is the element type of runner_label_requirements.
var runnerLabelRequirementObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"if_label_matches": types.StringType,
	"require_labels":   types.SetType{ElemType: types.StringType},
	"forbid_labels":    types.SetType{ElemType: types.StringType},
}}

// noSurroundingWhitespace rejects values the server would silently trim;
// without it a padded label plans one value and reads back another, which
// surfaces as an inconsistent-result error after apply.
var noSurroundingWhitespace = stringvalidator.RegexMatches(
	regexp.MustCompile(`^\S(.*\S)?$`),
	"must not contain leading or trailing whitespace or line breaks",
)

// runnerLabelRequirementModel mirrors one runner_label_requirements element.
type runnerLabelRequirementModel struct {
	IfLabelMatches types.String `tfsdk:"if_label_matches"`
	RequireLabels  types.Set    `tfsdk:"require_labels"`
	ForbidLabels   types.Set    `tfsdk:"forbid_labels"`
}

// stringSetValueOrNull converts a server string slice into a Set, null when empty
// (the backend omits empty lists, so null keeps the round-trip drift-free).
func stringSetValueOrNull(values []string, diags *diag.Diagnostics) types.Set {
	if len(values) == 0 {
		return types.SetNull(types.StringType)
	}
	elems := make([]attr.Value, len(values))
	for i, v := range values {
		elems[i] = types.StringValue(v)
	}
	setValue, setDiags := types.SetValue(types.StringType, elems)
	diags.Append(setDiags...)
	return setValue
}

// flattenRunnerLabelRequirements converts the server's rules into the state
// list. previous (the prior state's rules, optional) preserves the empty-vs-null
// signal of a rule's require/forbid sets: a planned empty set round-trips as
// omitted JSON, and index-plus-pattern matching keeps it from drifting to null.
func flattenRunnerLabelRequirements(ctx context.Context, rules []stepsecurityapi.RunnerLabelRequirement, previous []runnerLabelRequirementModel, diags *diag.Diagnostics) types.List {
	if rules == nil {
		return types.ListNull(runnerLabelRequirementObjectType)
	}
	previousEmptySet := func(prev types.Set) bool {
		if prev.IsNull() || prev.IsUnknown() {
			return false
		}
		var values []string
		// A parse failure on PREVIOUS state only disables preservation for this
		// value; it must neither consult nor pollute the shared diagnostics.
		if prev.ElementsAs(ctx, &values, false).HasError() {
			return false
		}
		return len(values) == 0
	}
	emptyStringSet := func() types.Set {
		setValue, setDiags := types.SetValue(types.StringType, []attr.Value{})
		diags.Append(setDiags...)
		return setValue
	}
	elems := make([]attr.Value, 0, len(rules))
	for i, rule := range rules {
		requireValue := stringSetValueOrNull(rule.RequireLabels, diags)
		forbidValue := stringSetValueOrNull(rule.ForbidLabels, diags)
		if len(previous) == len(rules) && previous[i].IfLabelMatches.ValueString() == rule.IfLabelMatches {
			if len(rule.RequireLabels) == 0 && previousEmptySet(previous[i].RequireLabels) {
				requireValue = emptyStringSet()
			}
			if len(rule.ForbidLabels) == 0 && previousEmptySet(previous[i].ForbidLabels) {
				forbidValue = emptyStringSet()
			}
		}
		obj, objDiags := types.ObjectValue(runnerLabelRequirementObjectType.AttrTypes, map[string]attr.Value{
			"if_label_matches": types.StringValue(rule.IfLabelMatches),
			"require_labels":   requireValue,
			"forbid_labels":    forbidValue,
		})
		diags.Append(objDiags...)
		elems = append(elems, obj)
	}
	listValue, listDiags := types.ListValue(runnerLabelRequirementObjectType, elems)
	diags.Append(listDiags...)
	return listValue
}

// expandRunnerLabelRequirements converts the planned rules into API form.
func expandRunnerLabelRequirements(ctx context.Context, list types.List, diags *diag.Diagnostics) []stepsecurityapi.RunnerLabelRequirement {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var rows []runnerLabelRequirementModel
	diags.Append(list.ElementsAs(ctx, &rows, false)...)
	if diags.HasError() {
		return nil
	}
	rules := make([]stepsecurityapi.RunnerLabelRequirement, 0, len(rows))
	for _, row := range rows {
		rule := stepsecurityapi.RunnerLabelRequirement{IfLabelMatches: row.IfLabelMatches.ValueString()}
		if !row.RequireLabels.IsNull() {
			diags.Append(row.RequireLabels.ElementsAs(ctx, &rule.RequireLabels, false)...)
		}
		if !row.ForbidLabels.IsNull() {
			diags.Append(row.ForbidLabels.ElementsAs(ctx, &rule.ForbidLabels, false)...)
		}
		rules = append(rules, rule)
	}
	return rules
}

// expandPrejobAndRequirementFields copies the prejob scoping lists and the
// conditional label requirements from the plan into an API policy config.
func expandPrejobAndRequirementFields(ctx context.Context, policyConfig policyConfigModel, cfg *stepsecurityapi.RunPolicyConfig, diags *diag.Diagnostics) {
	if !policyConfig.PrejobAllowedRunnerLabels.IsNull() {
		diags.Append(policyConfig.PrejobAllowedRunnerLabels.ElementsAs(ctx, &cfg.PrejobAllowedRunnerLabels, false)...)
	}
	if !policyConfig.PrejobDisallowedRunnerLabels.IsNull() {
		diags.Append(policyConfig.PrejobDisallowedRunnerLabels.ElementsAs(ctx, &cfg.PrejobDisallowedRunnerLabels, false)...)
	}
	cfg.RunnerLabelRequirements = expandRunnerLabelRequirements(ctx, policyConfig.RunnerLabelRequirements, diags)
}

// Metadata returns the resource type name.
func (r *githubRunPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_run_policy"
}

// Schema defines the schema for the resource.
func (r *githubRunPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a GitHub Actions run policy in StepSecurity.",
		Attributes: map[string]schema.Attribute{
			"owner": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The GitHub organization or user that owns this policy.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the run policy.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"policy_id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier for this policy generated by StepSecurity.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"all_repos": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether this policy applies to all repositories in the organization.",
			},
			"all_orgs": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Whether this policy applies to all organizations.",
			},
			"repositories": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "List of specific repositories this policy applies to.",
			},
			"custom_property_rule": repoPropertyFiltersSchemaAttribute(),
			"policy_config": schema.SingleNestedAttribute{
				Required:            true,
				MarkdownDescription: "The configuration for this run policy.",
				Attributes: map[string]schema.Attribute{
					"owner": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "The owner of the policy configuration.",
					},
					"name": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "The name of the policy configuration.",
					},
					"enable_action_policy": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Whether to enable the action policy.",
					},
					"allowed_actions": schema.MapAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Map of allowed actions and their permissions (e.g., `\"actions/checkout\" = \"allow\"`). Keys support exact match (`actions/checkout@v4`), name-only match (`actions/checkout`, any ref), owner wildcard (`my-org/*`), and global wildcard (`*/*`, every action). Use `*/*` to allow all actions while still enforcing `require_pinned_actions`.",
					},
					"enable_harden_runner_policy": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Whether to enable the Harden Runner policy.",
					},
					"harden_runner_target_labels": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Set of runner labels that target Harden Runner enforcement. Set to `[]` to apply the policy to every job; set a non-empty list to filter to jobs whose `runs-on` matches at least one label. Omitting the attribute leaves any existing backend value untouched (additive-only).",
					},
					"harden_runner_excluded_labels": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						Computed:            true,
						MarkdownDescription: "Set of runner labels excluded from Harden Runner enforcement. A job whose `runs-on` matches any entry is skipped, regardless of `harden_runner_target_labels`, so an org-wide policy can carve out runners that cannot run Harden Runner. Entries support a `*` wildcard (e.g. `custom-runner-*`), match case-insensitively, and are also tested against labels containing `${{ }}` expressions. A lone `*` is rejected because it would exclude every job. Set to `[]` to clear the exclusions; omitting the attribute leaves any existing backend value untouched.",
						PlanModifiers: []planmodifier.Set{
							setplanmodifier.UseStateForUnknown(),
						},
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(excludedRunnerLabel()),
						},
					},
					"harden_runner_custom_actions": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Set of custom actions accepted as Harden Runner equivalents (in addition to `step-security/harden-runner`).",
					},
					"enable_runs_on_policy": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Whether to enable the runs-on policy.",
					},
					"disallowed_runner_labels": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Set of disallowed runner labels.",
					},
					"enable_standard_runner_labels": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "When true, the GitHub-hosted standard runner label set (ubuntu-latest, windows-latest, macos-*, arm variants, ...; kept up to date automatically) is added to `disallowed_runner_labels` (runs-on policy) and `harden_runner_target_labels` (Harden Runner policy) at evaluation time.",
					},
					"enable_secrets_policy": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Whether to enable the secrets policy.",
					},
					"enable_compromised_actions_policy": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Whether to enable the compromised actions policy.",
					},
					"require_pinned_actions": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Whether to require all actions to be pinned to full-length commit SHAs. Sub-feature of the allowed actions policy — only meaningful when `enable_action_policy` is true.",
					},
					"actions_to_exempt_while_pinning": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Set of actions exempt from pinning requirements. Supports exact match (e.g., `actions/checkout@v4`), name-only match (e.g., `actions/checkout`), and owner wildcard (e.g., `my-org/*`). The global wildcard `*/*` is **rejected** by the API here: it would exempt every action from pinning, leaving `require_pinned_actions` enabled but enforcing nothing. To allow any action while still requiring pins, put `*/*` in `allowed_actions` instead.",
					},
					"is_dry_run": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Whether this policy is in dry-run mode.",
					},
					"bulk_secrets_only_mode": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "When enabled, the secret exfiltration policy restricts enforcement to high-risk bulk secret-exposure attempts rather than all secret references. See the StepSecurity run-policies documentation for details.",
					},
					"pr_comment_template": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString(""),
						MarkdownDescription: "Optional custom template for the pull request comment posted when this policy blocks a run. Supports placeholder substitution; leave empty to use the default StepSecurity comment.",
					},
					"exempted_users": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Set of exempted users (can be bots/usernames) for the secrets exfiltration policy. These users will not be subject to the secrets policy checks.",
					},
					"runs_on_mode": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString(""),
						MarkdownDescription: "Controls how the runs-on policy evaluates runner labels. `disallowed` (the default; an empty string is treated the same) blocks jobs whose `runs-on` matches `disallowed_runner_labels`. `allowed` instead only permits jobs whose `runs-on` matches `allowed_runner_labels` / `allowed_runner_constraints`. Only meaningful when `enable_runs_on_policy` is true.",
						Validators: []validator.String{
							stringvalidator.OneOf("", "disallowed", "allowed"),
						},
					},
					"allowed_runner_labels": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "Set of plain runner labels permitted when `runs_on_mode` is `allowed` (e.g. `ubuntu-latest`). A job is allowed when its `runs-on` label matches an entry verbatim. Ignored in `disallowed` mode.",
					},
					"allowed_runner_constraints": schema.MapAttribute{
						ElementType:         types.SetType{ElemType: types.StringType},
						Optional:            true,
						MarkdownDescription: "Structured runs-on.com constraints permitted when `runs_on_mode` is `allowed`, keyed by dimension (e.g. `family`, `cpu`, `image`). Each key maps to the set of allowed values for that dimension: a `runs-on` token of the form `key=value` is allowed when the key is unconfigured, or when its value is in the set. Keys are lowercased server-side (use lowercase keys to avoid plan drift) and each key must have at least one value. Expression values are matched by their exact text (whitespace-insensitive), so the `runs-on` routing key itself can be pinned to the conventional expression.",
					},
					"require_policy_store": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Sub-feature of the Harden Runner policy. When true, every targeted job's Harden Runner step must set `use-policy-store: true`; a missing or non-`true` value is a violation. The legacy `policy:` input does not satisfy this check. Only meaningful when `enable_harden_runner_policy` is true.",
					},
					"block_job_container": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Sub-feature of the Harden Runner policy. When true, targeted jobs that run entirely inside a job-level `container:` are blocked, because Harden Runner cannot monitor a fully containerized job on GitHub-hosted standard runners. Steps that use containers are unaffected. Only meaningful when `enable_harden_runner_policy` is true.",
					},
					"secrets_analyze_default_branch": schema.BoolAttribute{
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(false),
						MarkdownDescription: "Sub-feature of the secrets policy. When true, runs on the repository default branch are also evaluated (by default only non-default-branch runs are). Honors `bulk_secrets_only_mode` and `exempted_users`. Only meaningful when `enable_secrets_policy` is true.",
					},
					"enforce_method": schema.StringAttribute{
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString(""),
						MarkdownDescription: "How a blocked run is stopped. `api` (the default; an empty string is treated the same) cancels via the GitHub API. `prejob` defers cancellation to the StepSecurity prejob hook on the runner for eligible runs; standard GitHub-hosted runners always fall back to API cancellation.",
						Validators: []validator.String{
							stringvalidator.OneOf("", "api", "prejob"),
						},
					},
					"prejob_allowed_runner_labels": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "With `enforce_method = \"prejob\"`: only runs whose jobs all use these resolved runner labels defer cancellation to the prejob hook; other runs are cancelled via the API. Mutually exclusive with `prejob_disallowed_runner_labels`; omit both to defer for all non-standard-hosted runners. Expressions are not allowed. Labels are trimmed server-side and deduplicated case-insensitively (first occurrence wins); use trimmed, consistently cased values to avoid plan drift.",
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(noSurroundingWhitespace),
							caseInsensitiveUnique(),
							setvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("prejob_disallowed_runner_labels")),
						},
					},
					"prejob_disallowed_runner_labels": schema.SetAttribute{
						ElementType:         types.StringType,
						Optional:            true,
						MarkdownDescription: "With `enforce_method = \"prejob\"`: runs with any job on these resolved runner labels are cancelled via the API instead of deferring to the prejob hook. Mutually exclusive with `prejob_allowed_runner_labels`. Labels are trimmed server-side and deduplicated case-insensitively (first occurrence wins); use trimmed, consistently cased values to avoid plan drift.",
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(noSurroundingWhitespace),
							caseInsensitiveUnique(),
							setvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("prejob_allowed_runner_labels")),
						},
					},
					"runner_label_requirements": schema.ListNestedAttribute{
						Optional:            true,
						MarkdownDescription: "Conditional label rules evaluated per job in both runs-on modes, on top of the allow/block lists: when any of a job's runner labels matches `if_label_matches`, the rule's required labels must all be present on that job (or its forbidden labels absent), otherwise the run is blocked. Example: labels matching `codebuild-*` require `buildspec-override:true`. Only meaningful when `enable_runs_on_policy` is true.",
						NestedObject: schema.NestedAttributeObject{
							Validators: []validator.Object{
								runnerLabelRequirementRule(),
							},
							Attributes: map[string]schema.Attribute{
								"if_label_matches": schema.StringAttribute{
									Required:            true,
									MarkdownDescription: "Anchored glob tested against each of the job's runner labels; `*` matches any text. Expressions are not allowed, use `*` wildcards instead. The pattern is trimmed server-side.",
									Validators: []validator.String{
										noSurroundingWhitespace,
									},
								},
								"require_labels": schema.SetAttribute{
									ElementType:         types.StringType,
									Optional:            true,
									MarkdownDescription: "Labels that must all be present on a matching job (exact match). A rule uses either required or forbidden labels, not both. Labels are trimmed and deduplicated case-insensitively server-side.",
									Validators: []validator.Set{
										setvalidator.ValueStringsAre(noSurroundingWhitespace),
										caseInsensitiveUnique(),
										setvalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("forbid_labels")),
									},
								},
								"forbid_labels": schema.SetAttribute{
									ElementType:         types.StringType,
									Optional:            true,
									MarkdownDescription: "Labels that must not be present on a matching job (exact match). A rule uses either required or forbidden labels, not both. Labels are trimmed and deduplicated case-insensitively server-side.",
									Validators: []validator.Set{
										setvalidator.ValueStringsAre(noSurroundingWhitespace),
										caseInsensitiveUnique(),
									},
								},
							},
						},
					},
				},
			},
			"created_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who created this policy.",
			},
			"created_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when this policy was created.",
			},
			"last_updated_by": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The user who last updated this policy.",
			},
			"last_updated_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The timestamp when this policy was last updated.",
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *githubRunPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(stepsecurityapi.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected stepsecurityapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

// Create creates the resource and sets the initial Terraform state.
func (r *githubRunPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan githubRunPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract policy configuration
	var policyConfig policyConfigModel
	diags = plan.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert to API request format
	createRequest := stepsecurityapi.CreateRunPolicyRequest{
		Name:     plan.Name.ValueString(),
		AllRepos: plan.AllRepos.ValueBool(),
		AllOrgs:  plan.AllOrgs.ValueBool(),
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                          policyConfig.Owner.ValueString(),
			Name:                           policyConfig.Name.ValueString(),
			EnableActionPolicy:             policyConfig.EnableActionPolicy.ValueBool(),
			EnableHardenRunnerPolicy:       policyConfig.EnableHardenRunnerPolicy.ValueBool(),
			EnableRunsOnPolicy:             policyConfig.EnableRunsOnPolicy.ValueBool(),
			EnableStandardRunnerLabels:     policyConfig.EnableStandardRunnerLabels.ValueBool(),
			EnableSecretsPolicy:            policyConfig.EnableSecretsPolicy.ValueBool(),
			EnableCompromisedActionsPolicy: policyConfig.EnableCompromisedActionsPolicy.ValueBool(),
			RequirePinnedActions:           policyConfig.RequirePinnedActions.ValueBool(),
			IsDryRun:                       policyConfig.IsDryRun.ValueBool(),
			BulkSecretsOnlyMode:            policyConfig.BulkSecretsOnlyMode.ValueBool(),
			PrCommentTemplate:              policyConfig.PrCommentTemplate.ValueString(),
			RunsOnMode:                     policyConfig.RunsOnMode.ValueString(),
			RequirePolicyStore:             policyConfig.RequirePolicyStore.ValueBool(),
			BlockJobContainer:              policyConfig.BlockJobContainer.ValueBool(),
			SecretsAnalyzeDefaultBranch:    policyConfig.SecretsAnalyzeDefaultBranch.ValueBool(),
			EnforceMethod:                  policyConfig.EnforceMethod.ValueString(),
		},
	}

	// Handle repositories list
	if !plan.Repositories.IsNull() {
		var repos []string
		diags = plan.Repositories.ElementsAs(ctx, &repos, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.Repositories = repos
	}
	if !plan.RepoPropertyFilters.IsNull() {
		createRequest.RepoPropertyFilters = expandRepoPropertyFilters(ctx, plan.RepoPropertyFilters, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Handle allowed actions map
	if !policyConfig.AllowedActions.IsNull() {
		var allowedActions map[string]string
		diags = policyConfig.AllowedActions.ElementsAs(ctx, &allowedActions, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.PolicyConfig.AllowedActions = allowedActions
	}

	if !policyConfig.HardenRunnerTargetLabels.IsNull() {
		var hardenRunnerTargetLabels []string
		diags = policyConfig.HardenRunnerTargetLabels.ElementsAs(ctx, &hardenRunnerTargetLabels, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.PolicyConfig.HardenRunnerTargetLabels = hardenRunnerTargetLabels
	}

	if !policyConfig.HardenRunnerExcludedLabels.IsNull() && !policyConfig.HardenRunnerExcludedLabels.IsUnknown() {
		var hardenRunnerExcludedLabels []string
		diags = policyConfig.HardenRunnerExcludedLabels.ElementsAs(ctx, &hardenRunnerExcludedLabels, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.PolicyConfig.HardenRunnerExcludedLabels = hardenRunnerExcludedLabels
	}

	if !policyConfig.HardenRunnerCustomActions.IsNull() {
		var hardenRunnerCustomActions []string
		diags = policyConfig.HardenRunnerCustomActions.ElementsAs(ctx, &hardenRunnerCustomActions, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.PolicyConfig.HardenRunnerCustomActions = hardenRunnerCustomActions
	}

	// Handle disallowed runner labels set
	if !policyConfig.DisallowedRunnerLabels.IsNull() {
		var disallowedLabels []string
		diags = policyConfig.DisallowedRunnerLabels.ElementsAs(ctx, &disallowedLabels, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Convert to map[string]struct{} as expected by API
		disallowedMap := make(map[string]struct{})
		for _, label := range disallowedLabels {
			disallowedMap[label] = struct{}{}
		}
		createRequest.PolicyConfig.DisallowedRunnerLabels = disallowedMap
	}

	// Handle allowed runner labels set (allowed runs-on mode)
	if !policyConfig.AllowedRunnerLabels.IsNull() {
		var allowedLabels []string
		diags = policyConfig.AllowedRunnerLabels.ElementsAs(ctx, &allowedLabels, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Convert to map[string]struct{} as expected by API
		allowedMap := make(map[string]struct{})
		for _, label := range allowedLabels {
			allowedMap[label] = struct{}{}
		}
		createRequest.PolicyConfig.AllowedRunnerLabels = allowedMap
	}

	// Handle allowed runner constraints map (allowed runs-on mode)
	if !policyConfig.AllowedRunnerConstraints.IsNull() {
		allowedConstraints := make(map[string][]string)
		diags = policyConfig.AllowedRunnerConstraints.ElementsAs(ctx, &allowedConstraints, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.PolicyConfig.AllowedRunnerConstraints = allowedConstraints
	}

	expandPrejobAndRequirementFields(ctx, policyConfig, &createRequest.PolicyConfig, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Handle pinned actions exemptions set
	if !policyConfig.PinnedActionsExemptions.IsNull() {
		var pinnedExemptions []string
		diags = policyConfig.PinnedActionsExemptions.ElementsAs(ctx, &pinnedExemptions, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.PolicyConfig.PinnedActionsExemptions = pinnedExemptions
	}

	// Handle exempted users list
	if !policyConfig.ExemptedUsers.IsNull() {
		var exemptedUsers []string
		diags = policyConfig.ExemptedUsers.ElementsAs(ctx, &exemptedUsers, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		createRequest.PolicyConfig.ExemptedUsers = exemptedUsers
	}

	tflog.Debug(ctx, "Creating run policy", map[string]interface{}{
		"owner": plan.Owner.ValueString(),
		"name":  plan.Name.ValueString(),
	})

	// Create the run policy
	createdPolicy, err := r.client.CreateRunPolicy(ctx, plan.Owner.ValueString(), createRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating run policy",
			"Could not create run policy, unexpected error: "+err.Error(),
		)
		return
	}

	// Update the plan with the response data
	r.updateModelFromAPI(ctx, &plan, createdPolicy, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data.
func (r *githubRunPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state githubRunPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get run policy from API
	policy, err := r.client.GetRunPolicy(ctx, state.Owner.ValueString(), state.PolicyID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading run policy",
			"Could not read run policy ID "+state.PolicyID.ValueString()+": "+err.Error(),
		)
		return
	}

	// Update the state with the response data
	r.updateModelFromAPI(ctx, &state, policy, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *githubRunPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan githubRunPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state githubRunPolicyResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract policy configuration
	var policyConfig policyConfigModel
	diags = plan.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var statePolicyConfig policyConfigModel
	diags = state.PolicyConfig.As(ctx, &statePolicyConfig, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var configEnableHardenRunnerPolicy types.Bool
	diags = req.Config.GetAttribute(ctx, path.Root("policy_config").AtName("enable_harden_runner_policy"), &configEnableHardenRunnerPolicy)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var configHardenRunnerTargetLabels types.Set
	diags = req.Config.GetAttribute(ctx, path.Root("policy_config").AtName("harden_runner_target_labels"), &configHardenRunnerTargetLabels)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var configHardenRunnerCustomActions types.Set
	diags = req.Config.GetAttribute(ctx, path.Root("policy_config").AtName("harden_runner_custom_actions"), &configHardenRunnerCustomActions)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	enableHardenRunnerPolicy := policyConfig.EnableHardenRunnerPolicy
	if configEnableHardenRunnerPolicy.IsNull() || configEnableHardenRunnerPolicy.IsUnknown() {
		enableHardenRunnerPolicy = statePolicyConfig.EnableHardenRunnerPolicy
	}

	hardenRunnerTargetLabels := policyConfig.HardenRunnerTargetLabels
	if configHardenRunnerTargetLabels.IsNull() || configHardenRunnerTargetLabels.IsUnknown() {
		hardenRunnerTargetLabels = statePolicyConfig.HardenRunnerTargetLabels
	}

	hardenRunnerCustomActions := policyConfig.HardenRunnerCustomActions
	if configHardenRunnerCustomActions.IsNull() || configHardenRunnerCustomActions.IsUnknown() {
		hardenRunnerCustomActions = statePolicyConfig.HardenRunnerCustomActions
	}

	// Convert to API request format
	updateRequest := stepsecurityapi.UpdateRunPolicyRequest{
		Name:     plan.Name.ValueString(),
		AllRepos: plan.AllRepos.ValueBool(),
		AllOrgs:  plan.AllOrgs.ValueBool(),
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                          policyConfig.Owner.ValueString(),
			Name:                           policyConfig.Name.ValueString(),
			EnableActionPolicy:             policyConfig.EnableActionPolicy.ValueBool(),
			EnableHardenRunnerPolicy:       enableHardenRunnerPolicy.ValueBool(),
			EnableRunsOnPolicy:             policyConfig.EnableRunsOnPolicy.ValueBool(),
			EnableStandardRunnerLabels:     policyConfig.EnableStandardRunnerLabels.ValueBool(),
			EnableSecretsPolicy:            policyConfig.EnableSecretsPolicy.ValueBool(),
			EnableCompromisedActionsPolicy: policyConfig.EnableCompromisedActionsPolicy.ValueBool(),
			RequirePinnedActions:           policyConfig.RequirePinnedActions.ValueBool(),
			IsDryRun:                       policyConfig.IsDryRun.ValueBool(),
			BulkSecretsOnlyMode:            policyConfig.BulkSecretsOnlyMode.ValueBool(),
			PrCommentTemplate:              policyConfig.PrCommentTemplate.ValueString(),
			RunsOnMode:                     policyConfig.RunsOnMode.ValueString(),
			RequirePolicyStore:             policyConfig.RequirePolicyStore.ValueBool(),
			BlockJobContainer:              policyConfig.BlockJobContainer.ValueBool(),
			SecretsAnalyzeDefaultBranch:    policyConfig.SecretsAnalyzeDefaultBranch.ValueBool(),
			EnforceMethod:                  policyConfig.EnforceMethod.ValueString(),
		},
	}

	// Handle repositories list
	if !plan.Repositories.IsNull() {
		var repos []string
		diags = plan.Repositories.ElementsAs(ctx, &repos, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateRequest.Repositories = repos
	}
	updateRequest.RepoPropertyFilters = expandRepoPropertyFilters(ctx, plan.RepoPropertyFilters, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Handle allowed actions map
	if !policyConfig.AllowedActions.IsNull() {
		var allowedActions map[string]string
		diags = policyConfig.AllowedActions.ElementsAs(ctx, &allowedActions, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateRequest.PolicyConfig.AllowedActions = allowedActions
	}

	if !hardenRunnerTargetLabels.IsNull() {
		var hardenRunnerTargetLabelValues []string
		diags = hardenRunnerTargetLabels.ElementsAs(ctx, &hardenRunnerTargetLabelValues, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateRequest.PolicyConfig.HardenRunnerTargetLabels = hardenRunnerTargetLabelValues
	}

	// The PUT replaces the whole policy, so an omitted attribute must still send the
	// current value. UseStateForUnknown puts the prior state value in the plan for that.
	if !policyConfig.HardenRunnerExcludedLabels.IsNull() && !policyConfig.HardenRunnerExcludedLabels.IsUnknown() {
		var hardenRunnerExcludedLabelValues []string
		diags = policyConfig.HardenRunnerExcludedLabels.ElementsAs(ctx, &hardenRunnerExcludedLabelValues, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateRequest.PolicyConfig.HardenRunnerExcludedLabels = hardenRunnerExcludedLabelValues
	}

	if !hardenRunnerCustomActions.IsNull() {
		var hardenRunnerCustomActionValues []string
		diags = hardenRunnerCustomActions.ElementsAs(ctx, &hardenRunnerCustomActionValues, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateRequest.PolicyConfig.HardenRunnerCustomActions = hardenRunnerCustomActionValues
	}

	// Handle disallowed runner labels set
	if !policyConfig.DisallowedRunnerLabels.IsNull() {
		var disallowedLabels []string
		diags = policyConfig.DisallowedRunnerLabels.ElementsAs(ctx, &disallowedLabels, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Convert to map[string]struct{} as expected by API
		disallowedMap := make(map[string]struct{})
		for _, label := range disallowedLabels {
			disallowedMap[label] = struct{}{}
		}
		updateRequest.PolicyConfig.DisallowedRunnerLabels = disallowedMap
	}

	// Handle allowed runner labels set (allowed runs-on mode)
	if !policyConfig.AllowedRunnerLabels.IsNull() {
		var allowedLabels []string
		diags = policyConfig.AllowedRunnerLabels.ElementsAs(ctx, &allowedLabels, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Convert to map[string]struct{} as expected by API
		allowedMap := make(map[string]struct{})
		for _, label := range allowedLabels {
			allowedMap[label] = struct{}{}
		}
		updateRequest.PolicyConfig.AllowedRunnerLabels = allowedMap
	}

	// Handle allowed runner constraints map (allowed runs-on mode)
	if !policyConfig.AllowedRunnerConstraints.IsNull() {
		allowedConstraints := make(map[string][]string)
		diags = policyConfig.AllowedRunnerConstraints.ElementsAs(ctx, &allowedConstraints, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateRequest.PolicyConfig.AllowedRunnerConstraints = allowedConstraints
	}

	expandPrejobAndRequirementFields(ctx, policyConfig, &updateRequest.PolicyConfig, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Handle pinned actions exemptions set
	if !policyConfig.PinnedActionsExemptions.IsNull() {
		var pinnedExemptions []string
		diags = policyConfig.PinnedActionsExemptions.ElementsAs(ctx, &pinnedExemptions, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateRequest.PolicyConfig.PinnedActionsExemptions = pinnedExemptions
	}

	// Handle exempted users list
	if !policyConfig.ExemptedUsers.IsNull() {
		var exemptedUsers []string
		diags = policyConfig.ExemptedUsers.ElementsAs(ctx, &exemptedUsers, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		updateRequest.PolicyConfig.ExemptedUsers = exemptedUsers
	}

	// Update the run policy
	updatedPolicy, err := r.client.UpdateRunPolicy(ctx, plan.Owner.ValueString(), plan.PolicyID.ValueString(), updateRequest)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating run policy",
			"Could not update run policy, unexpected error: "+err.Error(),
		)
		return
	}

	// Update the plan with the response data
	r.updateModelFromAPI(ctx, &plan, updatedPolicy, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *githubRunPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state githubRunPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete the run policy
	err := r.client.DeleteRunPolicy(ctx, state.Owner.ValueString(), state.PolicyID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting run policy",
			"Could not delete run policy, unexpected error: "+err.Error(),
		)
		return
	}
}

// ImportState imports the resource state.
func (r *githubRunPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should be the owner name
	id := req.ID

	// Split the ID into owner and policy name
	splitted := strings.Split(id, "/")
	if len(splitted) != 2 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			fmt.Sprintf("Expected owner/policy_name, got: %s", id),
		)
		return
	}

	// Set the owner/policy name in the state
	owner := splitted[0]
	policyID := splitted[1]
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("owner"), owner)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("policy_id"), policyID)...)

	// Now call Read to populate the rest of the state
	readReq := resource.ReadRequest{
		State: resp.State,
	}
	readResp := &resource.ReadResponse{
		State: resp.State,
	}

	r.Read(ctx, readReq, readResp)

	// Copy any diagnostics and updated state from Read
	resp.Diagnostics.Append(readResp.Diagnostics...)
	resp.State = readResp.State
}

// updateModelFromAPI updates the Terraform model with data from the API response.
func (r *githubRunPolicyResource) updateModelFromAPI(ctx context.Context, model *githubRunPolicyResourceModel, policy *stepsecurityapi.RunPolicy, diags *diag.Diagnostics) {
	var existingPolicyConfig policyConfigModel
	hasExistingPolicyConfig := !model.PolicyConfig.IsNull() && !model.PolicyConfig.IsUnknown()
	if hasExistingPolicyConfig {
		existingDiags := model.PolicyConfig.As(ctx, &existingPolicyConfig, basetypes.ObjectAsOptions{})
		diags.Append(existingDiags...)
		if diags.HasError() {
			return
		}
	}

	preservePreviousEmptySet := func(previous types.Set) (attr.Value, bool) {
		if previous.IsNull() || previous.IsUnknown() {
			return nil, false
		}

		var values []string
		setDiags := previous.ElementsAs(ctx, &values, false)
		diags.Append(setDiags...)
		if diags.HasError() {
			return nil, false
		}

		if len(values) != 0 {
			return nil, false
		}

		emptySet, emptySetDiags := types.SetValue(types.StringType, []attr.Value{})
		diags.Append(emptySetDiags...)
		if diags.HasError() {
			return nil, false
		}

		return emptySet, true
	}

	// when applied across org..preserve owner set in state/plan
	if !strings.Contains(policy.Owner, "#[all]") {
		model.Owner = types.StringValue(policy.Owner)
	}
	model.Name = types.StringValue(policy.Name)
	model.PolicyID = types.StringValue(policy.PolicyID)
	model.AllRepos = types.BoolValue(policy.AllRepos)
	model.AllOrgs = types.BoolValue(policy.AllOrgs)
	model.CreatedBy = types.StringValue(policy.CreatedBy)
	model.CreatedAt = types.StringValue(policy.CreatedAt.Format(time.RFC3339))
	model.LastUpdatedBy = types.StringValue(policy.LastUpdatedBy)
	model.LastUpdatedAt = types.StringValue(policy.LastUpdatedAt.Format(time.RFC3339))

	// Handle repositories list
	if policy.Repositories != nil {
		repoList := make([]attr.Value, len(policy.Repositories))
		for i, repo := range policy.Repositories {
			repoList[i] = types.StringValue(repo)
		}
		listValue, listDiags := types.ListValue(types.StringType, repoList)
		diags.Append(listDiags...)
		model.Repositories = listValue
	} else {
		model.Repositories = types.ListNull(types.StringType)
	}
	model.RepoPropertyFilters = flattenRepoPropertyFilters(policy.RepoPropertyFilters, diags)

	// Handle policy configuration
	policyConfigAttrs := map[string]attr.Value{
		"owner":                             types.StringValue(policy.PolicyConfig.Owner),
		"name":                              types.StringValue(policy.PolicyConfig.Name),
		"enable_action_policy":              types.BoolValue(policy.PolicyConfig.EnableActionPolicy),
		"enable_harden_runner_policy":       types.BoolValue(policy.PolicyConfig.EnableHardenRunnerPolicy),
		"enable_runs_on_policy":             types.BoolValue(policy.PolicyConfig.EnableRunsOnPolicy),
		"enable_standard_runner_labels":     types.BoolValue(policy.PolicyConfig.EnableStandardRunnerLabels),
		"enable_secrets_policy":             types.BoolValue(policy.PolicyConfig.EnableSecretsPolicy),
		"enable_compromised_actions_policy": types.BoolValue(policy.PolicyConfig.EnableCompromisedActionsPolicy),
		"require_pinned_actions":            types.BoolValue(policy.PolicyConfig.RequirePinnedActions),
		"is_dry_run":                        types.BoolValue(policy.PolicyConfig.IsDryRun),
		"bulk_secrets_only_mode":            types.BoolValue(policy.PolicyConfig.BulkSecretsOnlyMode),
		"pr_comment_template":               types.StringValue(policy.PolicyConfig.PrCommentTemplate),
		"runs_on_mode":                      types.StringValue(policy.PolicyConfig.RunsOnMode),
		"require_policy_store":              types.BoolValue(policy.PolicyConfig.RequirePolicyStore),
		"block_job_container":               types.BoolValue(policy.PolicyConfig.BlockJobContainer),
		"secrets_analyze_default_branch":    types.BoolValue(policy.PolicyConfig.SecretsAnalyzeDefaultBranch),
		"enforce_method":                    types.StringValue(policy.PolicyConfig.EnforceMethod),
	}

	// Handle allowed actions map
	if policy.PolicyConfig.AllowedActions != nil {
		allowedActionsMap := make(map[string]attr.Value)
		for action, permission := range policy.PolicyConfig.AllowedActions {
			allowedActionsMap[action] = types.StringValue(permission)
		}
		mapValue, mapDiags := types.MapValue(types.StringType, allowedActionsMap)
		diags.Append(mapDiags...)
		policyConfigAttrs["allowed_actions"] = mapValue
	} else {
		policyConfigAttrs["allowed_actions"] = types.MapNull(types.StringType)
	}

	if len(policy.PolicyConfig.HardenRunnerTargetLabels) > 0 {
		hardenRunnerTargetLabelsList := make([]attr.Value, len(policy.PolicyConfig.HardenRunnerTargetLabels))
		for i, label := range policy.PolicyConfig.HardenRunnerTargetLabels {
			hardenRunnerTargetLabelsList[i] = types.StringValue(label)
		}
		setValue, setDiags := types.SetValue(types.StringType, hardenRunnerTargetLabelsList)
		diags.Append(setDiags...)
		policyConfigAttrs["harden_runner_target_labels"] = setValue
	} else if hasExistingPolicyConfig {
		if preservedValue, ok := preservePreviousEmptySet(existingPolicyConfig.HardenRunnerTargetLabels); ok {
			policyConfigAttrs["harden_runner_target_labels"] = preservedValue
		} else {
			policyConfigAttrs["harden_runner_target_labels"] = types.SetNull(types.StringType)
		}
	} else {
		policyConfigAttrs["harden_runner_target_labels"] = types.SetNull(types.StringType)
	}

	if len(policy.PolicyConfig.HardenRunnerExcludedLabels) > 0 {
		hardenRunnerExcludedLabelsList := make([]attr.Value, len(policy.PolicyConfig.HardenRunnerExcludedLabels))
		for i, label := range policy.PolicyConfig.HardenRunnerExcludedLabels {
			hardenRunnerExcludedLabelsList[i] = types.StringValue(label)
		}
		setValue, setDiags := types.SetValue(types.StringType, hardenRunnerExcludedLabelsList)
		diags.Append(setDiags...)
		policyConfigAttrs["harden_runner_excluded_labels"] = setValue
	} else if preservedValue, ok := preservePreviousEmptySet(existingPolicyConfig.HardenRunnerExcludedLabels); hasExistingPolicyConfig && ok {
		policyConfigAttrs["harden_runner_excluded_labels"] = preservedValue
	} else {
		policyConfigAttrs["harden_runner_excluded_labels"] = types.SetNull(types.StringType)
	}

	if len(policy.PolicyConfig.HardenRunnerCustomActions) > 0 {
		hardenRunnerCustomActionsList := make([]attr.Value, len(policy.PolicyConfig.HardenRunnerCustomActions))
		for i, action := range policy.PolicyConfig.HardenRunnerCustomActions {
			hardenRunnerCustomActionsList[i] = types.StringValue(action)
		}
		setValue, setDiags := types.SetValue(types.StringType, hardenRunnerCustomActionsList)
		diags.Append(setDiags...)
		policyConfigAttrs["harden_runner_custom_actions"] = setValue
	} else if hasExistingPolicyConfig {
		if preservedValue, ok := preservePreviousEmptySet(existingPolicyConfig.HardenRunnerCustomActions); ok {
			policyConfigAttrs["harden_runner_custom_actions"] = preservedValue
		} else {
			policyConfigAttrs["harden_runner_custom_actions"] = types.SetNull(types.StringType)
		}
	} else {
		policyConfigAttrs["harden_runner_custom_actions"] = types.SetNull(types.StringType)
	}

	// Handle disallowed runner labels set
	if policy.PolicyConfig.DisallowedRunnerLabels != nil {
		disallowedLabelsList := make([]attr.Value, 0, len(policy.PolicyConfig.DisallowedRunnerLabels))
		for label := range policy.PolicyConfig.DisallowedRunnerLabels {
			disallowedLabelsList = append(disallowedLabelsList, types.StringValue(label))
		}
		setValue, setDiags := types.SetValue(types.StringType, disallowedLabelsList)
		diags.Append(setDiags...)
		policyConfigAttrs["disallowed_runner_labels"] = setValue
	} else {
		policyConfigAttrs["disallowed_runner_labels"] = types.SetNull(types.StringType)
	}

	// Handle allowed runner labels set (allowed runs-on mode)
	if policy.PolicyConfig.AllowedRunnerLabels != nil {
		allowedLabelsList := make([]attr.Value, 0, len(policy.PolicyConfig.AllowedRunnerLabels))
		for label := range policy.PolicyConfig.AllowedRunnerLabels {
			allowedLabelsList = append(allowedLabelsList, types.StringValue(label))
		}
		setValue, setDiags := types.SetValue(types.StringType, allowedLabelsList)
		diags.Append(setDiags...)
		policyConfigAttrs["allowed_runner_labels"] = setValue
	} else {
		policyConfigAttrs["allowed_runner_labels"] = types.SetNull(types.StringType)
	}

	// Handle allowed runner constraints map (allowed runs-on mode). Values are
	// modeled as a set per key so the server-side sort/dedup does not surface as
	// plan drift.
	if policy.PolicyConfig.AllowedRunnerConstraints != nil {
		constraintsMap := make(map[string]attr.Value, len(policy.PolicyConfig.AllowedRunnerConstraints))
		for key, values := range policy.PolicyConfig.AllowedRunnerConstraints {
			valueList := make([]attr.Value, len(values))
			for i, v := range values {
				valueList[i] = types.StringValue(v)
			}
			setValue, setDiags := types.SetValue(types.StringType, valueList)
			diags.Append(setDiags...)
			constraintsMap[key] = setValue
		}
		mapValue, mapDiags := types.MapValue(types.SetType{ElemType: types.StringType}, constraintsMap)
		diags.Append(mapDiags...)
		policyConfigAttrs["allowed_runner_constraints"] = mapValue
	} else {
		policyConfigAttrs["allowed_runner_constraints"] = types.MapNull(types.SetType{ElemType: types.StringType})
	}

	// Prejob hook scoping lists and conditional label requirements. A planned
	// empty list round-trips as omitted JSON (nil), so the previous state's
	// empty-vs-null signal is preserved to avoid an inconsistent result after
	// apply, the same contract as the harden-runner label sets above.
	if len(policy.PolicyConfig.PrejobAllowedRunnerLabels) > 0 {
		policyConfigAttrs["prejob_allowed_runner_labels"] = stringSetValueOrNull(policy.PolicyConfig.PrejobAllowedRunnerLabels, diags)
	} else if preservedValue, ok := preservePreviousEmptySet(existingPolicyConfig.PrejobAllowedRunnerLabels); hasExistingPolicyConfig && ok {
		policyConfigAttrs["prejob_allowed_runner_labels"] = preservedValue
	} else {
		policyConfigAttrs["prejob_allowed_runner_labels"] = types.SetNull(types.StringType)
	}
	if len(policy.PolicyConfig.PrejobDisallowedRunnerLabels) > 0 {
		policyConfigAttrs["prejob_disallowed_runner_labels"] = stringSetValueOrNull(policy.PolicyConfig.PrejobDisallowedRunnerLabels, diags)
	} else if preservedValue, ok := preservePreviousEmptySet(existingPolicyConfig.PrejobDisallowedRunnerLabels); hasExistingPolicyConfig && ok {
		policyConfigAttrs["prejob_disallowed_runner_labels"] = preservedValue
	} else {
		policyConfigAttrs["prejob_disallowed_runner_labels"] = types.SetNull(types.StringType)
	}
	var previousRequirements []runnerLabelRequirementModel
	hasPreviousRequirements := hasExistingPolicyConfig &&
		!existingPolicyConfig.RunnerLabelRequirements.IsNull() &&
		!existingPolicyConfig.RunnerLabelRequirements.IsUnknown()
	if hasPreviousRequirements {
		reqDiags := existingPolicyConfig.RunnerLabelRequirements.ElementsAs(ctx, &previousRequirements, false)
		diags.Append(reqDiags...)
	}
	if policy.PolicyConfig.RunnerLabelRequirements != nil {
		policyConfigAttrs["runner_label_requirements"] = flattenRunnerLabelRequirements(ctx, policy.PolicyConfig.RunnerLabelRequirements, previousRequirements, diags)
	} else if hasPreviousRequirements && len(previousRequirements) == 0 {
		emptyList, emptyDiags := types.ListValue(runnerLabelRequirementObjectType, []attr.Value{})
		diags.Append(emptyDiags...)
		policyConfigAttrs["runner_label_requirements"] = emptyList
	} else {
		policyConfigAttrs["runner_label_requirements"] = types.ListNull(runnerLabelRequirementObjectType)
	}

	// Handle pinned actions exemptions set
	if policy.PolicyConfig.PinnedActionsExemptions != nil {
		pinnedExemptionsList := make([]attr.Value, len(policy.PolicyConfig.PinnedActionsExemptions))
		for i, exemption := range policy.PolicyConfig.PinnedActionsExemptions {
			pinnedExemptionsList[i] = types.StringValue(exemption)
		}
		setValue, setDiags := types.SetValue(types.StringType, pinnedExemptionsList)
		diags.Append(setDiags...)
		policyConfigAttrs["actions_to_exempt_while_pinning"] = setValue
	} else {
		policyConfigAttrs["actions_to_exempt_while_pinning"] = types.SetNull(types.StringType)
	}

	// Handle exempted users set
	if policy.PolicyConfig.ExemptedUsers != nil {
		exemptedUsersList := make([]attr.Value, len(policy.PolicyConfig.ExemptedUsers))
		for i, user := range policy.PolicyConfig.ExemptedUsers {
			exemptedUsersList[i] = types.StringValue(user)
		}
		setValue, setDiags := types.SetValue(types.StringType, exemptedUsersList)
		diags.Append(setDiags...)
		policyConfigAttrs["exempted_users"] = setValue
	} else {
		policyConfigAttrs["exempted_users"] = types.SetNull(types.StringType)
	}

	// Create the policy config object
	policyConfigAttrTypes := map[string]attr.Type{
		"owner":                             types.StringType,
		"name":                              types.StringType,
		"enable_action_policy":              types.BoolType,
		"allowed_actions":                   types.MapType{ElemType: types.StringType},
		"enable_harden_runner_policy":       types.BoolType,
		"harden_runner_target_labels":       types.SetType{ElemType: types.StringType},
		"harden_runner_excluded_labels":     types.SetType{ElemType: types.StringType},
		"harden_runner_custom_actions":      types.SetType{ElemType: types.StringType},
		"enable_runs_on_policy":             types.BoolType,
		"enable_standard_runner_labels":     types.BoolType,
		"disallowed_runner_labels":          types.SetType{ElemType: types.StringType},
		"enable_secrets_policy":             types.BoolType,
		"enable_compromised_actions_policy": types.BoolType,
		"require_pinned_actions":            types.BoolType,
		"actions_to_exempt_while_pinning":   types.SetType{ElemType: types.StringType},
		"is_dry_run":                        types.BoolType,
		"bulk_secrets_only_mode":            types.BoolType,
		"pr_comment_template":               types.StringType,
		"exempted_users":                    types.SetType{ElemType: types.StringType},
		"runs_on_mode":                      types.StringType,
		"allowed_runner_labels":             types.SetType{ElemType: types.StringType},
		"allowed_runner_constraints":        types.MapType{ElemType: types.SetType{ElemType: types.StringType}},
		"require_policy_store":              types.BoolType,
		"block_job_container":               types.BoolType,
		"secrets_analyze_default_branch":    types.BoolType,
		"enforce_method":                    types.StringType,
		"prejob_allowed_runner_labels":      types.SetType{ElemType: types.StringType},
		"prejob_disallowed_runner_labels":   types.SetType{ElemType: types.StringType},
		"runner_label_requirements":         types.ListType{ElemType: runnerLabelRequirementObjectType},
	}

	policyConfigObj, objDiags := types.ObjectValue(policyConfigAttrTypes, policyConfigAttrs)
	diags.Append(objDiags...)
	model.PolicyConfig = policyConfigObj
}

// Server-side limits for custom_property_rule (agent-api
// validateAndNormalizeRunPolicyScope); checking them here fails at plan time
// instead of as a 400 on apply.
const (
	maxRepoPropertyFilters      = 10
	maxRepoPropertyFilterValues = 50
	maxRepoPropertyTokenLength  = 75
)

// repoPropertyFilterObjectType is the element type of custom_property_rule.
var repoPropertyFilterObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"property": types.StringType,
	"values":   types.SetType{ElemType: types.StringType},
	"combine":  types.StringType,
}}

// repoPropertyFilterModel mirrors one custom_property_rule element.
type repoPropertyFilterModel struct {
	Property types.String `tfsdk:"property"`
	Values   types.Set    `tfsdk:"values"`
	Combine  types.String `tfsdk:"combine"`
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
			"combines with the row above through `combine` (`and` or `or`), and `and` binds before `or`. Property names " +
			"ignore case; values match exactly. Cannot be combined with `all_repos`, `repositories` or `all_orgs`. When a run's " +
			"repository properties cannot be resolved, the policy is not applied to that run.",
		Validators: []validator.List{
			listvalidator.SizeBetween(1, maxRepoPropertyFilters),
		},
		NestedObject: schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"property": schema.StringAttribute{
					Required:            true,
					MarkdownDescription: "The custom property name (case-insensitive).",
					Validators:          token,
				},
				"values": schema.SetAttribute{
					ElementType:         types.StringType,
					Required:            true,
					MarkdownDescription: "Values to match exactly (case-sensitive). A repository matches the row when it has any of them.",
					Validators: []validator.Set{
						setvalidator.SizeBetween(1, maxRepoPropertyFilterValues),
						setvalidator.ValueStringsAre(token...),
					},
				},
				"combine": schema.StringAttribute{
					Optional:            true,
					Computed:            true,
					MarkdownDescription: "How this row combines with the row above: `and` (default) or `or`. Omit on the first row.",
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
	attrPath := path.Root("custom_property_rule")
	if cfg.AllRepos.ValueBool() || cfg.AllOrgs.ValueBool() ||
		(!cfg.Repositories.IsNull() && !cfg.Repositories.IsUnknown() && len(cfg.Repositories.Elements()) > 0) {
		diags.AddAttributeError(attrPath, "Conflicting repository scope",
			"custom_property_rule cannot be combined with all_repos, repositories or all_orgs.")
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
		if i == 0 && !row.Combine.IsNull() && !row.Combine.IsUnknown() {
			diags.AddAttributeError(attrPath.AtListIndex(0).AtName("combine"), "Invalid combine on the first row",
				"combine says how a row combines with the row above, so it must be omitted on the first row.")
		}
		if row.Property.IsNull() || row.Property.IsUnknown() {
			continue
		}
		key := strings.ToLower(row.Property.ValueString())
		if seen[key] {
			diags.AddAttributeError(attrPath.AtListIndex(i).AtName("name"), "Duplicate property",
				fmt.Sprintf("property %q appears in more than one row; property names are case-insensitive.", row.Property.ValueString()))
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
			Name:   row.Property.ValueString(),
			Values: values,
			Join:   row.Combine.ValueString(),
		})
	}
	return out
}

// flattenRepoPropertyFilters converts the stored rule to state. The backend
// clears combine on the first row, which lands as null to match the config.
func flattenRepoPropertyFilters(filters []stepsecurityapi.RepoPropertyFilter, diags *diag.Diagnostics) types.List {
	if len(filters) == 0 {
		return types.ListNull(repoPropertyFilterObjectType)
	}
	rows := make([]attr.Value, 0, len(filters))
	for i, f := range filters {
		combine := types.StringNull()
		if i > 0 {
			combine = types.StringValue(f.Join)
		}
		row, d := types.ObjectValue(repoPropertyFilterObjectType.AttrTypes, map[string]attr.Value{
			"property": types.StringValue(f.Name),
			"values":   stringSetValueOrNull(f.Values, diags),
			"combine":  combine,
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

// ModifyPlan resolves an omitted combine to what the API stores: null on the
// first row and "and" on later rows. combine is Optional+Computed, so without
// this a removed combine keeps its prior value and the plan shows no change.
func (r *githubRunPolicyResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	attrPath := path.Root("custom_property_rule")
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
		if j, ok := cfgRow.Attributes()["combine"]; !ok || !j.IsNull() {
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
		if attrs["combine"].Equal(want) {
			continue
		}
		attrs["combine"] = want
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
