package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ datasource.DataSource              = &githubRunPoliciesDataSource{}
	_ datasource.DataSourceWithConfigure = &githubRunPoliciesDataSource{}
)

// NewGithubRunPoliciesDataSource is a helper function to simplify the provider implementation.
func NewGithubRunPoliciesDataSource() datasource.DataSource {
	return &githubRunPoliciesDataSource{}
}

// githubRunPoliciesDataSource is the data source implementation.
type githubRunPoliciesDataSource struct {
	client stepsecurityapi.Client
}

// githubRunPoliciesDataSourceModel maps the data source schema data.
type githubRunPoliciesDataSourceModel struct {
	Owner       types.String `tfsdk:"owner"`
	RunPolicies types.List   `tfsdk:"run_policies"`
}

// Metadata returns the data source type name.
func (d *githubRunPoliciesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_github_run_policies"
}

// Schema defines the schema for the data source.
func (d *githubRunPoliciesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Retrieves GitHub Actions run policies from StepSecurity.",
		Attributes: map[string]schema.Attribute{
			"owner": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The GitHub organization or user to retrieve policies for.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"run_policies": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "List of run policies for the specified owner.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"owner": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The owner of the policy.",
						},
						"customer": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The customer associated with the policy.",
						},
						"policy_id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The unique identifier for this policy.",
						},
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The name of the run policy.",
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
						"all_repos": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Whether this policy applies to all repositories in the organization.",
						},
						"all_orgs": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Whether this policy applies to all organizations.",
						},
						"repositories": schema.ListAttribute{
							ElementType:         types.StringType,
							Computed:            true,
							MarkdownDescription: "List of specific repositories this policy applies to.",
						},
						"repo_property_filters": schema.ListNestedAttribute{
							Computed:            true,
							MarkdownDescription: "Custom property rule this policy applies to, if any. Rows after the first join the previous row with `and` or `or`; `and` binds first.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name":   schema.StringAttribute{Computed: true, MarkdownDescription: "The custom property name."},
									"values": schema.SetAttribute{ElementType: types.StringType, Computed: true, MarkdownDescription: "Values matched exactly."},
									"match":  schema.StringAttribute{Computed: true, MarkdownDescription: "`any` or `all` of `values`."},
									"join":   schema.StringAttribute{Computed: true, MarkdownDescription: "`and` or `or` with the previous row; null on the first row."},
								},
							},
						},
						"policy_config": schema.SingleNestedAttribute{
							Computed:            true,
							MarkdownDescription: "The configuration for this run policy.",
							Attributes: map[string]schema.Attribute{
								"owner": schema.StringAttribute{
									Computed:            true,
									MarkdownDescription: "The owner of the policy configuration.",
								},
								"name": schema.StringAttribute{
									Computed:            true,
									MarkdownDescription: "The name of the policy configuration.",
								},
								"enable_action_policy": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether the action policy is enabled.",
								},
								"allowed_actions": schema.MapAttribute{
									ElementType:         types.StringType,
									Computed:            true,
									MarkdownDescription: "Map of allowed actions and their permissions. Keys may be an exact ref (`actions/checkout@v4`), a name-only match (`actions/checkout`), an owner wildcard (`my-org/*`), or the global wildcard (`*/*`).",
								},
								"enable_harden_runner_policy": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether the Harden Runner policy is enabled.",
								},
								"harden_runner_target_labels": schema.SetAttribute{
									ElementType:         types.StringType,
									Computed:            true,
									MarkdownDescription: "Set of runner labels that target Harden Runner enforcement. When `enable_harden_runner_policy` is true, an empty set means the policy applies to every job; a non-empty set filters to jobs whose `runs-on` matches at least one label. When the policy is disabled, this attribute is null.",
								},
								"harden_runner_excluded_labels": schema.SetAttribute{
									ElementType:         types.StringType,
									Computed:            true,
									MarkdownDescription: "Set of runner labels excluded from Harden Runner enforcement, regardless of `harden_runner_target_labels`. Entries support a `*` wildcard and match case-insensitively. Null when no labels are excluded.",
								},
								"harden_runner_custom_actions": schema.SetAttribute{
									ElementType:         types.StringType,
									Computed:            true,
									MarkdownDescription: "Set of custom actions accepted as Harden Runner equivalents (in addition to `step-security/harden-runner`).",
								},
								"enable_runs_on_policy": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether the runs-on policy is enabled.",
								},
								"disallowed_runner_labels": schema.SetAttribute{
									ElementType:         types.StringType,
									Computed:            true,
									MarkdownDescription: "Set of disallowed runner labels.",
								},
								"enable_standard_runner_labels": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether the GitHub-hosted standard runner label set is added to the policy labels at evaluation time.",
								},
								"enable_secrets_policy": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether the secrets policy is enabled.",
								},
								"enable_compromised_actions_policy": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether the compromised actions policy is enabled.",
								},
								"require_pinned_actions": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether all actions are required to be pinned to full-length commit SHAs.",
								},
								"actions_to_exempt_while_pinning": schema.SetAttribute{
									ElementType:         types.StringType,
									Computed:            true,
									MarkdownDescription: "Set of actions exempt from pinning requirements.",
								},
								"is_dry_run": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "Whether this policy is in dry-run mode.",
								},
								"pr_comment_template": schema.StringAttribute{
									Computed:            true,
									MarkdownDescription: "Optional custom template for the pull request comment posted when this policy blocks a run. Supports placeholder substitution; leave empty to use the default StepSecurity comment.",
								},
								"bulk_secrets_only_mode": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "When enabled, the secret exfiltration policy restricts enforcement to high-risk bulk secret-exposure attempts rather than all secret references. See the StepSecurity run-policies documentation for details.",
								},
								"runs_on_mode": schema.StringAttribute{
									Computed:            true,
									MarkdownDescription: "How the runs-on policy evaluates runner labels: `disallowed` (default; empty string treated the same) blocks `disallowed_runner_labels`, `allowed` only permits `allowed_runner_labels` / `allowed_runner_constraints`.",
								},
								"allowed_runner_labels": schema.SetAttribute{
									ElementType:         types.StringType,
									Computed:            true,
									MarkdownDescription: "Set of plain runner labels permitted when `runs_on_mode` is `allowed`.",
								},
								"allowed_runner_constraints": schema.MapAttribute{
									ElementType:         types.SetType{ElemType: types.StringType},
									Computed:            true,
									MarkdownDescription: "Structured runs-on.com constraints permitted when `runs_on_mode` is `allowed`, keyed by dimension (e.g. `family`, `cpu`, `image`); each key maps to the set of allowed values. Expression values match by exact text, which also lets the `runs-on` routing key be pinned.",
								},
								"require_policy_store": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "When true, every job targeted by the Harden Runner policy must set `use-policy-store: true` on its Harden Runner step.",
								},
								"block_job_container": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "When true, targeted jobs that run entirely inside a job-level `container:` are blocked (Harden Runner cannot monitor a fully containerized job on GitHub-hosted standard runners).",
								},
								"secrets_analyze_default_branch": schema.BoolAttribute{
									Computed:            true,
									MarkdownDescription: "When true, the secrets policy also evaluates runs on the repository default branch.",
								},
								"enforce_method": schema.StringAttribute{
									Computed:            true,
									MarkdownDescription: "How a blocked run is stopped: `api` (default; empty string treated the same) cancels via the GitHub API, `prejob` defers cancellation to the StepSecurity prejob hook for eligible runs.",
								},
								"prejob_allowed_runner_labels": schema.SetAttribute{
									ElementType:         types.StringType,
									Computed:            true,
									MarkdownDescription: "With prejob enforcement: only runs whose jobs all use these resolved runner labels defer cancellation to the prejob hook.",
								},
								"prejob_disallowed_runner_labels": schema.SetAttribute{
									ElementType:         types.StringType,
									Computed:            true,
									MarkdownDescription: "With prejob enforcement: runs with any job on these resolved runner labels are cancelled via the API instead of deferring to the prejob hook.",
								},
								"runner_label_requirements": schema.ListNestedAttribute{
									Computed:            true,
									MarkdownDescription: "Conditional label rules evaluated per job: when a job label matches the pattern, the rule's required labels must be present on that job (or its forbidden labels absent) or the run is blocked.",
									NestedObject: schema.NestedAttributeObject{
										Attributes: map[string]schema.Attribute{
											"if_label_matches": schema.StringAttribute{
												Computed:            true,
												MarkdownDescription: "Anchored glob tested against each of the job's runner labels; `*` matches any text.",
											},
											"require_labels": schema.SetAttribute{
												ElementType:         types.StringType,
												Computed:            true,
												MarkdownDescription: "Labels that must all be present on a matching job.",
											},
											"forbid_labels": schema.SetAttribute{
												ElementType:         types.StringType,
												Computed:            true,
												MarkdownDescription: "Labels that must not be present on a matching job.",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// Configure adds the provider configured client to the data source.
func (d *githubRunPoliciesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(stepsecurityapi.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected stepsecurityapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

// Read refreshes the Terraform state with the latest data.
func (d *githubRunPoliciesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state githubRunPoliciesDataSourceModel
	diags := req.Config.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get run policies from API
	policies, err := d.client.ListRunPolicies(ctx, state.Owner.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading run policies",
			"Could not read run policies for owner "+state.Owner.ValueString()+": "+err.Error(),
		)
		return
	}

	// Convert API response to Terraform state
	runPoliciesList := make([]attr.Value, 0, len(policies))

	for _, policy := range policies {
		// Handle repositories list
		var reposList types.List
		if policy.Repositories != nil {
			repoValues := make([]attr.Value, len(policy.Repositories))
			for i, repo := range policy.Repositories {
				repoValues[i] = types.StringValue(repo)
			}
			reposList, _ = types.ListValue(types.StringType, repoValues)
		} else {
			reposList = types.ListNull(types.StringType)
		}

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

		// Prejob hook scoping lists and conditional label requirements.
		var labelDiags diag.Diagnostics
		policyConfigAttrs["prejob_allowed_runner_labels"] = stringSetValueOrNull(policy.PolicyConfig.PrejobAllowedRunnerLabels, &labelDiags)
		policyConfigAttrs["prejob_disallowed_runner_labels"] = stringSetValueOrNull(policy.PolicyConfig.PrejobDisallowedRunnerLabels, &labelDiags)
		policyConfigAttrs["runner_label_requirements"] = flattenRunnerLabelRequirements(ctx, policy.PolicyConfig.RunnerLabelRequirements, nil, &labelDiags)
		resp.Diagnostics.Append(labelDiags...)

		// Handle allowed actions map
		if policy.PolicyConfig.AllowedActions != nil {
			allowedActionsMap := make(map[string]attr.Value)
			for action, permission := range policy.PolicyConfig.AllowedActions {
				allowedActionsMap[action] = types.StringValue(permission)
			}
			mapValue, _ := types.MapValue(types.StringType, allowedActionsMap)
			policyConfigAttrs["allowed_actions"] = mapValue
		} else {
			policyConfigAttrs["allowed_actions"] = types.MapNull(types.StringType)
		}

		// When the Harden Runner policy is enabled, surface an empty set (not
		// null) for empty labels so consumers can see the documented
		// "empty = all jobs" contract even though the backend response omits
		// the field for empty values (JSON omitempty).
		if len(policy.PolicyConfig.HardenRunnerTargetLabels) > 0 {
			hardenRunnerTargetLabelsList := make([]attr.Value, len(policy.PolicyConfig.HardenRunnerTargetLabels))
			for i, label := range policy.PolicyConfig.HardenRunnerTargetLabels {
				hardenRunnerTargetLabelsList[i] = types.StringValue(label)
			}
			setValue, _ := types.SetValue(types.StringType, hardenRunnerTargetLabelsList)
			policyConfigAttrs["harden_runner_target_labels"] = setValue
		} else if policy.PolicyConfig.EnableHardenRunnerPolicy {
			setValue, _ := types.SetValue(types.StringType, []attr.Value{})
			policyConfigAttrs["harden_runner_target_labels"] = setValue
		} else {
			policyConfigAttrs["harden_runner_target_labels"] = types.SetNull(types.StringType)
		}

		if len(policy.PolicyConfig.HardenRunnerExcludedLabels) > 0 {
			hardenRunnerExcludedLabelsList := make([]attr.Value, len(policy.PolicyConfig.HardenRunnerExcludedLabels))
			for i, label := range policy.PolicyConfig.HardenRunnerExcludedLabels {
				hardenRunnerExcludedLabelsList[i] = types.StringValue(label)
			}
			setValue, _ := types.SetValue(types.StringType, hardenRunnerExcludedLabelsList)
			policyConfigAttrs["harden_runner_excluded_labels"] = setValue
		} else {
			policyConfigAttrs["harden_runner_excluded_labels"] = types.SetNull(types.StringType)
		}

		if len(policy.PolicyConfig.HardenRunnerCustomActions) > 0 {
			hardenRunnerCustomActionsList := make([]attr.Value, len(policy.PolicyConfig.HardenRunnerCustomActions))
			for i, action := range policy.PolicyConfig.HardenRunnerCustomActions {
				hardenRunnerCustomActionsList[i] = types.StringValue(action)
			}
			setValue, _ := types.SetValue(types.StringType, hardenRunnerCustomActionsList)
			policyConfigAttrs["harden_runner_custom_actions"] = setValue
		} else if policy.PolicyConfig.EnableHardenRunnerPolicy {
			setValue, _ := types.SetValue(types.StringType, []attr.Value{})
			policyConfigAttrs["harden_runner_custom_actions"] = setValue
		} else {
			policyConfigAttrs["harden_runner_custom_actions"] = types.SetNull(types.StringType)
		}

		// Handle disallowed runner labels set
		if policy.PolicyConfig.DisallowedRunnerLabels != nil {
			disallowedLabelsList := make([]attr.Value, 0, len(policy.PolicyConfig.DisallowedRunnerLabels))
			for label := range policy.PolicyConfig.DisallowedRunnerLabels {
				disallowedLabelsList = append(disallowedLabelsList, types.StringValue(label))
			}
			setValue, _ := types.SetValue(types.StringType, disallowedLabelsList)
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
			setValue, _ := types.SetValue(types.StringType, allowedLabelsList)
			policyConfigAttrs["allowed_runner_labels"] = setValue
		} else {
			policyConfigAttrs["allowed_runner_labels"] = types.SetNull(types.StringType)
		}

		// Handle allowed runner constraints map (allowed runs-on mode)
		if policy.PolicyConfig.AllowedRunnerConstraints != nil {
			constraintsMap := make(map[string]attr.Value, len(policy.PolicyConfig.AllowedRunnerConstraints))
			for key, values := range policy.PolicyConfig.AllowedRunnerConstraints {
				valueList := make([]attr.Value, len(values))
				for i, v := range values {
					valueList[i] = types.StringValue(v)
				}
				setValue, _ := types.SetValue(types.StringType, valueList)
				constraintsMap[key] = setValue
			}
			mapValue, _ := types.MapValue(types.SetType{ElemType: types.StringType}, constraintsMap)
			policyConfigAttrs["allowed_runner_constraints"] = mapValue
		} else {
			policyConfigAttrs["allowed_runner_constraints"] = types.MapNull(types.SetType{ElemType: types.StringType})
		}

		// Handle pinned actions exemptions set
		if policy.PolicyConfig.PinnedActionsExemptions != nil {
			pinnedExemptionsList := make([]attr.Value, len(policy.PolicyConfig.PinnedActionsExemptions))
			for i, exemption := range policy.PolicyConfig.PinnedActionsExemptions {
				pinnedExemptionsList[i] = types.StringValue(exemption)
			}
			setValue, _ := types.SetValue(types.StringType, pinnedExemptionsList)
			policyConfigAttrs["actions_to_exempt_while_pinning"] = setValue
		} else {
			policyConfigAttrs["actions_to_exempt_while_pinning"] = types.SetNull(types.StringType)
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

		policyConfigObj, _ := types.ObjectValue(policyConfigAttrTypes, policyConfigAttrs)

		// Create run policy object
		runPolicyAttrs := map[string]attr.Value{
			"owner":                 types.StringValue(policy.Owner),
			"customer":              types.StringValue(policy.Customer),
			"policy_id":             types.StringValue(policy.PolicyID),
			"name":                  types.StringValue(policy.Name),
			"created_by":            types.StringValue(policy.CreatedBy),
			"created_at":            types.StringValue(policy.CreatedAt.Format(time.RFC3339)),
			"last_updated_by":       types.StringValue(policy.LastUpdatedBy),
			"last_updated_at":       types.StringValue(policy.LastUpdatedAt.Format(time.RFC3339)),
			"all_repos":             types.BoolValue(policy.AllRepos),
			"all_orgs":              types.BoolValue(policy.AllOrgs),
			"repositories":          reposList,
			"repo_property_filters": flattenRepoPropertyFilters(policy.RepoPropertyFilters, &resp.Diagnostics),
			"policy_config":         policyConfigObj,
		}

		runPolicyAttrTypes := map[string]attr.Type{
			"owner":                 types.StringType,
			"customer":              types.StringType,
			"policy_id":             types.StringType,
			"name":                  types.StringType,
			"created_by":            types.StringType,
			"created_at":            types.StringType,
			"last_updated_by":       types.StringType,
			"last_updated_at":       types.StringType,
			"all_repos":             types.BoolType,
			"all_orgs":              types.BoolType,
			"repositories":          types.ListType{ElemType: types.StringType},
			"repo_property_filters": types.ListType{ElemType: repoPropertyFilterObjectType},
			"policy_config":         types.ObjectType{AttrTypes: policyConfigAttrTypes},
		}

		runPolicyObj, _ := types.ObjectValue(runPolicyAttrTypes, runPolicyAttrs)
		runPoliciesList = append(runPoliciesList, runPolicyObj)
	}

	// Create the final list
	runPolicyAttrTypes := map[string]attr.Type{
		"owner":                 types.StringType,
		"customer":              types.StringType,
		"policy_id":             types.StringType,
		"name":                  types.StringType,
		"created_by":            types.StringType,
		"created_at":            types.StringType,
		"last_updated_by":       types.StringType,
		"last_updated_at":       types.StringType,
		"all_repos":             types.BoolType,
		"all_orgs":              types.BoolType,
		"repositories":          types.ListType{ElemType: types.StringType},
		"repo_property_filters": types.ListType{ElemType: repoPropertyFilterObjectType},
		"policy_config": types.ObjectType{AttrTypes: map[string]attr.Type{
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
		}},
	}

	runPoliciesListValue, _ := types.ListValue(types.ObjectType{AttrTypes: runPolicyAttrTypes}, runPoliciesList)
	state.RunPolicies = runPoliciesListValue

	// Set the state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}
