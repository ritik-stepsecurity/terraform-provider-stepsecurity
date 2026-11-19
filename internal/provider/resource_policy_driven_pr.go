package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                   = &policyDrivenPRResource{}
	_ resource.ResourceWithConfigure      = &policyDrivenPRResource{}
	_ resource.ResourceWithValidateConfig = &policyDrivenPRResource{}
	_ resource.ResourceWithModifyPlan     = &policyDrivenPRResource{}
	_ resource.ResourceWithImportState    = &policyDrivenPRResource{}
)

// NewPolicyDrivenPRResource is a helper function to simplify the provider implementation.
func NewPolicyDrivenPRResource() resource.Resource {
	return &policyDrivenPRResource{}
}

// policyDrivenPRResource is the resource implementation.
type policyDrivenPRResource struct {
	client stepsecurityapi.Client
}

// Configure adds the provider configured client to the resource.
func (r *policyDrivenPRResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Add a nil check when handling ProviderData because Terraform
	// sets that data after it calls the ConfigureProvider RPC.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(stepsecurityapi.Client)

	if !ok || client == nil {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected stepsecurityapi.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	r.client = client
}

// Metadata returns the resource type name.
func (r *policyDrivenPRResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_driven_pr"
}

// Schema defines the schema for the resource.
func (r *policyDrivenPRResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages policy-driven PRs for a GitHub organization in StepSecurity.\n\n" +
			"Each resource applies one set of `auto_remediation_options` to the repositories it selects:\n\n" +
			"- `selected_repos = [\"*\"]` applies the settings at the organization level, to every repository, " +
			"and turns on \"Apply to all repositories\". Use `excluded_repos` to opt repositories out, and " +
			"`selected_repos_filter` to limit it to repositories with given topics.\n" +
			"- A list of repositories applies the settings to each of those repositories as its own repo-level configuration.\n\n" +
			"To give some repositories different settings, use one resource per set of settings: an organization-level " +
			"resource that lists those repositories in `excluded_repos`, plus a resource that selects them, as shown in the examples below. " +
			"Each repository should be selected by only one resource, otherwise the resources overwrite each other's settings on every apply. " +
			"Destroying an organization-level resource, or changing its `selected_repos` from `[\"*\"]` to specific repositories, " +
			"resets the policy-driven PR configuration of every repository in the organization, including those managed by other resources; " +
			"apply again to restore them.\n\n" +
			"Import reads the organization's current configuration. It imports `[\"*\"]` when \"Apply to all repositories\" is on, " +
			"and otherwise the repositories that are selected. Because one resource holds one set of settings, import fails when the " +
			"selected repositories have different settings; give them the same settings first, or declare one resource per set of settings without importing.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The ID of the policy-driven PR. This is same as the owner/organization name.",
			},
			"owner": schema.StringAttribute{
				Required:    true,
				Description: "The owner/organization name where the policy-driven PR's to be created.",
			},
			"auto_remediation_options": schema.SingleNestedAttribute{
				Required: true,
				Attributes: map[string]schema.Attribute{
					"create_pr": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Create a PR when a finding is detected.",
						Default:     booldefault.StaticBool(true),
					},
					"create_issue": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Create an issue when a finding is detected.",
						Default:     booldefault.StaticBool(false),
					},
					"create_github_advanced_security_alert": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Create a GitHub Advanced Security alert when a finding is detected. Note that this triggers only when issue creation is enabled.",
						Default:     booldefault.StaticBool(false),
					},
					"harden_github_hosted_runner": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "When enabled, this creates a PR/issue to install security agent on the GitHub-hosted runner to prevent exfiltration of credentials, monitor the build process, and detect compromised dependencies.",
						Default:     booldefault.StaticBool(false),
					},
					"pin_actions_to_sha": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "When enabled, this creates a PR/issue to pin actions to SHA. GitHub's Security Hardening guide recommends pinning actions to full length commit for third party actions.",
						Default:     booldefault.StaticBool(false),
					},
					"restrict_github_token_permissions": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "When enabled, this creates a PR/issue to restrict GitHub token permissions. GitHub's Security Hardening guide recommends restricting permissions to the minimum required",
						Default:     booldefault.StaticBool(false),
					},
					"secure_docker_file": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "When enabled, this creates a PR/issue to secure Dockerfile by pinning base images to SHA.",
						Default:     booldefault.StaticBool(false),
					},
					"labels_to_replace": schema.MapAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Description: "Map of runner labels to replace with their alternatives (e.g., {\"disallowed-label\": \"allowed-label\"}). When specified, this creates a PR/issue to replace disallowed runner labels.",
					},
					"actions_to_exempt_while_pinning": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Description: "List of actions to exempt while pinning actions to SHA. When exempted, the action will not be pinned to SHA.",
						Default: listdefault.StaticValue(
							types.ListValueMust(
								types.StringType,
								[]attr.Value{},
							),
						),
					},
					"images_to_exempt_while_pinning": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Description: "List of Docker images to exempt while pinning images to SHA. When exempted, the image will not be pinned to SHA.",
						Default: listdefault.StaticValue(
							types.ListValueMust(
								types.StringType,
								[]attr.Value{},
							),
						),
					},
					"actions_to_replace_with_step_security_actions": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Description: "List of actions to replace with Step Security actions. When provided, the actions will be replaced with Step Security actions.",
						Default: listdefault.StaticValue(
							types.ListValueMust(
								types.StringType,
								[]attr.Value{},
							),
						),
					},
					"custom_actions_to_replace": schema.MapAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Description: "Map of actions to replace with custom replacements. Keys are the original action names, values are the replacement action names chosen by the customer.",
					},
					"replace_action_on_major_tag_match": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "When enabled, actions in actions_to_replace_with_step_security_actions are replaced only when the major tag matches. Requires actions_to_replace_with_step_security_actions to be non-empty.",
						Default:     booldefault.StaticBool(false),
					},
					"actions_exempted_from_replacement": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Description: "List of actions to exempt from replacement. When set, ALL maintained actions are replaced EXCEPT those listed. Mutually exclusive with actions_to_replace_with_step_security_actions.",
						Default: listdefault.StaticValue(
							types.ListValueMust(
								types.StringType,
								[]attr.Value{},
							),
						),
					},
					"update_precommit_file": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Description: "List of pre-commit file paths to update (e.g., ['.pre-commit-config.yaml']).",
						Default: listdefault.StaticValue(
							types.ListValueMust(
								types.StringType,
								[]attr.Value{},
							),
						),
					},
					"custom_precommit_config": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Provide a full .pre-commit-config.yaml verbatim instead of assembling it from update_precommit_file hooks. Mutually exclusive with update_precommit_file.",
						Attributes: map[string]schema.Attribute{
							"config": schema.StringAttribute{
								Required:    true,
								Description: "The full .pre-commit-config.yaml content to write to the repository.",
							},
							"update_existing_configuration": schema.BoolAttribute{
								Optional:    true,
								Computed:    true,
								Default:     booldefault.StaticBool(false),
								Description: "When true, overwrite an existing .pre-commit-config.yaml. When false (default), an existing file is left untouched and one is only created when absent.",
							},
						},
					},
					"package_ecosystem": schema.ListNestedAttribute{
						Optional:    true,
						Description: "List of package ecosystems to enable for dependency updates.",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"package": schema.StringAttribute{
									Required:    true,
									Description: "Package ecosystem (e.g., 'npm', 'pip', 'docker').",
								},
								"interval": schema.StringAttribute{
									Required:    true,
									Description: "Update interval (e.g., 'daily', 'weekly', 'monthly').",
								},
								"cooldown_yaml": schema.StringAttribute{
									Optional:    true,
									Description: "YAML string configuring cooldown periods for dependency updates.",
									// An empty string is never sent and reads back as null, so it
									// would show a diff on every plan. Omit the attribute instead.
									Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
								},
								"groups_yaml": schema.StringAttribute{
									Optional:    true,
									Description: "YAML string configuring dependency update groups.",
									// An empty string is never sent and reads back as null, so it
									// would show a diff on every plan. Omit the attribute instead.
									Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
								},
								"options_yaml": schema.StringAttribute{
									Optional:    true,
									Description: "YAML string configuring additional dependabot options (e.g. day, time, timezone, allow, assignees, labels, ignore, reviewers, target-branch, versioning-strategy, etc.).",
									// An empty string is never sent and reads back as null, so it
									// would show a diff on every plan. Omit the attribute instead.
									Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
								},
							},
						},
					},
					// A set rather than a list: the patterns are an unordered
					// collection, so ordering carries no meaning and duplicates are
					// never intended. Declaring that in the schema makes Terraform
					// dedupe the config and ignore element order when diffing, instead
					// of the provider realigning the API ordering against state to
					// avoid a spurious diff.
					"dockerfile_patterns": schema.SetAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Description: "Extra shell-glob patterns, matched case-insensitively against a file's name only (not its path), naming files that the Docker base image pinning control (secure_docker_file) should pin in addition to files named exactly 'Dockerfile'. The built-in rule always applies, so these can only ever pin more files, never fewer. Use this for repositories naming files 'Dockerfile.dev' or 'Containerfile'. Example: [\"Dockerfile.*\", \"Containerfile\"].",
						// The API does not return an empty list, so [] would read back as
						// null and show a diff on every plan. Omitting the attribute
						// already means "no extra patterns".
						Validators: []validator.Set{setvalidator.SizeAtLeast(1)},
					},
					"update_existing_configuration": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "When enabled, dependabot will remove existing entries that are not in the package_ecosystem config.",
						Default:     booldefault.StaticBool(false),
					},
					"add_workflows": schema.StringAttribute{
						Optional:    true,
						Description: "Additional workflows to add as part of policy-driven PR.",
					},
					"action_commit_map": schema.MapAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Description: "Map of actions to their corresponding commit SHAs to bypass pinning",
					},
					"harden_runner_config": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Configuration for harden runner. When not provided, the default harden runner config will be applied.",
						Attributes: map[string]schema.Attribute{
							"config": schema.StringAttribute{
								Optional:    true,
								Description: "YAML string configuring the harden runner.",
							},
							"update_existing_configuration": schema.BoolAttribute{
								Optional:    true,
								Computed:    true,
								Default:     booldefault.StaticBool(false),
								Description: "When enabled, removes existing harden runner configurations not in the config.",
							},
							"target_runner_labels": schema.ListAttribute{
								ElementType: types.StringType,
								Optional:    true,
								Computed:    true,
								Default: listdefault.StaticValue(
									types.ListValueMust(types.StringType, []attr.Value{}),
								),
								Description: "List of runner labels to apply the harden runner config to. When non-empty, skip_harden_runner is automatically set to true internally.",
							},
							"exempt_runner_labels": schema.SetAttribute{
								ElementType: types.StringType,
								Optional:    true,
								Computed:    true,
								Default: setdefault.StaticValue(
									types.SetValueMust(types.StringType, []attr.Value{}),
								),
								Description: "Set of runner label glob patterns (e.g. \"gpu-*\") to exclude from harden runner. Jobs whose runs-on matches any pattern are skipped, regardless of target_runner_labels. Order is not significant.",
							},
						},
					},
				},
			},
			"selected_repos": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "List of repositories to apply the policy-driven PR to. Use ['*'] to apply to all repositories.",
			},
			"selected_repos_filter": schema.SingleNestedAttribute{
				Optional: true,
				Attributes: map[string]schema.Attribute{
					"include_repos_only_with_topics": schema.SetAttribute{
						ElementType: types.StringType,
						Optional:    true,
						Description: "Topics that repos should have when selected_repos is ['*'].",
					},
				},
			},
			"excluded_repos": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "List of repositories to exclude when selected_repos is ['*']. It restores their original configs (preserving configs from other Terraform resources) or deletes configs for repos that had none.",
				Default: listdefault.StaticValue(
					types.ListValueMust(
						types.StringType,
						[]attr.Value{},
					),
				),
			},
		},
	}
}

// ImportState implements resource.ResourceWithImportState.
func (r *policyDrivenPRResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import ID should be the owner name
	owner := req.ID

	// Discover the policy configuration for this owner
	policy, err := r.client.DiscoverPolicyDrivenPRConfig(ctx, owner)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Import Policy-Driven PR",
			fmt.Sprintf("Failed to discover policy configuration: %s", err.Error()),
		)
		return
	}

	if policy == nil || len(policy.SelectedRepos) == 0 {
		resp.Diagnostics.AddError(
			"Unable to Import Policy-Driven PR",
			fmt.Sprintf("No policy-driven PR configuration found for owner '%s'", owner),
		)
		return
	}

	// Convert the discovered policy to Terraform state
	var state policyDrivenPRModel
	state.ID = types.StringValue(owner)
	state.Owner = types.StringValue(owner)

	// Set selected_repos
	repoElements := make([]types.String, len(policy.SelectedRepos))
	for i, repo := range policy.SelectedRepos {
		repoElements[i] = types.StringValue(repo)
	}
	repoList, _ := types.ListValueFrom(ctx, types.StringType, repoElements)
	state.SelectedRepos = repoList

	// Set excluded_repos (empty by default for import)
	state.ExcludedRepos = types.ListValueMust(types.StringType, []attr.Value{})

	// Set selected_repos_filter
	if len(policy.SelectedReposFilter.ReposTopics) > 0 {
		topicsElements := make([]attr.Value, len(policy.SelectedReposFilter.ReposTopics))
		for i, topic := range policy.SelectedReposFilter.ReposTopics {
			topicsElements[i] = types.StringValue(topic)
		}
		topicsSet, _ := types.SetValue(types.StringType, topicsElements)

		filterObj, _ := types.ObjectValue(
			map[string]attr.Type{
				"include_repos_only_with_topics": types.SetType{ElemType: types.StringType},
			},
			map[string]attr.Value{
				"include_repos_only_with_topics": topicsSet,
			},
		)
		state.SelectedReposFilter = filterObj
	} else {
		// Set to null if no filter is present
		state.SelectedReposFilter = types.ObjectNull(map[string]attr.Type{
			"include_repos_only_with_topics": types.SetType{ElemType: types.StringType},
		})
	}

	// Set auto_remediation_options
	exemptElements := make([]types.String, len(policy.AutoRemdiationOptions.ActionsToExemptWhilePinning))
	for i, action := range policy.AutoRemdiationOptions.ActionsToExemptWhilePinning {
		exemptElements[i] = types.StringValue(action)
	}
	exemptList, _ := types.ListValueFrom(ctx, types.StringType, exemptElements)

	exemptImagesElements := make([]types.String, len(policy.AutoRemdiationOptions.ImagesToExemptWhilePinning))
	for i, image := range policy.AutoRemdiationOptions.ImagesToExemptWhilePinning {
		exemptImagesElements[i] = types.StringValue(image)
	}
	exemptImagesList, _ := types.ListValueFrom(ctx, types.StringType, exemptImagesElements)

	replaceElements := make([]types.String, len(policy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions))
	for i, action := range policy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions {
		replaceElements[i] = types.StringValue(action)
	}
	replaceList, _ := types.ListValueFrom(ctx, types.StringType, replaceElements)

	exemptedFromReplacementElements := make([]types.String, len(policy.AutoRemdiationOptions.ExemptedFromReplacement))
	for i, action := range policy.AutoRemdiationOptions.ExemptedFromReplacement {
		exemptedFromReplacementElements[i] = types.StringValue(action)
	}
	exemptedFromReplacementList, _ := types.ListValueFrom(ctx, types.StringType, exemptedFromReplacementElements)

	// Null rather than an empty set when unset: dockerfile_patterns is Optional
	// and not Computed, so returning [] for a config that omits it would read as
	// a permanent diff.
	dockerfilePatternsSet := types.SetNull(types.StringType)
	if len(policy.AutoRemdiationOptions.DockerfilePatterns) > 0 {
		elements := make([]types.String, len(policy.AutoRemdiationOptions.DockerfilePatterns))
		for i, pattern := range policy.AutoRemdiationOptions.DockerfilePatterns {
			elements[i] = types.StringValue(pattern)
		}
		dockerfilePatternsSet, _ = types.SetValueFrom(ctx, types.StringType, elements)
	}

	// The API returns cooldown and groups parsed, not as the YAML the practitioner
	// wrote. There is no prior state on import, so they are rendered as YAML.
	policy.AutoRemdiationOptions.PackageEcosystem = recoverDependabotYAML(policy.AutoRemdiationOptions.PackageEcosystem, nil)

	var packageEcosystemList types.List
	if len(policy.AutoRemdiationOptions.PackageEcosystem) > 0 {
		var ecosystemObjects []attr.Value
		for _, ecosystem := range policy.AutoRemdiationOptions.PackageEcosystem {
			obj, _ := types.ObjectValue(
				map[string]attr.Type{
					"package":       types.StringType,
					"interval":      types.StringType,
					"cooldown_yaml": types.StringType,
					"groups_yaml":   types.StringType,
					"options_yaml":  types.StringType,
				},
				map[string]attr.Value{
					"package":       types.StringValue(ecosystem.Package),
					"interval":      types.StringValue(ecosystem.Interval),
					"cooldown_yaml": stringOrNull(ecosystem.CoolDownYAML),
					"groups_yaml":   stringOrNull(ecosystem.GroupsYAML),
					"options_yaml":  stringOrNull(ecosystem.OptionsYAML),
				},
			)
			ecosystemObjects = append(ecosystemObjects, obj)
		}
		packageEcosystemList, _ = types.ListValue(
			types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"package":       types.StringType,
					"interval":      types.StringType,
					"cooldown_yaml": types.StringType,
					"groups_yaml":   types.StringType,
					"options_yaml":  types.StringType,
				},
			},
			ecosystemObjects,
		)
	} else {
		packageEcosystemList = types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"package":       types.StringType,
				"interval":      types.StringType,
				"cooldown_yaml": types.StringType,
				"groups_yaml":   types.StringType,
				"options_yaml":  types.StringType,
			},
		})
	}

	var updatePrecommitFileList types.List
	if len(policy.AutoRemdiationOptions.UpdatePrecommitFile) > 0 {
		fileElements := make([]types.String, len(policy.AutoRemdiationOptions.UpdatePrecommitFile))
		for i, file := range policy.AutoRemdiationOptions.UpdatePrecommitFile {
			fileElements[i] = types.StringValue(file)
		}
		updatePrecommitFileList, _ = types.ListValueFrom(ctx, types.StringType, fileElements)
	} else {
		// Return empty list instead of null to match schema default
		updatePrecommitFileList = types.ListValueMust(types.StringType, []attr.Value{})
	}

	var addWorkflowsValue types.String
	if policy.AutoRemdiationOptions.AddWorkflows != "" {
		addWorkflowsValue = types.StringValue(policy.AutoRemdiationOptions.AddWorkflows)
	} else {
		addWorkflowsValue = types.StringNull()
	}

	var actionCommitMapValue types.Map
	if len(policy.AutoRemdiationOptions.ActionCommitMap) > 0 {
		mapElements := make(map[string]attr.Value)
		for key, value := range policy.AutoRemdiationOptions.ActionCommitMap {
			mapElements[key] = types.StringValue(value)
		}
		actionCommitMapValue, _ = types.MapValue(types.StringType, mapElements)
	} else {
		actionCommitMapValue = types.MapNull(types.StringType)
	}

	var customActionsToReplaceValue types.Map
	if len(policy.AutoRemdiationOptions.CustomActionsToReplace) > 0 {
		mapElements := make(map[string]attr.Value)
		for key, value := range policy.AutoRemdiationOptions.CustomActionsToReplace {
			mapElements[key] = types.StringValue(value)
		}
		customActionsToReplaceValue, _ = types.MapValue(types.StringType, mapElements)
	} else {
		customActionsToReplaceValue = types.MapNull(types.StringType)
	}

	var labelsToReplaceValue types.Map
	if len(policy.AutoRemdiationOptions.LabelsToReplace) > 0 {
		mapElements := make(map[string]attr.Value)
		for key, value := range policy.AutoRemdiationOptions.LabelsToReplace {
			mapElements[key] = types.StringValue(value)
		}
		labelsToReplaceValue, _ = types.MapValue(types.StringType, mapElements)
	} else {
		labelsToReplaceValue = types.MapNull(types.StringType)
	}

	optionsObj, _ := types.ObjectValue(
		map[string]attr.Type{
			"create_pr":                                     types.BoolType,
			"create_issue":                                  types.BoolType,
			"create_github_advanced_security_alert":         types.BoolType,
			"harden_github_hosted_runner":                   types.BoolType,
			"pin_actions_to_sha":                            types.BoolType,
			"restrict_github_token_permissions":             types.BoolType,
			"secure_docker_file":                            types.BoolType,
			"labels_to_replace":                             types.MapType{ElemType: types.StringType},
			"actions_to_exempt_while_pinning":               types.ListType{ElemType: types.StringType},
			"images_to_exempt_while_pinning":                types.ListType{ElemType: types.StringType},
			"actions_to_replace_with_step_security_actions": types.ListType{ElemType: types.StringType},
			"custom_actions_to_replace":                     types.MapType{ElemType: types.StringType},
			"replace_action_on_major_tag_match":             types.BoolType,
			"actions_exempted_from_replacement":             types.ListType{ElemType: types.StringType},
			"update_precommit_file":                         types.ListType{ElemType: types.StringType},
			"custom_precommit_config": types.ObjectType{AttrTypes: map[string]attr.Type{
				"config":                        types.StringType,
				"update_existing_configuration": types.BoolType,
			}},
			"package_ecosystem": types.ListType{
				ElemType: types.ObjectType{
					AttrTypes: map[string]attr.Type{
						"package":       types.StringType,
						"interval":      types.StringType,
						"cooldown_yaml": types.StringType,
						"groups_yaml":   types.StringType,
						"options_yaml":  types.StringType,
					},
				},
			},
			"dockerfile_patterns":           types.SetType{ElemType: types.StringType},
			"update_existing_configuration": types.BoolType,
			"add_workflows":                 types.StringType,
			"action_commit_map":             types.MapType{ElemType: types.StringType},
			"harden_runner_config": types.ObjectType{AttrTypes: map[string]attr.Type{
				"config":                        types.StringType,
				"update_existing_configuration": types.BoolType,
				"target_runner_labels":          types.ListType{ElemType: types.StringType},
				"exempt_runner_labels":          types.SetType{ElemType: types.StringType},
			}},
		},
		map[string]attr.Value{
			"create_pr":                                     types.BoolValue(policy.AutoRemdiationOptions.CreatePR),
			"create_issue":                                  types.BoolValue(policy.AutoRemdiationOptions.CreateIssue),
			"create_github_advanced_security_alert":         types.BoolValue(policy.AutoRemdiationOptions.CreateGitHubAdvancedSecurityAlert),
			"harden_github_hosted_runner":                   types.BoolValue(policy.AutoRemdiationOptions.HardenGitHubHostedRunner),
			"pin_actions_to_sha":                            types.BoolValue(policy.AutoRemdiationOptions.PinActionsToSHA),
			"restrict_github_token_permissions":             types.BoolValue(policy.AutoRemdiationOptions.RestrictGitHubTokenPermissions),
			"secure_docker_file":                            types.BoolValue(policy.AutoRemdiationOptions.SecureDockerFile),
			"labels_to_replace":                             labelsToReplaceValue,
			"actions_to_exempt_while_pinning":               exemptList,
			"images_to_exempt_while_pinning":                exemptImagesList,
			"actions_to_replace_with_step_security_actions": replaceList,
			"custom_actions_to_replace":                     customActionsToReplaceValue,
			"replace_action_on_major_tag_match": types.BoolValue(func() bool {
				if policy.AutoRemdiationOptions.ReplaceByMajorTag != nil {
					return *policy.AutoRemdiationOptions.ReplaceByMajorTag
				}
				return false
			}()),
			"update_precommit_file":             updatePrecommitFileList,
			"package_ecosystem":                 packageEcosystemList,
			"dockerfile_patterns":               dockerfilePatternsSet,
			"actions_exempted_from_replacement": exemptedFromReplacementList,
			"update_existing_configuration": types.BoolValue(func() bool {
				if policy.AutoRemdiationOptions.Subtractive != nil {
					return *policy.AutoRemdiationOptions.Subtractive
				}
				return false
			}()),
			"add_workflows":     addWorkflowsValue,
			"action_commit_map": actionCommitMapValue,
			"custom_precommit_config": func() attr.Value {
				cpcAttrTypes := map[string]attr.Type{
					"config":                        types.StringType,
					"update_existing_configuration": types.BoolType,
				}
				if policy.AutoRemdiationOptions.CustomPrecommitConfig != nil {
					obj, _ := types.ObjectValue(cpcAttrTypes, map[string]attr.Value{
						"config":                        types.StringValue(policy.AutoRemdiationOptions.CustomPrecommitConfig.Config),
						"update_existing_configuration": types.BoolValue(policy.AutoRemdiationOptions.CustomPrecommitConfig.UpdateExistingConfiguration),
					})
					return obj
				}
				return types.ObjectNull(cpcAttrTypes)
			}(),
			"harden_runner_config": func() attr.Value {
				if policy.AutoRemdiationOptions.HardenRunnerConfig != nil {
					hrLabels := policy.AutoRemdiationOptions.HardenRunnerConfig.RunnerLabels
					labelElems := make([]attr.Value, len(hrLabels))
					for i, l := range hrLabels {
						labelElems[i] = types.StringValue(l)
					}
					labelsList, _ := types.ListValue(types.StringType, labelElems)
					exemptLabels := policy.AutoRemdiationOptions.HardenRunnerConfig.ExemptRunnerLabels
					exemptLabelElems := make([]attr.Value, len(exemptLabels))
					for i, l := range exemptLabels {
						exemptLabelElems[i] = types.StringValue(l)
					}
					exemptLabelsSet, _ := types.SetValue(types.StringType, exemptLabelElems)
					obj, _ := types.ObjectValue(
						map[string]attr.Type{
							"config":                        types.StringType,
							"update_existing_configuration": types.BoolType,
							"target_runner_labels":          types.ListType{ElemType: types.StringType},
							"exempt_runner_labels":          types.SetType{ElemType: types.StringType},
						},
						map[string]attr.Value{
							"config":                        stringOrNull(policy.AutoRemdiationOptions.HardenRunnerConfig.Config),
							"update_existing_configuration": types.BoolValue(policy.AutoRemdiationOptions.HardenRunnerConfig.Subtractive),
							"target_runner_labels":          labelsList,
							"exempt_runner_labels":          exemptLabelsSet,
						},
					)
					return obj
				}
				return types.ObjectNull(map[string]attr.Type{
					"config":                        types.StringType,
					"update_existing_configuration": types.BoolType,
					"target_runner_labels":          types.ListType{ElemType: types.StringType},
					"exempt_runner_labels":          types.SetType{ElemType: types.StringType},
				})
			}(),
		},
	)
	state.AutoRemdiationOptions = optionsObj

	// Set the state
	diags := resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

type policyDrivenPRModel struct {
	ID                    types.String `tfsdk:"id"`
	Owner                 types.String `tfsdk:"owner"`
	AutoRemdiationOptions types.Object `tfsdk:"auto_remediation_options"`
	SelectedRepos         types.List   `tfsdk:"selected_repos"`
	SelectedReposFilter   types.Object `tfsdk:"selected_repos_filter"`
	ExcludedRepos         types.List   `tfsdk:"excluded_repos"`
}

type selectedReposFilterModel struct {
	IncludeReposOnlyWithTopics types.Set `tfsdk:"include_repos_only_with_topics"`
}

type autoRemdiationOptionsModel struct {
	CreatePR                                types.Bool   `tfsdk:"create_pr"`
	CreateIssue                             types.Bool   `tfsdk:"create_issue"`
	CreateGitHubAdvancedSecurityAlert       types.Bool   `tfsdk:"create_github_advanced_security_alert"`
	PinActionsToSHA                         types.Bool   `tfsdk:"pin_actions_to_sha"`
	HardenGitHubHostedRunner                types.Bool   `tfsdk:"harden_github_hosted_runner"`
	RestrictGitHubTokenPermissions          types.Bool   `tfsdk:"restrict_github_token_permissions"`
	SecureDockerFile                        types.Bool   `tfsdk:"secure_docker_file"`
	LabelsToReplace                         types.Map    `tfsdk:"labels_to_replace"`
	ActionsToExemptWhilePinning             types.List   `tfsdk:"actions_to_exempt_while_pinning"`
	ImagesToExemptWhilePinning              types.List   `tfsdk:"images_to_exempt_while_pinning"`
	ActionsToReplaceWithStepSecurityActions types.List   `tfsdk:"actions_to_replace_with_step_security_actions"`
	CustomActionsToReplace                  types.Map    `tfsdk:"custom_actions_to_replace"`
	ReplaceByMajorTag                       types.Bool   `tfsdk:"replace_action_on_major_tag_match"`
	ExemptedFromReplacement                 types.List   `tfsdk:"actions_exempted_from_replacement"`
	UpdatePrecommitFile                     types.List   `tfsdk:"update_precommit_file"`
	CustomPrecommitConfig                   types.Object `tfsdk:"custom_precommit_config"`
	PackageEcosystem                        types.List   `tfsdk:"package_ecosystem"`
	DockerfilePatterns                      types.Set    `tfsdk:"dockerfile_patterns"`
	UpdateExistingConfiguration             types.Bool   `tfsdk:"update_existing_configuration"`
	AddWorkflows                            types.String `tfsdk:"add_workflows"`
	ActionCommitMap                         types.Map    `tfsdk:"action_commit_map"`
	HardenRunnerConfig                      types.Object `tfsdk:"harden_runner_config"`
}

type packageEcosystemModel struct {
	Package      types.String `tfsdk:"package"`
	Interval     types.String `tfsdk:"interval"`
	CoolDownYAML types.String `tfsdk:"cooldown_yaml"`
	GroupsYAML   types.String `tfsdk:"groups_yaml"`
	OptionsYAML  types.String `tfsdk:"options_yaml"`
}

type hardenRunnerConfigModel struct {
	Config                      types.String `tfsdk:"config"`
	UpdateExistingConfiguration types.Bool   `tfsdk:"update_existing_configuration"`
	RunnerLabels                types.List   `tfsdk:"target_runner_labels"`
	ExemptRunnerLabels          types.Set    `tfsdk:"exempt_runner_labels"`
}

type customPrecommitConfigModel struct {
	Config                      types.String `tfsdk:"config"`
	UpdateExistingConfiguration types.Bool   `tfsdk:"update_existing_configuration"`
}

type ActionsToReplaceModel struct {
	ActionName         string `tfsdk:"action_name"`
	StepSecurityAction string `tfsdk:"stepsecurity_action"`
}

func (r *policyDrivenPRResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config policyDrivenPRModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !config.SelectedRepos.IsUnknown() && (config.SelectedRepos.IsNull() || len(config.SelectedRepos.Elements()) == 0) {
		resp.Diagnostics.AddError(
			"Selected Repos is required",
			"At least one repo is required in selected_repos",
		)
		return
	}

	// Get selected repos
	var selectedRepos []string
	if !config.SelectedRepos.IsUnknown() {
		elements := config.SelectedRepos.Elements()
		for _, elem := range elements {
			selectedRepos = append(selectedRepos, elem.(types.String).ValueString())
		}
	}

	// Validate excluded_repos only makes sense with wildcard
	hasWildcard := len(selectedRepos) == 1 && selectedRepos[0] == "*"
	if !config.ExcludedRepos.IsUnknown() && !config.ExcludedRepos.IsNull() && len(config.ExcludedRepos.Elements()) > 0 {
		if !hasWildcard {
			resp.Diagnostics.AddError(
				"Invalid Configuration",
				"excluded_repos can only be used when selected_repos is ['*'] (wildcard for all repos)",
			)
		}
	}

	// Validate selected_repos_filter only makes sense with wildcard
	hasSelectedReposFilter := !config.SelectedReposFilter.IsNull() && !config.SelectedReposFilter.IsUnknown()
	if hasSelectedReposFilter {
		var selectedReposFilter selectedReposFilterModel
		diags = config.SelectedReposFilter.As(ctx, &selectedReposFilter, basetypes.ObjectAsOptions{})
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		hasTopicsFilter := !selectedReposFilter.IncludeReposOnlyWithTopics.IsNull() && !selectedReposFilter.IncludeReposOnlyWithTopics.IsUnknown()
		if !hasWildcard && hasTopicsFilter {
			if !hasWildcard {
				resp.Diagnostics.AddError(
					"Invalid Configuration",
					"topics under selected_repos_filter can only be used when selected_repos is ['*'] (wildcard for all repos)",
				)
			}
		}
	}

	// Extract auto_remediation_options for validation
	if !config.AutoRemdiationOptions.IsNull() && !config.AutoRemdiationOptions.IsUnknown() {
		var options autoRemdiationOptionsModel
		diags := config.AutoRemdiationOptions.As(ctx, &options, basetypes.ObjectAsOptions{})
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}

		if !options.CreatePR.IsNull() && !options.CreateIssue.IsNull() &&
			options.CreatePR.ValueBool() && options.CreateIssue.ValueBool() {
			resp.Diagnostics.AddError(
				"Create PR and Create Issue cannot be both true",
				"Create PR and Create Issue cannot be both true",
			)
		}

		if !options.CreateGitHubAdvancedSecurityAlert.IsNull() && !options.CreateIssue.IsNull() &&
			options.CreateGitHubAdvancedSecurityAlert.ValueBool() && !options.CreateIssue.ValueBool() {
			resp.Diagnostics.AddError(
				"GitHub Advanced Security Alert can only be true if Create Issue is true",
				"GitHub Advanced Security Alert can only be triggered when issue creation is enabled",
			)
		}

		if !options.ReplaceByMajorTag.IsNull() && !options.ReplaceByMajorTag.IsUnknown() &&
			options.ReplaceByMajorTag.ValueBool() {
			hasActionsToReplace := !options.ActionsToReplaceWithStepSecurityActions.IsNull() &&
				!options.ActionsToReplaceWithStepSecurityActions.IsUnknown() &&
				len(options.ActionsToReplaceWithStepSecurityActions.Elements()) > 0
			if !hasActionsToReplace {
				resp.Diagnostics.AddError(
					"Invalid Configuration",
					"replace_action_on_major_tag_match can only be set to true when actions_to_replace_with_step_security_actions is non-empty",
				)
			}
		}
		hasExemptedFromReplacement := !options.ExemptedFromReplacement.IsNull() && !options.ExemptedFromReplacement.IsUnknown() && len(options.ExemptedFromReplacement.Elements()) > 0
		if hasExemptedFromReplacement {
			// actions_exempted_from_replacement requires actions_to_replace_with_step_security_actions = ["*"]
			actionsToReplaceElems := options.ActionsToReplaceWithStepSecurityActions.Elements()
			isWildcard := len(actionsToReplaceElems) == 1 && actionsToReplaceElems[0].(types.String).ValueString() == "*"
			if !isWildcard {
				resp.Diagnostics.AddError(
					"Invalid Configuration",
					"actions_exempted_from_replacement can only be used when actions_to_replace_with_step_security_actions is [\"*\"]",
				)
			}
		}

		if !options.HardenRunnerConfig.IsNull() && !options.HardenRunnerConfig.IsUnknown() {
			if options.HardenGitHubHostedRunner.IsNull() || !options.HardenGitHubHostedRunner.ValueBool() {
				resp.Diagnostics.AddError(
					"Invalid Configuration",
					"harden_runner_config can only be set when harden_github_hosted_runner is true",
				)
			}
		}

		// The API reads dockerfile_patterns only when the base image pinning
		// control is on, and drops it silently otherwise. Configuring patterns
		// against a disabled control then looks like the patterns are broken
		// rather than unused, so fail at plan time instead.
		hasDockerfilePatterns := !options.DockerfilePatterns.IsNull() && !options.DockerfilePatterns.IsUnknown() && len(options.DockerfilePatterns.Elements()) > 0
		if hasDockerfilePatterns {
			// Skip while secure_docker_file is unknown: ValueBool() is false then,
			// which would reject a config that is valid once the value is known.
			if !options.SecureDockerFile.IsUnknown() && (options.SecureDockerFile.IsNull() || !options.SecureDockerFile.ValueBool()) {
				resp.Diagnostics.AddError(
					"Invalid Configuration",
					"dockerfile_patterns can only be set when secure_docker_file is true",
				)
			}
		}

		// Pre-commit remediation has two mutually exclusive modes: selecting hooks
		// (update_precommit_file) or pasting a full .pre-commit-config.yaml
		// (custom_precommit_config). The API rejects a payload that sets both, so
		// catch it at plan time with a clearer message. An empty hook list is not a
		// conflict, that is how a previous selection is cleared.
		if !options.CustomPrecommitConfig.IsNull() && !options.CustomPrecommitConfig.IsUnknown() {
			var cpcModel customPrecommitConfigModel
			diags := options.CustomPrecommitConfig.As(ctx, &cpcModel, basetypes.ObjectAsOptions{})
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}

			hasCustomConfig := !cpcModel.Config.IsUnknown() && strings.TrimSpace(cpcModel.Config.ValueString()) != ""
			hasPrecommitHooks := !options.UpdatePrecommitFile.IsNull() &&
				!options.UpdatePrecommitFile.IsUnknown() &&
				len(options.UpdatePrecommitFile.Elements()) > 0

			if hasCustomConfig && hasPrecommitHooks {
				resp.Diagnostics.AddError(
					"Invalid Configuration",
					"update_precommit_file and custom_precommit_config are mutually exclusive. Select hooks with update_precommit_file, or provide a full .pre-commit-config.yaml with custom_precommit_config, but not both",
				)
			}
		}

	}
}

// ModifyPlan is called during terraform plan to check v2 features and show warnings
func (r *policyDrivenPRResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// If the entire plan is null, the resource is being destroyed, so we don't need to validate
	if req.Plan.Raw.IsNull() {
		return
	}

	// If the state is null, this is a create operation
	// If both state and plan are present, this is an update operation
	var plan policyDrivenPRModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract auto_remediation_options
	if plan.AutoRemdiationOptions.IsNull() || plan.AutoRemdiationOptions.IsUnknown() {
		return
	}

	var options autoRemdiationOptionsModel
	diags = plan.AutoRemdiationOptions.As(ctx, &options, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check v2 features during plan phase
	hasUpdatePrecommit := !options.UpdatePrecommitFile.IsNull() && !options.UpdatePrecommitFile.IsUnknown() && len(options.UpdatePrecommitFile.Elements()) > 0
	hasPackageEcosystem := !options.PackageEcosystem.IsNull() && !options.PackageEcosystem.IsUnknown() && len(options.PackageEcosystem.Elements()) > 0
	hasAddWorkflows := !options.AddWorkflows.IsNull() && !options.AddWorkflows.IsUnknown() && options.AddWorkflows.ValueString() != ""
	hasCustomPrecommitConfig := !options.CustomPrecommitConfig.IsNull() && !options.CustomPrecommitConfig.IsUnknown()
	hasV2Features := hasUpdatePrecommit || hasPackageEcosystem || hasAddWorkflows || hasCustomPrecommitConfig

	if !hasV2Features {
		return
	}

	// Get selected repos to determine which repo to check
	var selectedRepos []string
	if !plan.SelectedRepos.IsNull() {
		elements := plan.SelectedRepos.Elements()
		selectedRepos = make([]string, len(elements))
		for i, elem := range elements {
			selectedRepos[i] = elem.(types.String).ValueString()
		}
	}

	// Determine which repo to check for subscription status
	checkRepo := "[all]"
	if len(selectedRepos) > 0 && selectedRepos[0] != "*" {
		checkRepo = selectedRepos[0]
	}

	status, err := r.client.GetSubscriptionStatus(ctx, plan.Owner.ValueString(), checkRepo)

	if err != nil {
		tflog.Warn(ctx, "Failed to check subscription status during plan, skipping v2 validation", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	if status == nil {
		tflog.Warn(ctx, "Subscription status returned nil during plan, skipping v2 validation", map[string]interface{}{})
		return
	}

	v2Enabled := status.AppFeatureFlags.IsPolicyDrivenPrV2Enabled

	if !v2Enabled {
		warningMessage := "Policy-driven PR v2 is not enabled for this subscription. The following v2-only features will be ignored:\n"
		if hasUpdatePrecommit {
			warningMessage += "- update_precommit_file\n"
		}
		if hasPackageEcosystem {
			warningMessage += "- package_ecosystem\n"
		}
		if hasAddWorkflows {
			warningMessage += "- add_workflows\n"
		}
		warningMessage += "\nTo use these features, please upgrade your subscription to enable policy-driven PR v2."

		resp.Diagnostics.AddWarning(
			"Policy-driven PR v2 Not Enabled",
			warningMessage,
		)
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *policyDrivenPRResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyDrivenPRModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Extract auto_remediation_options
	var options autoRemdiationOptionsModel
	diags = plan.AutoRemdiationOptions.As(ctx, &options, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert Terraform types to Go types for API
	var selectedRepos []string
	if !plan.SelectedRepos.IsNull() {
		elements := plan.SelectedRepos.Elements()
		selectedRepos = make([]string, len(elements))
		for i, elem := range elements {
			selectedRepos[i] = elem.(types.String).ValueString()
		}
	}

	var selectedReposFilterForAllRepos stepsecurityapi.ApplyIssuePRConfigForAllReposFilter
	if !plan.SelectedReposFilter.IsNull() {
		var selectedReposFilter selectedReposFilterModel
		diags := plan.SelectedReposFilter.As(ctx, &selectedReposFilter, basetypes.ObjectAsOptions{})
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		var reposTopics []string
		if !selectedReposFilter.IncludeReposOnlyWithTopics.IsNull() && !selectedReposFilter.IncludeReposOnlyWithTopics.IsUnknown() {
			elements := selectedReposFilter.IncludeReposOnlyWithTopics.Elements()
			reposTopics = make([]string, len(elements))
			for i, elem := range elements {
				reposTopics[i] = elem.(types.String).ValueString()
			}
		}
		selectedReposFilterForAllRepos.ReposTopics = reposTopics
	}

	var excludedRepos []string
	if !plan.ExcludedRepos.IsNull() {
		elements := plan.ExcludedRepos.Elements()
		excludedRepos = make([]string, len(elements))
		for i, elem := range elements {
			excludedRepos[i] = elem.(types.String).ValueString()
		}
	}

	var actionsToExempt []string
	if !options.ActionsToExemptWhilePinning.IsNull() {
		elements := options.ActionsToExemptWhilePinning.Elements()
		actionsToExempt = make([]string, len(elements))
		for i, elem := range elements {
			actionsToExempt[i] = elem.(types.String).ValueString()
		}
	}

	var imagesToExempt []string
	if !options.ImagesToExemptWhilePinning.IsNull() {
		elements := options.ImagesToExemptWhilePinning.Elements()
		imagesToExempt = make([]string, len(elements))
		for i, elem := range elements {
			imagesToExempt[i] = elem.(types.String).ValueString()
		}
	}

	var actionsToReplace []string
	if !options.ActionsToReplaceWithStepSecurityActions.IsNull() {
		elements := options.ActionsToReplaceWithStepSecurityActions.Elements()
		actionsToReplace = make([]string, len(elements))
		for i, elem := range elements {
			actionsToReplace[i] = elem.(types.String).ValueString()
		}
	}

	var exemptedFromReplacement []string
	if !options.ExemptedFromReplacement.IsNull() {
		elements := options.ExemptedFromReplacement.Elements()
		exemptedFromReplacement = make([]string, len(elements))
		for i, elem := range elements {
			exemptedFromReplacement[i] = elem.(types.String).ValueString()
		}
	}

	// Empty rather than nil when unset, so the request clears any patterns the
	// repo already has instead of leaving them in place.
	dockerfilePatterns := []string{}
	if !options.DockerfilePatterns.IsNull() {
		for _, elem := range options.DockerfilePatterns.Elements() {
			dockerfilePatterns = append(dockerfilePatterns, elem.(types.String).ValueString())
		}
	}

	// Extract new optional fields
	var packageEcosystem []stepsecurityapi.DependabotConfig
	if !options.PackageEcosystem.IsNull() {
		var ecosystemModels []packageEcosystemModel
		diags := options.PackageEcosystem.ElementsAs(ctx, &ecosystemModels, false)
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			for _, model := range ecosystemModels {
				packageEcosystem = append(packageEcosystem, stepsecurityapi.DependabotConfig{
					Package:      model.Package.ValueString(),
					Interval:     model.Interval.ValueString(),
					CoolDownYAML: model.CoolDownYAML.ValueString(),
					GroupsYAML:   model.GroupsYAML.ValueString(),
					OptionsYAML:  model.OptionsYAML.ValueString(),
				})
			}
		}
	}

	var updatePrecommitFile []string
	if !options.UpdatePrecommitFile.IsNull() {
		elements := options.UpdatePrecommitFile.Elements()
		updatePrecommitFile = make([]string, len(elements))
		for i, elem := range elements {
			updatePrecommitFile[i] = elem.(types.String).ValueString()
		}
	}

	var actionCommitMap map[string]string
	if !options.ActionCommitMap.IsNull() {
		actionCommitMap = make(map[string]string)
		for key, value := range options.ActionCommitMap.Elements() {
			actionCommitMap[key] = value.(types.String).ValueString()
		}
	}

	var customActionsToReplace map[string]string
	if !options.CustomActionsToReplace.IsNull() && !options.CustomActionsToReplace.IsUnknown() {
		customActionsToReplace = make(map[string]string)
		for key, value := range options.CustomActionsToReplace.Elements() {
			customActionsToReplace[key] = value.(types.String).ValueString()
		}
	}

	var labelsToReplace map[string]string
	if !options.LabelsToReplace.IsNull() {
		labelsToReplace = make(map[string]string)
		for key, value := range options.LabelsToReplace.Elements() {
			labelsToReplace[key] = value.(types.String).ValueString()
		}
	} else {
		labelsToReplace = map[string]string{}
	}

	// Automatically compute config levels based on selected_repos
	// If selected_repos = ["*"], use org-level config
	// Otherwise, use repo-level config
	hasWildcard := len(selectedRepos) == 1 && selectedRepos[0] == "*"
	useOrgLevel := hasWildcard
	useRepoLevel := !hasWildcard

	var subtractive *bool
	if !options.UpdateExistingConfiguration.IsNull() && !options.UpdateExistingConfiguration.IsUnknown() {
		v := options.UpdateExistingConfiguration.ValueBool()
		subtractive = &v
	}

	var replaceByMajorTag *bool
	if !options.ReplaceByMajorTag.IsNull() && !options.ReplaceByMajorTag.IsUnknown() {
		v := options.ReplaceByMajorTag.ValueBool()
		replaceByMajorTag = &v
	}
	var hardenRunnerConfig *stepsecurityapi.HardenRunnerConfig
	if !options.HardenRunnerConfig.IsNull() && !options.HardenRunnerConfig.IsUnknown() {
		var hrcModel hardenRunnerConfigModel
		options.HardenRunnerConfig.As(ctx, &hrcModel, basetypes.ObjectAsOptions{})
		var runnerLabels []string
		if !hrcModel.RunnerLabels.IsNull() {
			for _, elem := range hrcModel.RunnerLabels.Elements() {
				runnerLabels = append(runnerLabels, elem.(types.String).ValueString())
			}
		}
		var exemptRunnerLabels []string
		if !hrcModel.ExemptRunnerLabels.IsNull() {
			for _, elem := range hrcModel.ExemptRunnerLabels.Elements() {
				exemptRunnerLabels = append(exemptRunnerLabels, elem.(types.String).ValueString())
			}
		}
		hardenRunnerConfig = &stepsecurityapi.HardenRunnerConfig{
			Config:             hrcModel.Config.ValueString(),
			Subtractive:        hrcModel.UpdateExistingConfiguration.ValueBool(),
			SkipHardenRunner:   len(runnerLabels) > 0,
			RunnerLabels:       runnerLabels,
			ExemptRunnerLabels: exemptRunnerLabels,
		}
	}

	var customPrecommitConfig *stepsecurityapi.CustomPrecommitConfig
	if !options.CustomPrecommitConfig.IsNull() && !options.CustomPrecommitConfig.IsUnknown() {
		var cpcModel customPrecommitConfigModel
		options.CustomPrecommitConfig.As(ctx, &cpcModel, basetypes.ObjectAsOptions{})
		customPrecommitConfig = &stepsecurityapi.CustomPrecommitConfig{
			Config:                      cpcModel.Config.ValueString(),
			UpdateExistingConfiguration: cpcModel.UpdateExistingConfiguration.ValueBool(),
		}
	}

	// convert to stepsecurityapi.PolicyDrivenPRPolicy
	stepSecurityPolicy := stepsecurityapi.PolicyDrivenPRPolicy{
		Owner: plan.Owner.ValueString(),
		AutoRemdiationOptions: stepsecurityapi.AutoRemdiationOptions{
			CreatePR:                                options.CreatePR.ValueBool(),
			CreateIssue:                             options.CreateIssue.ValueBool(),
			CreateGitHubAdvancedSecurityAlert:       options.CreateGitHubAdvancedSecurityAlert.ValueBool(),
			PinActionsToSHA:                         options.PinActionsToSHA.ValueBool(),
			HardenGitHubHostedRunner:                options.HardenGitHubHostedRunner.ValueBool(),
			RestrictGitHubTokenPermissions:          options.RestrictGitHubTokenPermissions.ValueBool(),
			SecureDockerFile:                        options.SecureDockerFile.ValueBool(),
			LabelsToReplace:                         labelsToReplace,
			ActionsToExemptWhilePinning:             actionsToExempt,
			ImagesToExemptWhilePinning:              imagesToExempt,
			ActionsToReplaceWithStepSecurityActions: actionsToReplace,
			CustomActionsToReplace:                  customActionsToReplace,
			ReplaceByMajorTag:                       replaceByMajorTag,
			ExemptedFromReplacement:                 exemptedFromReplacement,
			UpdatePrecommitFile:                     updatePrecommitFile,
			PackageEcosystem:                        packageEcosystem,
			DockerfilePatterns:                      dockerfilePatterns,
			Subtractive:                             subtractive,
			AddWorkflows:                            options.AddWorkflows.ValueString(),
			ActionCommitMap:                         actionCommitMap,
			HardenRunnerConfig:                      hardenRunnerConfig,
			CustomPrecommitConfig:                   customPrecommitConfig,
		},
		SelectedRepos:       selectedRepos,
		SelectedReposFilter: selectedReposFilterForAllRepos,
		UseRepoLevelConfig:  useRepoLevel,
		UseOrgLevelConfig:   useOrgLevel,
	}

	// Handle excluded repos: Save their current configs before applying org-level config
	var excludedRepoConfigs map[string]*stepsecurityapi.PolicyDrivenPRPolicy
	var err error
	if len(selectedRepos) == 1 && selectedRepos[0] == "*" && len(excludedRepos) > 0 {
		excludedRepoConfigs = make(map[string]*stepsecurityapi.PolicyDrivenPRPolicy)
		for _, repo := range excludedRepos {
			// Read current config for this excluded repo
			currentConfig, err := r.client.GetPolicyDrivenPRPolicy(ctx, plan.Owner.ValueString(), []string{repo})
			if err != nil {
				tflog.Warn(ctx, "Failed to get current config for excluded repo", map[string]interface{}{
					"repo":  repo,
					"error": err.Error(),
				})
				continue
			}
			// Store the config if it exists and has settings
			if currentConfig != nil {
				excludedRepoConfigs[repo] = currentConfig
			}
		}
	}

	// Create policy-driven PR in StepSecurity
	err = r.client.CreatePolicyDrivenPRPolicy(ctx, stepSecurityPolicy)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create Policy-Driven PR",
			err.Error(),
		)
		return
	}

	// Restore original configs for excluded repos to prevent them from inheriting org-level config
	if len(excludedRepoConfigs) > 0 {
		for repo, originalConfig := range excludedRepoConfigs {
			// Restore the original config for this repo
			originalConfig.SelectedRepos = []string{repo}
			err = r.client.CreatePolicyDrivenPRPolicy(ctx, *originalConfig)
			if err != nil {
				resp.Diagnostics.AddError(
					"Unable to Restore Config for Excluded Repo",
					fmt.Sprintf("Failed to restore config for repo %s: %s", repo, err.Error()),
				)
				return
			}
			tflog.Info(ctx, "Restored original config for excluded repo", map[string]interface{}{
				"repo": repo,
			})
		}
	} else if len(selectedRepos) == 1 && selectedRepos[0] == "*" && len(excludedRepos) > 0 {
		// For excluded repos that had no previous config, delete them to prevent inheritance
		err = r.client.DeletePolicyDrivenPRPolicy(ctx, plan.Owner.ValueString(), excludedRepos)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Exclude Repos from Policy-Driven PR",
				fmt.Sprintf("Failed to exclude repos: %s", err.Error()),
			)
			return
		}
	}

	// Set the ID (use owner as the unique identifier)
	plan.ID = types.StringValue(plan.Owner.ValueString())

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *policyDrivenPRResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyDrivenPRModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get current state repos to determine what to query
	var stateSelectedRepos []string
	if !state.SelectedRepos.IsNull() {
		elements := state.SelectedRepos.Elements()
		stateSelectedRepos = make([]string, len(elements))
		for i, elem := range elements {
			stateSelectedRepos[i] = elem.(types.String).ValueString()
		}
	}

	var stateExcludedRepos []string
	if !state.ExcludedRepos.IsNull() {
		elements := state.ExcludedRepos.Elements()
		stateExcludedRepos = make([]string, len(elements))
		for i, elem := range elements {
			stateExcludedRepos[i] = elem.(types.String).ValueString()
		}
	}

	// Query based on what's in the state
	// For org-level (selected_repos = ["*"]), query org config
	// For repo-level, query specific repos
	var reposToQuery []string
	if len(stateSelectedRepos) == 1 && stateSelectedRepos[0] == "*" {
		reposToQuery = []string{"*"}
	} else {
		reposToQuery = append([]string{}, stateSelectedRepos...)
	}

	// Get policy-driven PR from StepSecurity
	stepSecurityPolicy, err := r.client.GetPolicyDrivenPRPolicy(ctx, state.Owner.ValueString(), reposToQuery)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Read Policy-Driven PR",
			err.Error(),
		)
		return
	}

	if stepSecurityPolicy == nil {
		resp.Diagnostics.AddError(
			"Unable to Read Policy-Driven PR",
			"Policy returned nil",
		)
		return
	}

	if stepSecurityPolicy.OrgConfigNotAppliedToAllRepos {
		resp.Diagnostics.AddWarning(
			"Policy-Driven PR Not Applied to All Repositories",
			fmt.Sprintf("selected_repos is [\"*\"], but \"Apply to all repositories\" is turned off for '%s' in StepSecurity, "+
				"so the org-level configuration is not applied to every repository. "+
				"Applying this configuration turns it back on for all repositories in the organization. "+
				"To keep it limited to specific repositories, list them in selected_repos instead.",
				state.Owner.ValueString()),
		)
	}

	// Extract current state's v2 feature values before updating
	var currentStateOptions autoRemdiationOptionsModel
	var hasV2FeaturesInState bool
	if !state.AutoRemdiationOptions.IsNull() {
		diags := state.AutoRemdiationOptions.As(ctx, &currentStateOptions, basetypes.ObjectAsOptions{})
		if diags.HasError() {
			// If we can't extract, just continue without preserving
			hasV2FeaturesInState = false
		} else {
			// Check if state has v2 features
			hasUpdatePrecommit := !currentStateOptions.UpdatePrecommitFile.IsNull() && len(currentStateOptions.UpdatePrecommitFile.Elements()) > 0
			hasPackageEcosystem := !currentStateOptions.PackageEcosystem.IsNull() && len(currentStateOptions.PackageEcosystem.Elements()) > 0
			hasAddWorkflows := !currentStateOptions.AddWorkflows.IsNull() && currentStateOptions.AddWorkflows.ValueString() != ""
			hasUpdateExistingConfig := !currentStateOptions.UpdateExistingConfiguration.IsNull() && currentStateOptions.UpdateExistingConfiguration.ValueBool()
			hasHardenRunnerConfig := !currentStateOptions.HardenRunnerConfig.IsNull()
			hasCustomPrecommitConfig := !currentStateOptions.CustomPrecommitConfig.IsNull()
			hasV2FeaturesInState = hasUpdatePrecommit || hasPackageEcosystem || hasAddWorkflows || hasUpdateExistingConfig || hasHardenRunnerConfig || hasCustomPrecommitConfig
		}
	}

	// Check if v2 is enabled
	checkRepo := "[all]"
	if len(stateSelectedRepos) > 0 && stateSelectedRepos[0] != "*" {
		checkRepo = stateSelectedRepos[0]
	}

	var v2Enabled bool
	if hasV2FeaturesInState {
		status, err := r.client.GetSubscriptionStatus(ctx, state.Owner.ValueString(), checkRepo)
		if err != nil {
			tflog.Warn(ctx, "Failed to check subscription status during read, assuming v2 disabled", map[string]interface{}{
				"error": err.Error(),
			})
			v2Enabled = false
		} else if status != nil {
			v2Enabled = status.AppFeatureFlags.IsPolicyDrivenPrV2Enabled
		}
	}

	// Preserve features from state if API returns empty but state has values (avoid unnecessary diffs)
	// This handles both v1 features that might not be supported and v2 features when v2 is disabled
	if hasV2FeaturesInState && !v2Enabled {
		// Preserve v2 features from current state
		stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile = []string{}
		if !currentStateOptions.UpdatePrecommitFile.IsNull() {
			elements := currentStateOptions.UpdatePrecommitFile.Elements()
			for _, elem := range elements {
				stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile = append(
					stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile,
					elem.(types.String).ValueString(),
				)
			}
		}

		stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem = []stepsecurityapi.DependabotConfig{}
		if !currentStateOptions.PackageEcosystem.IsNull() {
			var ecosystemModels []packageEcosystemModel
			currentStateOptions.PackageEcosystem.ElementsAs(ctx, &ecosystemModels, false)
			for _, model := range ecosystemModels {
				stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem = append(
					stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem,
					stepsecurityapi.DependabotConfig{
						Package:      model.Package.ValueString(),
						Interval:     model.Interval.ValueString(),
						CoolDownYAML: model.CoolDownYAML.ValueString(),
						GroupsYAML:   model.GroupsYAML.ValueString(),
						OptionsYAML:  model.OptionsYAML.ValueString(),
					},
				)
			}
		}

		if !currentStateOptions.AddWorkflows.IsNull() {
			stepSecurityPolicy.AutoRemdiationOptions.AddWorkflows = currentStateOptions.AddWorkflows.ValueString()
		}

		if !currentStateOptions.HardenRunnerConfig.IsNull() {
			var hrcModel hardenRunnerConfigModel
			currentStateOptions.HardenRunnerConfig.As(ctx, &hrcModel, basetypes.ObjectAsOptions{})
			var runnerLabels []string
			if !hrcModel.RunnerLabels.IsNull() {
				for _, elem := range hrcModel.RunnerLabels.Elements() {
					runnerLabels = append(runnerLabels, elem.(types.String).ValueString())
				}
			}
			var exemptRunnerLabels []string
			if !hrcModel.ExemptRunnerLabels.IsNull() {
				for _, elem := range hrcModel.ExemptRunnerLabels.Elements() {
					exemptRunnerLabels = append(exemptRunnerLabels, elem.(types.String).ValueString())
				}
			}
			stepSecurityPolicy.AutoRemdiationOptions.HardenRunnerConfig = &stepsecurityapi.HardenRunnerConfig{
				Config:             hrcModel.Config.ValueString(),
				Subtractive:        hrcModel.UpdateExistingConfiguration.ValueBool(),
				SkipHardenRunner:   len(runnerLabels) > 0,
				RunnerLabels:       runnerLabels,
				ExemptRunnerLabels: exemptRunnerLabels,
			}
		}

		if !currentStateOptions.CustomPrecommitConfig.IsNull() {
			var cpcModel customPrecommitConfigModel
			currentStateOptions.CustomPrecommitConfig.As(ctx, &cpcModel, basetypes.ObjectAsOptions{})
			stepSecurityPolicy.AutoRemdiationOptions.CustomPrecommitConfig = &stepsecurityapi.CustomPrecommitConfig{
				Config:                      cpcModel.Config.ValueString(),
				UpdateExistingConfiguration: cpcModel.UpdateExistingConfiguration.ValueBool(),
			}
		}

		if !currentStateOptions.UpdateExistingConfiguration.IsNull() {
			v := currentStateOptions.UpdateExistingConfiguration.ValueBool()
			stepSecurityPolicy.AutoRemdiationOptions.Subtractive = &v
		}

		tflog.Info(ctx, "Preserving v2 features in state as v2 is not enabled")
	}

	// Also preserve v1 features if API returns empty arrays but state has values
	if len(stepSecurityPolicy.AutoRemdiationOptions.ActionsToExemptWhilePinning) == 0 &&
		!currentStateOptions.ActionsToExemptWhilePinning.IsNull() &&
		len(currentStateOptions.ActionsToExemptWhilePinning.Elements()) > 0 {
		elements := currentStateOptions.ActionsToExemptWhilePinning.Elements()
		for _, elem := range elements {
			stepSecurityPolicy.AutoRemdiationOptions.ActionsToExemptWhilePinning = append(
				stepSecurityPolicy.AutoRemdiationOptions.ActionsToExemptWhilePinning,
				elem.(types.String).ValueString(),
			)
		}
		tflog.Info(ctx, "Preserving actions_to_exempt_while_pinning from state")
	}

	if len(stepSecurityPolicy.AutoRemdiationOptions.ImagesToExemptWhilePinning) == 0 &&
		!currentStateOptions.ImagesToExemptWhilePinning.IsNull() &&
		len(currentStateOptions.ImagesToExemptWhilePinning.Elements()) > 0 {
		elements := currentStateOptions.ImagesToExemptWhilePinning.Elements()
		for _, elem := range elements {
			stepSecurityPolicy.AutoRemdiationOptions.ImagesToExemptWhilePinning = append(
				stepSecurityPolicy.AutoRemdiationOptions.ImagesToExemptWhilePinning,
				elem.(types.String).ValueString(),
			)
		}
		tflog.Info(ctx, "Preserving images_to_exempt_while_pinning from state")
	}

	if len(stepSecurityPolicy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions) == 0 &&
		!currentStateOptions.ActionsToReplaceWithStepSecurityActions.IsNull() &&
		len(currentStateOptions.ActionsToReplaceWithStepSecurityActions.Elements()) > 0 {
		elements := currentStateOptions.ActionsToReplaceWithStepSecurityActions.Elements()
		for _, elem := range elements {
			stepSecurityPolicy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions = append(
				stepSecurityPolicy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions,
				elem.(types.String).ValueString(),
			)
		}
		tflog.Info(ctx, "Preserving actions_to_replace_with_step_security_actions from state")
	}

	if !currentStateOptions.ActionCommitMap.IsNull() {
		stepSecurityPolicy.AutoRemdiationOptions.ActionCommitMap = make(map[string]string)
		for key, value := range currentStateOptions.ActionCommitMap.Elements() {
			stepSecurityPolicy.AutoRemdiationOptions.ActionCommitMap[key] = value.(types.String).ValueString()
		}
		tflog.Info(ctx, "Preserving action_commit_map from state")
	} else if len(stepSecurityPolicy.AutoRemdiationOptions.ActionCommitMap) == 0 {
		stepSecurityPolicy.AutoRemdiationOptions.ActionCommitMap = map[string]string{}
	}

	// Preserve update_existing_configuration from state: the API may not correctly
	// persist or return this field, so we always trust the state value to prevent drift.
	if !currentStateOptions.UpdateExistingConfiguration.IsNull() {
		v := currentStateOptions.UpdateExistingConfiguration.ValueBool()
		stepSecurityPolicy.AutoRemdiationOptions.Subtractive = &v
	}

	// Update state with API response, preserving selected_repos and excluded_repos from state
	// The API returns cooldown and groups parsed, not as the YAML in state. Keep the
	// YAML from state when it parses to the same value, so a refresh does not turn
	// formatting into a diff.
	var priorEcosystems []packageEcosystemModel
	if !currentStateOptions.PackageEcosystem.IsNull() && !currentStateOptions.PackageEcosystem.IsUnknown() {
		currentStateOptions.PackageEcosystem.ElementsAs(ctx, &priorEcosystems, false)
	}
	stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem = recoverDependabotYAML(stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem, priorEcosystems)

	r.updatePolicyDrivenPRState(ctx, *stepSecurityPolicy, &state, stateSelectedRepos, stateExcludedRepos)

	// Preserve ordering of list attributes from current state to prevent spurious diffs
	// when the API returns the same elements in a different order.
	r.preserveAutoRemediationListOrder(ctx, currentStateOptions, &state)

	// Set state to fully populated data
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *policyDrivenPRResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan policyDrivenPRModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state policyDrivenPRModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert state and plan repos to string slices for comparison
	var stateRepos []string
	if !state.SelectedRepos.IsNull() {
		elements := state.SelectedRepos.Elements()
		stateRepos = make([]string, len(elements))
		for i, elem := range elements {
			stateRepos[i] = elem.(types.String).ValueString()
		}
	}

	var selectedReposFilterForAllRepos stepsecurityapi.ApplyIssuePRConfigForAllReposFilter
	if !plan.SelectedReposFilter.IsNull() {
		var selectedReposFilter selectedReposFilterModel
		diags := plan.SelectedReposFilter.As(ctx, &selectedReposFilter, basetypes.ObjectAsOptions{})
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		var reposTopics []string
		if !selectedReposFilter.IncludeReposOnlyWithTopics.IsNull() && !selectedReposFilter.IncludeReposOnlyWithTopics.IsUnknown() {
			elements := selectedReposFilter.IncludeReposOnlyWithTopics.Elements()
			reposTopics = make([]string, len(elements))
			for i, elem := range elements {
				reposTopics[i] = elem.(types.String).ValueString()
			}
		}
		selectedReposFilterForAllRepos.ReposTopics = reposTopics
	}

	var stateExcludedRepos []string
	if !state.ExcludedRepos.IsNull() {
		elements := state.ExcludedRepos.Elements()
		stateExcludedRepos = make([]string, len(elements))
		for i, elem := range elements {
			stateExcludedRepos[i] = elem.(types.String).ValueString()
		}
	}

	var planRepos []string
	if !plan.SelectedRepos.IsNull() {
		elements := plan.SelectedRepos.Elements()
		planRepos = make([]string, len(elements))
		for i, elem := range elements {
			planRepos[i] = elem.(types.String).ValueString()
		}
	}

	var planExcludedRepos []string
	if !plan.ExcludedRepos.IsNull() {
		elements := plan.ExcludedRepos.Elements()
		planExcludedRepos = make([]string, len(elements))
		for i, elem := range elements {
			planExcludedRepos[i] = elem.(types.String).ValueString()
		}
	}

	// Determine repos to be removed
	var removedRepos []string

	// If switching from org-level to repo-level, need to delete org config
	stateIsOrgLevel := len(stateRepos) == 1 && stateRepos[0] == "*"
	planIsOrgLevel := len(planRepos) == 1 && planRepos[0] == "*"

	if stateIsOrgLevel && !planIsOrgLevel {
		// Switching from org-level to repo-level
		removedRepos = append(removedRepos, "*")
	} else if !stateIsOrgLevel && !planIsOrgLevel {
		// Both repo-level, check for removed repos
		for _, repo := range stateRepos {
			if !slices.Contains(planRepos, repo) {
				removedRepos = append(removedRepos, repo)
			}
		}
	}

	// Handle repos that were excluded in state but not in plan (need to add them back)
	for _, repo := range stateExcludedRepos {
		if !slices.Contains(planExcludedRepos, repo) {
			// Repo was excluded before but not anymore, will be added by create call
		}
	}

	// Extract auto_remediation_options from plan
	var planOptions autoRemdiationOptionsModel
	diags = plan.AutoRemdiationOptions.As(ctx, &planOptions, basetypes.ObjectAsOptions{})
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var actionsToExempt []string
	if !planOptions.ActionsToExemptWhilePinning.IsNull() {
		elements := planOptions.ActionsToExemptWhilePinning.Elements()
		actionsToExempt = make([]string, len(elements))
		for i, elem := range elements {
			actionsToExempt[i] = elem.(types.String).ValueString()
		}
	}

	var imagesToExempt []string
	if !planOptions.ImagesToExemptWhilePinning.IsNull() {
		elements := planOptions.ImagesToExemptWhilePinning.Elements()
		imagesToExempt = make([]string, len(elements))
		for i, elem := range elements {
			imagesToExempt[i] = elem.(types.String).ValueString()
		}
	}

	var actionsToReplace []string
	if !planOptions.ActionsToReplaceWithStepSecurityActions.IsNull() {
		elements := planOptions.ActionsToReplaceWithStepSecurityActions.Elements()
		actionsToReplace = make([]string, len(elements))
		for i, elem := range elements {
			actionsToReplace[i] = elem.(types.String).ValueString()
		}
	}

	var exemptedFromReplacementUpdate []string
	if !planOptions.ExemptedFromReplacement.IsNull() {
		elements := planOptions.ExemptedFromReplacement.Elements()
		exemptedFromReplacementUpdate = make([]string, len(elements))
		for i, elem := range elements {
			exemptedFromReplacementUpdate[i] = elem.(types.String).ValueString()
		}
	}

	// Empty rather than nil when removed from the config: the API only replaces
	// the stored patterns when the key is present, so a nil here would leave the
	// old patterns stored and every later refresh would read them back as drift.
	dockerfilePatternsUpdate := []string{}
	if !planOptions.DockerfilePatterns.IsNull() {
		for _, elem := range planOptions.DockerfilePatterns.Elements() {
			dockerfilePatternsUpdate = append(dockerfilePatternsUpdate, elem.(types.String).ValueString())
		}
	}

	// Extract new optional fields for update
	var packageEcosystemPlan []stepsecurityapi.DependabotConfig
	if !planOptions.PackageEcosystem.IsNull() {
		var ecosystemModels []packageEcosystemModel
		diags := planOptions.PackageEcosystem.ElementsAs(ctx, &ecosystemModels, false)
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			for _, model := range ecosystemModels {
				packageEcosystemPlan = append(packageEcosystemPlan, stepsecurityapi.DependabotConfig{
					Package:      model.Package.ValueString(),
					Interval:     model.Interval.ValueString(),
					CoolDownYAML: model.CoolDownYAML.ValueString(),
					GroupsYAML:   model.GroupsYAML.ValueString(),
					OptionsYAML:  model.OptionsYAML.ValueString(),
				})
			}
		}
	}

	var updatePrecommitFilePlan []string
	if !planOptions.UpdatePrecommitFile.IsNull() {
		elements := planOptions.UpdatePrecommitFile.Elements()
		updatePrecommitFilePlan = make([]string, len(elements))
		for i, elem := range elements {
			updatePrecommitFilePlan[i] = elem.(types.String).ValueString()
		}
	}

	var actionCommitMapPlan map[string]string
	if !planOptions.ActionCommitMap.IsNull() {
		actionCommitMapPlan = make(map[string]string)
		for key, value := range planOptions.ActionCommitMap.Elements() {
			actionCommitMapPlan[key] = value.(types.String).ValueString()
		}
	} else if len(planOptions.ActionCommitMap.Elements()) == 0 {
		actionCommitMapPlan = map[string]string{}
	}

	var customActionsToReplacePlan map[string]string
	if !planOptions.CustomActionsToReplace.IsNull() && !planOptions.CustomActionsToReplace.IsUnknown() {
		customActionsToReplacePlan = make(map[string]string)
		for key, value := range planOptions.CustomActionsToReplace.Elements() {
			customActionsToReplacePlan[key] = value.(types.String).ValueString()
		}
	}

	var labelsToReplacePlan map[string]string
	if !planOptions.LabelsToReplace.IsNull() {
		labelsToReplacePlan = make(map[string]string)
		for key, value := range planOptions.LabelsToReplace.Elements() {
			labelsToReplacePlan[key] = value.(types.String).ValueString()
		}
	} else {
		labelsToReplacePlan = map[string]string{}
	}

	// Automatically compute config levels based on planRepos
	// If planRepos = ["*"], use org-level config
	// Otherwise, use repo-level config
	planHasWildcard := len(planRepos) == 1 && planRepos[0] == "*"
	useOrgLevel := planHasWildcard
	useRepoLevel := !planHasWildcard

	var subtractiveUpdate *bool
	if !planOptions.UpdateExistingConfiguration.IsNull() && !planOptions.UpdateExistingConfiguration.IsUnknown() {
		v := planOptions.UpdateExistingConfiguration.ValueBool()
		subtractiveUpdate = &v
	}

	var replaceByMajorTagUpdate *bool
	if !planOptions.ReplaceByMajorTag.IsNull() && !planOptions.ReplaceByMajorTag.IsUnknown() {
		v := planOptions.ReplaceByMajorTag.ValueBool()
		replaceByMajorTagUpdate = &v
	}
	var hardenRunnerConfigUpdate *stepsecurityapi.HardenRunnerConfig
	if !planOptions.HardenRunnerConfig.IsNull() && !planOptions.HardenRunnerConfig.IsUnknown() {
		var hrcModel hardenRunnerConfigModel
		planOptions.HardenRunnerConfig.As(ctx, &hrcModel, basetypes.ObjectAsOptions{})
		var runnerLabels []string
		if !hrcModel.RunnerLabels.IsNull() {
			for _, elem := range hrcModel.RunnerLabels.Elements() {
				runnerLabels = append(runnerLabels, elem.(types.String).ValueString())
			}
		}
		var exemptRunnerLabels []string
		if !hrcModel.ExemptRunnerLabels.IsNull() {
			for _, elem := range hrcModel.ExemptRunnerLabels.Elements() {
				exemptRunnerLabels = append(exemptRunnerLabels, elem.(types.String).ValueString())
			}
		}
		hardenRunnerConfigUpdate = &stepsecurityapi.HardenRunnerConfig{
			Config:             hrcModel.Config.ValueString(),
			Subtractive:        hrcModel.UpdateExistingConfiguration.ValueBool(),
			SkipHardenRunner:   len(runnerLabels) > 0,
			RunnerLabels:       runnerLabels,
			ExemptRunnerLabels: exemptRunnerLabels,
		}
	}

	var customPrecommitConfigUpdate *stepsecurityapi.CustomPrecommitConfig
	if !planOptions.CustomPrecommitConfig.IsNull() && !planOptions.CustomPrecommitConfig.IsUnknown() {
		var cpcModel customPrecommitConfigModel
		planOptions.CustomPrecommitConfig.As(ctx, &cpcModel, basetypes.ObjectAsOptions{})
		customPrecommitConfigUpdate = &stepsecurityapi.CustomPrecommitConfig{
			Config:                      cpcModel.Config.ValueString(),
			UpdateExistingConfiguration: cpcModel.UpdateExistingConfiguration.ValueBool(),
		}
	}

	policy := stepsecurityapi.PolicyDrivenPRPolicy{
		Owner: plan.Owner.ValueString(),
		AutoRemdiationOptions: stepsecurityapi.AutoRemdiationOptions{
			CreatePR:                                planOptions.CreatePR.ValueBool(),
			CreateIssue:                             planOptions.CreateIssue.ValueBool(),
			CreateGitHubAdvancedSecurityAlert:       planOptions.CreateGitHubAdvancedSecurityAlert.ValueBool(),
			PinActionsToSHA:                         planOptions.PinActionsToSHA.ValueBool(),
			HardenGitHubHostedRunner:                planOptions.HardenGitHubHostedRunner.ValueBool(),
			RestrictGitHubTokenPermissions:          planOptions.RestrictGitHubTokenPermissions.ValueBool(),
			SecureDockerFile:                        planOptions.SecureDockerFile.ValueBool(),
			LabelsToReplace:                         labelsToReplacePlan,
			ActionsToExemptWhilePinning:             actionsToExempt,
			ImagesToExemptWhilePinning:              imagesToExempt,
			ActionsToReplaceWithStepSecurityActions: actionsToReplace,
			CustomActionsToReplace:                  customActionsToReplacePlan,
			ReplaceByMajorTag:                       replaceByMajorTagUpdate,
			ExemptedFromReplacement:                 exemptedFromReplacementUpdate,
			UpdatePrecommitFile:                     updatePrecommitFilePlan,
			PackageEcosystem:                        packageEcosystemPlan,
			DockerfilePatterns:                      dockerfilePatternsUpdate,
			Subtractive:                             subtractiveUpdate,
			AddWorkflows:                            planOptions.AddWorkflows.ValueString(),
			ActionCommitMap:                         actionCommitMapPlan,
			HardenRunnerConfig:                      hardenRunnerConfigUpdate,
			CustomPrecommitConfig:                   customPrecommitConfigUpdate,
		},
		SelectedRepos:       planRepos,
		SelectedReposFilter: selectedReposFilterForAllRepos,
		UseRepoLevelConfig:  useRepoLevel,
		UseOrgLevelConfig:   useOrgLevel,
	}

	// Handle excluded repos: Save their current configs before updating org-level config
	var excludedRepoConfigs map[string]*stepsecurityapi.PolicyDrivenPRPolicy
	if len(planRepos) == 1 && planRepos[0] == "*" && len(planExcludedRepos) > 0 {
		excludedRepoConfigs = make(map[string]*stepsecurityapi.PolicyDrivenPRPolicy)
		for _, repo := range planExcludedRepos {
			// Read current config for this excluded repo
			currentConfig, err := r.client.GetPolicyDrivenPRPolicy(ctx, plan.Owner.ValueString(), []string{repo})
			if err != nil {
				tflog.Warn(ctx, "Failed to get current config for excluded repo", map[string]interface{}{
					"repo":  repo,
					"error": err.Error(),
				})
				continue
			}
			// Store the config if it exists and has settings
			if currentConfig != nil {
				excludedRepoConfigs[repo] = currentConfig
			}
		}
	}

	// Update policy-driven PR in StepSecurity
	err := r.client.UpdatePolicyDrivenPRPolicy(ctx, policy, removedRepos)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Update Policy-Driven PR",
			err.Error(),
		)
		return
	}

	// Restore original configs for excluded repos to prevent them from inheriting org-level config
	if len(excludedRepoConfigs) > 0 {
		for repo, originalConfig := range excludedRepoConfigs {
			// Restore the original config for this repo
			originalConfig.SelectedRepos = []string{repo}
			err = r.client.CreatePolicyDrivenPRPolicy(ctx, *originalConfig)
			if err != nil {
				resp.Diagnostics.AddError(
					"Unable to Restore Config for Excluded Repo",
					fmt.Sprintf("Failed to restore config for repo %s: %s", repo, err.Error()),
				)
				return
			}
			tflog.Info(ctx, "Restored original config for excluded repo", map[string]interface{}{
				"repo": repo,
			})
		}
	}

	// Handle newly excluded repos that had no previous config - delete them to prevent inheritance
	for _, repo := range planExcludedRepos {
		if !slices.Contains(stateExcludedRepos, repo) {
			// Check if this repo had a config that we restored
			if _, restored := excludedRepoConfigs[repo]; !restored {
				// New exclusion with no previous config - delete it
				err = r.client.DeletePolicyDrivenPRPolicy(ctx, plan.Owner.ValueString(), []string{repo})
				if err != nil {
					resp.Diagnostics.AddError(
						"Unable to Exclude Repo from Policy-Driven PR",
						fmt.Sprintf("Failed to exclude repo %s: %s", repo, err.Error()),
					)
					return
				}
			}
		}
	}

	// Set the ID (use owner as the unique identifier)
	plan.ID = types.StringValue(plan.Owner.ValueString())

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *policyDrivenPRResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyDrivenPRModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert state repos to string slice
	var stateRepos []string
	if !state.SelectedRepos.IsNull() {
		elements := state.SelectedRepos.Elements()
		stateRepos = make([]string, len(elements))
		for i, elem := range elements {
			stateRepos[i] = elem.(types.String).ValueString()
		}
	}

	// Delete policy-driven PR from StepSecurity
	err := r.client.DeletePolicyDrivenPRPolicy(ctx, state.Owner.ValueString(), stateRepos)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Delete Policy-Driven PR",
			err.Error(),
		)
		return
	}
}

func (r *policyDrivenPRResource) updatePolicyDrivenPRState(ctx context.Context, stepSecurityPolicy stepsecurityapi.PolicyDrivenPRPolicy, state *policyDrivenPRModel, stateSelectedRepos []string, stateExcludedRepos []string) {
	// Update basic fields
	state.ID = types.StringValue(stepSecurityPolicy.Owner)
	state.Owner = types.StringValue(stepSecurityPolicy.Owner)

	// Create auto_remediation_options object
	exemptElements := make([]types.String, len(stepSecurityPolicy.AutoRemdiationOptions.ActionsToExemptWhilePinning))
	for i, action := range stepSecurityPolicy.AutoRemdiationOptions.ActionsToExemptWhilePinning {
		exemptElements[i] = types.StringValue(action)
	}
	exemptList, _ := types.ListValueFrom(ctx, types.StringType, exemptElements)

	exemptImagesElements := make([]types.String, len(stepSecurityPolicy.AutoRemdiationOptions.ImagesToExemptWhilePinning))
	for i, image := range stepSecurityPolicy.AutoRemdiationOptions.ImagesToExemptWhilePinning {
		exemptImagesElements[i] = types.StringValue(image)
	}
	exemptImagesList, _ := types.ListValueFrom(ctx, types.StringType, exemptImagesElements)

	replaceElements := make([]types.String, len(stepSecurityPolicy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions))
	for i, action := range stepSecurityPolicy.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions {
		replaceElements[i] = types.StringValue(action)
	}
	replaceList, _ := types.ListValueFrom(ctx, types.StringType, replaceElements)

	exemptedFromReplacementElements := make([]types.String, len(stepSecurityPolicy.AutoRemdiationOptions.ExemptedFromReplacement))
	for i, action := range stepSecurityPolicy.AutoRemdiationOptions.ExemptedFromReplacement {
		exemptedFromReplacementElements[i] = types.StringValue(action)
	}
	exemptedFromReplacementList, _ := types.ListValueFrom(ctx, types.StringType, exemptedFromReplacementElements)

	// Null rather than an empty set when unset: dockerfile_patterns is Optional
	// and not Computed, so returning [] for a config that omits it would read as
	// a permanent diff.
	dockerfilePatternsSet := types.SetNull(types.StringType)
	if len(stepSecurityPolicy.AutoRemdiationOptions.DockerfilePatterns) > 0 {
		elements := make([]types.String, len(stepSecurityPolicy.AutoRemdiationOptions.DockerfilePatterns))
		for i, pattern := range stepSecurityPolicy.AutoRemdiationOptions.DockerfilePatterns {
			elements[i] = types.StringValue(pattern)
		}
		dockerfilePatternsSet, _ = types.SetValueFrom(ctx, types.StringType, elements)
	}

	// Handle new optional fields
	var packageEcosystemList types.List
	if len(stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem) > 0 {
		var ecosystemObjects []attr.Value
		for _, ecosystem := range stepSecurityPolicy.AutoRemdiationOptions.PackageEcosystem {
			obj, _ := types.ObjectValue(
				map[string]attr.Type{
					"package":       types.StringType,
					"interval":      types.StringType,
					"cooldown_yaml": types.StringType,
					"groups_yaml":   types.StringType,
					"options_yaml":  types.StringType,
				},
				map[string]attr.Value{
					"package":       types.StringValue(ecosystem.Package),
					"interval":      types.StringValue(ecosystem.Interval),
					"cooldown_yaml": stringOrNull(ecosystem.CoolDownYAML),
					"groups_yaml":   stringOrNull(ecosystem.GroupsYAML),
					"options_yaml":  stringOrNull(ecosystem.OptionsYAML),
				},
			)
			ecosystemObjects = append(ecosystemObjects, obj)
		}
		packageEcosystemList, _ = types.ListValue(
			types.ObjectType{
				AttrTypes: map[string]attr.Type{
					"package":       types.StringType,
					"interval":      types.StringType,
					"cooldown_yaml": types.StringType,
					"groups_yaml":   types.StringType,
					"options_yaml":  types.StringType,
				},
			},
			ecosystemObjects,
		)
	} else {
		packageEcosystemList = types.ListNull(types.ObjectType{
			AttrTypes: map[string]attr.Type{
				"package":       types.StringType,
				"interval":      types.StringType,
				"cooldown_yaml": types.StringType,
				"groups_yaml":   types.StringType,
				"options_yaml":  types.StringType,
			},
		})
	}

	var updatePrecommitFileList types.List
	if len(stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile) > 0 {
		fileElements := make([]types.String, len(stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile))
		for i, file := range stepSecurityPolicy.AutoRemdiationOptions.UpdatePrecommitFile {
			fileElements[i] = types.StringValue(file)
		}
		updatePrecommitFileList, _ = types.ListValueFrom(ctx, types.StringType, fileElements)
	} else {
		// Return empty list instead of null to match schema default
		updatePrecommitFileList = types.ListValueMust(types.StringType, []attr.Value{})
	}

	var addWorkflowsValue types.String
	if stepSecurityPolicy.AutoRemdiationOptions.AddWorkflows != "" {
		addWorkflowsValue = types.StringValue(stepSecurityPolicy.AutoRemdiationOptions.AddWorkflows)
	} else {
		addWorkflowsValue = types.StringNull()
	}

	var actionCommitMapValue types.Map
	if len(stepSecurityPolicy.AutoRemdiationOptions.ActionCommitMap) > 0 {
		mapElements := make(map[string]attr.Value)
		for key, value := range stepSecurityPolicy.AutoRemdiationOptions.ActionCommitMap {
			mapElements[key] = types.StringValue(value)
		}
		actionCommitMapValue, _ = types.MapValue(types.StringType, mapElements)
	} else {
		actionCommitMapValue = types.MapNull(types.StringType)
	}

	var customActionsToReplaceValue types.Map
	if len(stepSecurityPolicy.AutoRemdiationOptions.CustomActionsToReplace) > 0 {
		mapElements := make(map[string]attr.Value)
		for key, value := range stepSecurityPolicy.AutoRemdiationOptions.CustomActionsToReplace {
			mapElements[key] = types.StringValue(value)
		}
		customActionsToReplaceValue, _ = types.MapValue(types.StringType, mapElements)
	} else {
		customActionsToReplaceValue = types.MapNull(types.StringType)
	}

	var labelsToReplaceValue types.Map
	if len(stepSecurityPolicy.AutoRemdiationOptions.LabelsToReplace) > 0 {
		mapElements := make(map[string]attr.Value)
		for key, value := range stepSecurityPolicy.AutoRemdiationOptions.LabelsToReplace {
			mapElements[key] = types.StringValue(value)
		}
		labelsToReplaceValue, _ = types.MapValue(types.StringType, mapElements)
	} else {
		labelsToReplaceValue = types.MapNull(types.StringType)
	}

	optionsObj, _ := types.ObjectValue(
		map[string]attr.Type{
			"create_pr":                                     types.BoolType,
			"create_issue":                                  types.BoolType,
			"create_github_advanced_security_alert":         types.BoolType,
			"harden_github_hosted_runner":                   types.BoolType,
			"pin_actions_to_sha":                            types.BoolType,
			"restrict_github_token_permissions":             types.BoolType,
			"secure_docker_file":                            types.BoolType,
			"labels_to_replace":                             types.MapType{ElemType: types.StringType},
			"actions_to_exempt_while_pinning":               types.ListType{ElemType: types.StringType},
			"images_to_exempt_while_pinning":                types.ListType{ElemType: types.StringType},
			"actions_to_replace_with_step_security_actions": types.ListType{ElemType: types.StringType},
			"custom_actions_to_replace":                     types.MapType{ElemType: types.StringType},
			"replace_action_on_major_tag_match":             types.BoolType,
			"actions_exempted_from_replacement":             types.ListType{ElemType: types.StringType},
			"update_precommit_file":                         types.ListType{ElemType: types.StringType},
			"custom_precommit_config": types.ObjectType{AttrTypes: map[string]attr.Type{
				"config":                        types.StringType,
				"update_existing_configuration": types.BoolType,
			}},
			"package_ecosystem": types.ListType{
				ElemType: types.ObjectType{
					AttrTypes: map[string]attr.Type{
						"package":       types.StringType,
						"interval":      types.StringType,
						"cooldown_yaml": types.StringType,
						"groups_yaml":   types.StringType,
						"options_yaml":  types.StringType,
					},
				},
			},
			"dockerfile_patterns":           types.SetType{ElemType: types.StringType},
			"update_existing_configuration": types.BoolType,
			"add_workflows":                 types.StringType,
			"action_commit_map":             types.MapType{ElemType: types.StringType},
			"harden_runner_config": types.ObjectType{AttrTypes: map[string]attr.Type{
				"config":                        types.StringType,
				"update_existing_configuration": types.BoolType,
				"target_runner_labels":          types.ListType{ElemType: types.StringType},
				"exempt_runner_labels":          types.SetType{ElemType: types.StringType},
			}},
		},
		map[string]attr.Value{
			"create_pr":                                     types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.CreatePR),
			"create_issue":                                  types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.CreateIssue),
			"create_github_advanced_security_alert":         types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.CreateGitHubAdvancedSecurityAlert),
			"harden_github_hosted_runner":                   types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.HardenGitHubHostedRunner),
			"pin_actions_to_sha":                            types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.PinActionsToSHA),
			"restrict_github_token_permissions":             types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.RestrictGitHubTokenPermissions),
			"secure_docker_file":                            types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.SecureDockerFile),
			"labels_to_replace":                             labelsToReplaceValue,
			"actions_to_exempt_while_pinning":               exemptList,
			"images_to_exempt_while_pinning":                exemptImagesList,
			"actions_to_replace_with_step_security_actions": replaceList,
			"custom_actions_to_replace":                     customActionsToReplaceValue,
			"replace_action_on_major_tag_match": types.BoolValue(func() bool {
				if stepSecurityPolicy.AutoRemdiationOptions.ReplaceByMajorTag != nil {
					return *stepSecurityPolicy.AutoRemdiationOptions.ReplaceByMajorTag
				}
				return false
			}()),
			"update_precommit_file":             updatePrecommitFileList,
			"package_ecosystem":                 packageEcosystemList,
			"dockerfile_patterns":               dockerfilePatternsSet,
			"actions_exempted_from_replacement": exemptedFromReplacementList,
			"update_existing_configuration": types.BoolValue(func() bool {
				if stepSecurityPolicy.AutoRemdiationOptions.Subtractive != nil {
					return *stepSecurityPolicy.AutoRemdiationOptions.Subtractive
				}
				return false
			}()),
			"add_workflows":     addWorkflowsValue,
			"action_commit_map": actionCommitMapValue,
			"custom_precommit_config": func() attr.Value {
				cpcAttrTypes := map[string]attr.Type{
					"config":                        types.StringType,
					"update_existing_configuration": types.BoolType,
				}
				if stepSecurityPolicy.AutoRemdiationOptions.CustomPrecommitConfig != nil {
					obj, _ := types.ObjectValue(cpcAttrTypes, map[string]attr.Value{
						"config":                        types.StringValue(stepSecurityPolicy.AutoRemdiationOptions.CustomPrecommitConfig.Config),
						"update_existing_configuration": types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.CustomPrecommitConfig.UpdateExistingConfiguration),
					})
					return obj
				}
				return types.ObjectNull(cpcAttrTypes)
			}(),
			"harden_runner_config": func() attr.Value {
				if stepSecurityPolicy.AutoRemdiationOptions.HardenRunnerConfig != nil {
					hrLabels := stepSecurityPolicy.AutoRemdiationOptions.HardenRunnerConfig.RunnerLabels
					labelElems := make([]attr.Value, len(hrLabels))
					for i, l := range hrLabels {
						labelElems[i] = types.StringValue(l)
					}
					labelsList, _ := types.ListValue(types.StringType, labelElems)
					exemptLabels := stepSecurityPolicy.AutoRemdiationOptions.HardenRunnerConfig.ExemptRunnerLabels
					exemptLabelElems := make([]attr.Value, len(exemptLabels))
					for i, l := range exemptLabels {
						exemptLabelElems[i] = types.StringValue(l)
					}
					exemptLabelsSet, _ := types.SetValue(types.StringType, exemptLabelElems)
					obj, _ := types.ObjectValue(
						map[string]attr.Type{
							"config":                        types.StringType,
							"update_existing_configuration": types.BoolType,
							"target_runner_labels":          types.ListType{ElemType: types.StringType},
							"exempt_runner_labels":          types.SetType{ElemType: types.StringType},
						},
						map[string]attr.Value{
							"config":                        stringOrNull(stepSecurityPolicy.AutoRemdiationOptions.HardenRunnerConfig.Config),
							"update_existing_configuration": types.BoolValue(stepSecurityPolicy.AutoRemdiationOptions.HardenRunnerConfig.Subtractive),
							"target_runner_labels":          labelsList,
							"exempt_runner_labels":          exemptLabelsSet,
						},
					)
					return obj
				}
				return types.ObjectNull(map[string]attr.Type{
					"config":                        types.StringType,
					"update_existing_configuration": types.BoolType,
					"target_runner_labels":          types.ListType{ElemType: types.StringType},
					"exempt_runner_labels":          types.SetType{ElemType: types.StringType},
				})
			}(),
		},
	)
	state.AutoRemdiationOptions = optionsObj

	// Note: We do NOT set UseRepoLevelConfig and UseOrgLevelConfig here.
	// These fields represent the user's intent and should be preserved from the existing state.
	// When org-level config is applied to specific repos (not wildcard), the API stores it per-repo,
	// making it impossible to distinguish from repo-level config when reading back.
	// Therefore, we trust the state to maintain the user's original configuration intent.

	// Preserve selected_repos and excluded_repos from state to avoid diffs
	// This ensures that the order and exact values match what the user configured
	if len(stateSelectedRepos) > 0 {
		repoElements := make([]types.String, len(stateSelectedRepos))
		for i, repo := range stateSelectedRepos {
			repoElements[i] = types.StringValue(repo)
		}
		repoList, _ := types.ListValueFrom(ctx, types.StringType, repoElements)
		state.SelectedRepos = repoList
	}

	if len(stateExcludedRepos) > 0 {
		excludedElements := make([]types.String, len(stateExcludedRepos))
		for i, repo := range stateExcludedRepos {
			excludedElements[i] = types.StringValue(repo)
		}
		excludedList, _ := types.ListValueFrom(ctx, types.StringType, excludedElements)
		state.ExcludedRepos = excludedList
	}
}

// stringOrNull maps an absent API string to null rather than to the empty string.
//
// cooldown_yaml, groups_yaml and harden_runner_config.config are Optional with no
// default, so a configuration that omits them holds null. All three are omitempty on the
// wire, so the API returns them absent and Go decodes that to "". Writing types.StringValue("")
// into state therefore disagrees with the plan on every refresh. Terraform counts that as
// a change but renders empty-string-vs-null as unchanged, producing a plan that reports
// "1 to change" with no attribute diff shown at all.
func stringOrNull(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// listToStrings extracts a []string from a types.List of strings, skipping any
// element that is not a known string value.
func listToStrings(list types.List) []string {
	out := make([]string, 0, len(list.Elements()))
	for _, e := range list.Elements() {
		s, ok := e.(types.String)
		if !ok || s.IsNull() || s.IsUnknown() {
			continue
		}
		out = append(out, s.ValueString())
	}
	return out
}

// alignListOrder reorders apiList to follow stateList's ordering for the elements the
// two have in common, appending any element that only the API returned in the order the
// API returned it.
//
// The API stores some of these lists as JSON objects, which unmarshal into Go maps, so
// the read path has to derive a list from a randomized map range. Sorting that list (see
// GetPolicyDrivenPRPolicy) makes each read self-consistent but does not match the order
// the practitioner wrote in their configuration, so a config that is not already sorted
// gets a permanent reordering diff. Realigning to the prior state's order removes that
// diff while still surfacing genuine membership changes: an element the API dropped
// disappears and an element the API added shows up at the end.
//
// Returns ok=false when apiList is already in the desired order, so callers can avoid
// rebuilding the enclosing object for no reason.
func alignListOrder(ctx context.Context, stateList, apiList types.List) (types.List, bool) {
	if stateList.IsNull() || stateList.IsUnknown() || apiList.IsNull() || apiList.IsUnknown() {
		return apiList, false
	}

	stateElems := listToStrings(stateList)
	apiElems := listToStrings(apiList)
	if len(apiElems) == 0 {
		return apiList, false
	}

	// Track occurrences rather than mere presence so duplicated elements survive.
	remaining := make(map[string]int, len(apiElems))
	for _, e := range apiElems {
		remaining[e]++
	}

	aligned := make([]string, 0, len(apiElems))
	for _, e := range stateElems {
		if remaining[e] > 0 {
			remaining[e]--
			aligned = append(aligned, e)
		}
	}
	for _, e := range apiElems {
		if remaining[e] > 0 {
			remaining[e]--
			aligned = append(aligned, e)
		}
	}

	if slices.Equal(aligned, apiElems) {
		return apiList, false
	}

	alignedList, diags := types.ListValueFrom(ctx, types.StringType, aligned)
	if diags.HasError() {
		return apiList, false
	}
	return alignedList, true
}

// preserveAutoRemediationListOrder prevents spurious diffs caused by the API returning
// the elements of a list attribute in an order that differs from the configured order.
func (r *policyDrivenPRResource) preserveAutoRemediationListOrder(ctx context.Context, currentStateOptions autoRemdiationOptionsModel, state *policyDrivenPRModel) {
	if state.AutoRemdiationOptions.IsNull() || state.AutoRemdiationOptions.IsUnknown() {
		return
	}

	attrs := state.AutoRemdiationOptions.Attributes()
	changed := false

	// preserveOrder rewrites attrs[key] so it follows stateList's ordering.
	preserveOrder := func(key string, stateList types.List) {
		apiList, ok := attrs[key].(types.List)
		if !ok {
			return
		}
		aligned, ok := alignListOrder(ctx, stateList, apiList)
		if !ok {
			return
		}
		attrs[key] = aligned
		changed = true
	}

	preserveOrder("actions_to_replace_with_step_security_actions", currentStateOptions.ActionsToReplaceWithStepSecurityActions)
	preserveOrder("actions_to_exempt_while_pinning", currentStateOptions.ActionsToExemptWhilePinning)
	preserveOrder("images_to_exempt_while_pinning", currentStateOptions.ImagesToExemptWhilePinning)
	preserveOrder("actions_exempted_from_replacement", currentStateOptions.ExemptedFromReplacement)
	preserveOrder("update_precommit_file", currentStateOptions.UpdatePrecommitFile)

	if r.preserveHardenRunnerLabelOrder(ctx, currentStateOptions, attrs) {
		changed = true
	}

	if !changed {
		return
	}

	// Derive attrTypes from the existing object rather than hardcoding, so this
	// remains correct when new fields are added to auto_remediation_options.
	objType, ok := state.AutoRemdiationOptions.Type(ctx).(basetypes.ObjectType)
	if !ok {
		return
	}
	updatedObj, diags := types.ObjectValue(objType.AttrTypes, attrs)
	if diags.HasError() {
		return
	}
	state.AutoRemdiationOptions = updatedObj
}

// preserveHardenRunnerLabelOrder applies the same ordering fix to
// harden_runner_config.target_runner_labels, which lives one level down in a nested
// object. It mutates attrs in place and reports whether it changed anything.
func (r *policyDrivenPRResource) preserveHardenRunnerLabelOrder(ctx context.Context, currentStateOptions autoRemdiationOptionsModel, attrs map[string]attr.Value) bool {
	stateConfig := currentStateOptions.HardenRunnerConfig
	if stateConfig.IsNull() || stateConfig.IsUnknown() {
		return false
	}
	var stateModel hardenRunnerConfigModel
	if diags := stateConfig.As(ctx, &stateModel, basetypes.ObjectAsOptions{}); diags.HasError() {
		return false
	}

	apiConfig, ok := attrs["harden_runner_config"].(types.Object)
	if !ok || apiConfig.IsNull() || apiConfig.IsUnknown() {
		return false
	}
	configAttrs := apiConfig.Attributes()
	apiLabels, ok := configAttrs["target_runner_labels"].(types.List)
	if !ok {
		return false
	}

	aligned, ok := alignListOrder(ctx, stateModel.RunnerLabels, apiLabels)
	if !ok {
		return false
	}
	configAttrs["target_runner_labels"] = aligned

	objType, ok := apiConfig.Type(ctx).(basetypes.ObjectType)
	if !ok {
		return false
	}
	updatedConfig, diags := types.ObjectValue(objType.AttrTypes, configAttrs)
	if diags.HasError() {
		return false
	}
	attrs["harden_runner_config"] = updatedConfig
	return true
}
