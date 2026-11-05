package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGithubRunPoliciesDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Read testing
			{
				Config: testAccGithubRunPoliciesDataSourceConfig("test-org"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.stepsecurity_github_run_policies.test", "owner", "test-org"),
					resource.TestCheckResourceAttrSet("data.stepsecurity_github_run_policies.test", "run_policies.#"),
				),
			},
		},
	})
}

func TestGithubRunPoliciesDataSource_ReadMappingWithPinnedActions(t *testing.T) {
	dataSource := &githubRunPoliciesDataSource{}
	assert.NotNil(t, dataSource)

	policy := stepsecurityapi.RunPolicy{
		Owner:         "test-org",
		Customer:      "test-customer",
		PolicyID:      "policy-123",
		Name:          "Test Policy",
		CreatedBy:     "user1",
		CreatedAt:     time.Now(),
		LastUpdatedBy: "user1",
		LastUpdatedAt: time.Now(),
		AllRepos:      true,
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                   "test-org",
			Name:                    "Test Policy",
			EnableActionPolicy:      true,
			RequirePinnedActions:    true,
			PinnedActionsExemptions: []string{"actions/*"},
		},
	}

	policyConfigAttrs := map[string]attr.Value{
		"owner":                             types.StringValue(policy.PolicyConfig.Owner),
		"name":                              types.StringValue(policy.PolicyConfig.Name),
		"enable_action_policy":              types.BoolValue(policy.PolicyConfig.EnableActionPolicy),
		"allowed_actions":                   types.MapNull(types.StringType),
		"enable_harden_runner_policy":       types.BoolValue(policy.PolicyConfig.EnableHardenRunnerPolicy),
		"harden_runner_target_labels":       types.SetNull(types.StringType),
		"harden_runner_excluded_labels":     types.SetNull(types.StringType),
		"harden_runner_custom_actions":      types.SetNull(types.StringType),
		"enable_runs_on_policy":             types.BoolValue(policy.PolicyConfig.EnableRunsOnPolicy),
		"enable_standard_runner_labels":     types.BoolValue(policy.PolicyConfig.EnableStandardRunnerLabels),
		"disallowed_runner_labels":          types.SetNull(types.StringType),
		"enable_secrets_policy":             types.BoolValue(policy.PolicyConfig.EnableSecretsPolicy),
		"enable_compromised_actions_policy": types.BoolValue(policy.PolicyConfig.EnableCompromisedActionsPolicy),
		"require_pinned_actions":            types.BoolValue(policy.PolicyConfig.RequirePinnedActions),
		"is_dry_run":                        types.BoolValue(policy.PolicyConfig.IsDryRun),
		"bulk_secrets_only_mode":            types.BoolValue(policy.PolicyConfig.BulkSecretsOnlyMode),
		"pr_comment_template":               types.StringValue(policy.PolicyConfig.PrCommentTemplate),
		"runs_on_mode":                      types.StringValue(policy.PolicyConfig.RunsOnMode),
		"allowed_runner_labels":             types.SetNull(types.StringType),
		"allowed_runner_constraints":        types.MapNull(types.SetType{ElemType: types.StringType}),
		"require_policy_store":              types.BoolValue(policy.PolicyConfig.RequirePolicyStore),
		"block_job_container":               types.BoolValue(policy.PolicyConfig.BlockJobContainer),
		"secrets_analyze_default_branch":    types.BoolValue(policy.PolicyConfig.SecretsAnalyzeDefaultBranch),
		"enforce_method":                    types.StringValue(policy.PolicyConfig.EnforceMethod),
		"prejob_allowed_runner_labels":      types.SetNull(types.StringType),
		"prejob_disallowed_runner_labels":   types.SetNull(types.StringType),
		"runner_label_requirements":         types.ListNull(runnerLabelRequirementObjectType),
	}

	pinnedExemptionsList := make([]attr.Value, len(policy.PolicyConfig.PinnedActionsExemptions))
	for i, exemption := range policy.PolicyConfig.PinnedActionsExemptions {
		pinnedExemptionsList[i] = types.StringValue(exemption)
	}
	pinnedSet, diags := types.SetValue(types.StringType, pinnedExemptionsList)
	assert.False(t, diags.HasError())
	policyConfigAttrs["actions_to_exempt_while_pinning"] = pinnedSet

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

	policyConfigObj, objDiags := types.ObjectValue(policyConfigAttrTypes, policyConfigAttrs)
	assert.False(t, objDiags.HasError(), "ObjectValue should not produce errors with synced type maps")
	assert.False(t, policyConfigObj.IsNull())
}

func TestGithubRunPoliciesDataSource_Read(t *testing.T) {
	dataSource := &githubRunPoliciesDataSource{}

	// Verify that the data source is properly instantiated
	assert.NotNil(t, dataSource)
	assert.Nil(t, dataSource.client)
}

func TestGithubRunPoliciesDataSource_EmptyResult(t *testing.T) {
	dataSource := &githubRunPoliciesDataSource{}

	// Test initialization with empty client
	assert.NotNil(t, dataSource)
	assert.Nil(t, dataSource.client)
}

func TestGithubRunPoliciesDataSource_ErrorHandling(t *testing.T) {
	dataSource := &githubRunPoliciesDataSource{}

	// Test that we can configure the data source
	assert.NotNil(t, dataSource)

	// Set a mock client and verify it
	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	dataSource.client = mockClient
	assert.NotNil(t, dataSource.client)
}

func TestGithubRunPoliciesDataSource_ReadMapsHardenRunnerFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	labels := []string{"ubuntu-step-security", "linux-secure"}
	customActions := []string{"my-org/harden-runner", "octo/harden-runner-action"}
	now := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.
		On("ListRunPolicies", mock.Anything, "test-org").
		Return([]stepsecurityapi.RunPolicy{
			{
				Owner:         "test-org",
				Customer:      "test-customer",
				PolicyID:      "policy-123",
				Name:          "Test Policy",
				CreatedBy:     "test-user",
				CreatedAt:     now,
				LastUpdatedBy: "test-user",
				LastUpdatedAt: now,
				AllRepos:      true,
				AllOrgs:       false,
				PolicyConfig: stepsecurityapi.RunPolicyConfig{
					Owner:                     "test-org",
					Name:                      "Test Policy",
					EnableHardenRunnerPolicy:  true,
					HardenRunnerTargetLabels:  labels,
					HardenRunnerCustomActions: customActions,
				},
			},
		}, nil).
		Once()

	d := &githubRunPoliciesDataSource{client: mockClient}
	req := fwdatasource.ReadRequest{
		Config: testGithubRunPoliciesDataSourceConfigValue(t, githubRunPoliciesDataSourceModel{
			Owner:       types.StringValue("test-org"),
			RunPolicies: types.ListNull(types.ObjectType{AttrTypes: testRunPolicyDataSourceAttrTypes()}),
		}),
	}
	resp := &fwdatasource.ReadResponse{
		State: tfsdk.State{Schema: testGithubRunPoliciesDataSourceSchema(t)},
	}

	d.Read(ctx, req, resp)

	require.False(t, resp.Diagnostics.HasError())
	mockClient.AssertExpectations(t)

	var state githubRunPoliciesDataSourceModel
	diags := resp.State.Get(ctx, &state)
	require.False(t, diags.HasError())

	var runPolicies []githubRunPolicyDataSourceEntryModel
	diags = state.RunPolicies.ElementsAs(ctx, &runPolicies, false)
	require.False(t, diags.HasError())
	require.Len(t, runPolicies, 1)

	var policyConfig githubRunPolicyDataSourcePolicyConfigModel
	diags = runPolicies[0].PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError())

	assert.True(t, policyConfig.EnableHardenRunnerPolicy.ValueBool())
	assert.ElementsMatch(t, labels, setStrings(t, policyConfig.HardenRunnerTargetLabels))
	assert.ElementsMatch(t, customActions, setStrings(t, policyConfig.HardenRunnerCustomActions))
}

func TestGithubRunPoliciesDataSource_ReadEmptyLabelsSurfaceAsEmptySet(t *testing.T) {
	t.Parallel()

	// Backend omits empty `harden_runner_labels` from the JSON response
	// (omitempty). When the Harden Runner policy is enabled, the data source
	// must still surface the "match all jobs" contract as an empty set rather
	// than collapsing it to null, so downstream consumers (outputs, for-loops)
	// can rely on the documented shape.
	ctx := context.Background()
	now := time.Date(2024, 6, 7, 8, 9, 10, 0, time.UTC)

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.
		On("ListRunPolicies", mock.Anything, "test-org").
		Return([]stepsecurityapi.RunPolicy{
			{
				Owner:         "test-org",
				PolicyID:      "policy-allmatch",
				Name:          "All Jobs Policy",
				CreatedBy:     "test-user",
				CreatedAt:     now,
				LastUpdatedBy: "test-user",
				LastUpdatedAt: now,
				AllRepos:      true,
				PolicyConfig: stepsecurityapi.RunPolicyConfig{
					Owner:                     "test-org",
					Name:                      "All Jobs Policy",
					EnableHardenRunnerPolicy:  true,
					HardenRunnerTargetLabels:  nil,
					HardenRunnerCustomActions: nil,
				},
			},
			{
				Owner:         "test-org",
				PolicyID:      "policy-disabled",
				Name:          "Other Policy",
				CreatedBy:     "test-user",
				CreatedAt:     now,
				LastUpdatedBy: "test-user",
				LastUpdatedAt: now,
				AllRepos:      true,
				PolicyConfig: stepsecurityapi.RunPolicyConfig{
					Owner:                    "test-org",
					Name:                     "Other Policy",
					EnableHardenRunnerPolicy: false,
				},
			},
		}, nil).
		Once()

	d := &githubRunPoliciesDataSource{client: mockClient}
	req := fwdatasource.ReadRequest{
		Config: testGithubRunPoliciesDataSourceConfigValue(t, githubRunPoliciesDataSourceModel{
			Owner:       types.StringValue("test-org"),
			RunPolicies: types.ListNull(types.ObjectType{AttrTypes: testRunPolicyDataSourceAttrTypes()}),
		}),
	}
	resp := &fwdatasource.ReadResponse{
		State: tfsdk.State{Schema: testGithubRunPoliciesDataSourceSchema(t)},
	}

	d.Read(ctx, req, resp)

	require.False(t, resp.Diagnostics.HasError())
	mockClient.AssertExpectations(t)

	var state githubRunPoliciesDataSourceModel
	diags := resp.State.Get(ctx, &state)
	require.False(t, diags.HasError())

	var runPolicies []githubRunPolicyDataSourceEntryModel
	diags = state.RunPolicies.ElementsAs(ctx, &runPolicies, false)
	require.False(t, diags.HasError())
	require.Len(t, runPolicies, 2)

	// Enabled + empty: expect empty set, not null.
	var enabled githubRunPolicyDataSourcePolicyConfigModel
	diags = runPolicies[0].PolicyConfig.As(ctx, &enabled, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError())
	assert.True(t, enabled.EnableHardenRunnerPolicy.ValueBool())
	assert.False(t, enabled.HardenRunnerTargetLabels.IsNull(), "enabled+empty must surface as empty set, not null")
	assert.False(t, enabled.HardenRunnerCustomActions.IsNull())
	assert.Empty(t, setStrings(t, enabled.HardenRunnerTargetLabels))
	assert.Empty(t, setStrings(t, enabled.HardenRunnerCustomActions))

	// Disabled: null is the correct shape (attribute doesn't apply).
	var disabled githubRunPolicyDataSourcePolicyConfigModel
	diags = runPolicies[1].PolicyConfig.As(ctx, &disabled, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError())
	assert.False(t, disabled.EnableHardenRunnerPolicy.ValueBool())
	assert.True(t, disabled.HardenRunnerTargetLabels.IsNull())
	assert.True(t, disabled.HardenRunnerCustomActions.IsNull())
}

type githubRunPolicyDataSourceEntryModel struct {
	Owner               types.String `tfsdk:"owner"`
	Customer            types.String `tfsdk:"customer"`
	PolicyID            types.String `tfsdk:"policy_id"`
	Name                types.String `tfsdk:"name"`
	CreatedBy           types.String `tfsdk:"created_by"`
	CreatedAt           types.String `tfsdk:"created_at"`
	LastUpdatedBy       types.String `tfsdk:"last_updated_by"`
	LastUpdatedAt       types.String `tfsdk:"last_updated_at"`
	AllRepos            types.Bool   `tfsdk:"all_repos"`
	AllOrgs             types.Bool   `tfsdk:"all_orgs"`
	Repositories        types.List   `tfsdk:"repositories"`
	RepoPropertyFilters types.List   `tfsdk:"repo_property_filters"`
	PolicyConfig        types.Object `tfsdk:"policy_config"`
}

type githubRunPolicyDataSourcePolicyConfigModel struct {
	Owner                          types.String `tfsdk:"owner"`
	Name                           types.String `tfsdk:"name"`
	EnableActionPolicy             types.Bool   `tfsdk:"enable_action_policy"`
	AllowedActions                 types.Map    `tfsdk:"allowed_actions"`
	EnableHardenRunnerPolicy       types.Bool   `tfsdk:"enable_harden_runner_policy"`
	HardenRunnerTargetLabels       types.Set    `tfsdk:"harden_runner_target_labels"`
	HardenRunnerExcludedLabels     types.Set    `tfsdk:"harden_runner_excluded_labels"`
	HardenRunnerCustomActions      types.Set    `tfsdk:"harden_runner_custom_actions"`
	EnableRunsOnPolicy             types.Bool   `tfsdk:"enable_runs_on_policy"`
	EnableStandardRunnerLabels     types.Bool   `tfsdk:"enable_standard_runner_labels"`
	DisallowedRunnerLabels         types.Set    `tfsdk:"disallowed_runner_labels"`
	EnableSecretsPolicy            types.Bool   `tfsdk:"enable_secrets_policy"`
	EnableCompromisedActionsPolicy types.Bool   `tfsdk:"enable_compromised_actions_policy"`
	RequirePinnedActions           types.Bool   `tfsdk:"require_pinned_actions"`
	PinnedActionsExemptions        types.Set    `tfsdk:"actions_to_exempt_while_pinning"`
	IsDryRun                       types.Bool   `tfsdk:"is_dry_run"`
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

func testGithubRunPoliciesDataSourceSchema(t *testing.T) datasourceschema.Schema {
	t.Helper()

	d := &githubRunPoliciesDataSource{}
	resp := &fwdatasource.SchemaResponse{}
	d.Schema(context.Background(), fwdatasource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError())

	return resp.Schema
}

func testGithubRunPoliciesDataSourceConfigValue(t *testing.T, model githubRunPoliciesDataSourceModel) tfsdk.Config {
	t.Helper()

	state := tfsdk.State{Schema: testGithubRunPoliciesDataSourceSchema(t)}
	diags := state.Set(context.Background(), model)
	require.False(t, diags.HasError())

	return tfsdk.Config{
		Raw:    state.Raw,
		Schema: testGithubRunPoliciesDataSourceSchema(t),
	}
}

func testRunPolicyDataSourceAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
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
}

func testAccGithubRunPoliciesDataSourceConfig(owner string) string {
	return fmt.Sprintf(`
data "stepsecurity_github_run_policies" "test" {
  owner = %[1]q
}
`, owner)
}
