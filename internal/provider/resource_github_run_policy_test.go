package provider

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	resourcehelper "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func TestAccGithubRunPolicyResource(t *testing.T) {
	resourcehelper.Test(t, resourcehelper.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resourcehelper.TestStep{
			// Create and Read testing
			{
				Config: testAccGithubRunPolicyResourceConfig("test-org", "Test Policy"),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "owner", "test-org"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "name", "Test Policy"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "all_repos", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_action_policy", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_harden_runner_policy", "true"),
					resourcehelper.TestCheckTypeSetElemAttr("stepsecurity_github_run_policy.test", "policy_config.harden_runner_target_labels.*", "ubuntu-step-security"),
					resourcehelper.TestCheckTypeSetElemAttr("stepsecurity_github_run_policy.test", "policy_config.harden_runner_custom_actions.*", "my-org/harden-runner"),
					resourcehelper.TestCheckResourceAttrSet("stepsecurity_github_run_policy.test", "policy_id"),
					resourcehelper.TestCheckResourceAttrSet("stepsecurity_github_run_policy.test", "id"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "stepsecurity_github_run_policy.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Update and Read testing
			{
				Config: testAccGithubRunPolicyResourceConfigUpdated("test-org", "Updated Test Policy"),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "name", "Updated Test Policy"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_secrets_policy", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_harden_runner_policy", "true"),
					resourcehelper.TestCheckTypeSetElemAttr("stepsecurity_github_run_policy.test", "policy_config.harden_runner_target_labels.*", "ubuntu-step-security"),
					resourcehelper.TestCheckTypeSetElemAttr("stepsecurity_github_run_policy.test", "policy_config.harden_runner_custom_actions.*", "my-org/harden-runner"),
				),
			},
			{
				Config: testAccGithubRunPolicyResourceConfigWithPinning("test-org", "Allowed Actions Policy - Pinned Actions Enforcement"),
				Check: resourcehelper.ComposeAggregateTestCheckFunc(
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "name", "Allowed Actions Policy - Pinned Actions Enforcement"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.enable_action_policy", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.require_pinned_actions", "true"),
					resourcehelper.TestCheckResourceAttr("stepsecurity_github_run_policy.test", "policy_config.actions_to_exempt_while_pinning.#", "1"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestGithubRunPolicyResource_Create(t *testing.T) {
	resource := &githubRunPolicyResource{}

	// Verify resource is properly initialized
	assert.NotNil(t, resource)
	assert.Nil(t, resource.client)

	// Test that we can set a client
	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	resource.client = mockClient
	assert.NotNil(t, resource.client)
}

func TestGithubRunPolicyResource_UpdateModelFromAPI(t *testing.T) {
	resource := &githubRunPolicyResource{}

	ctx := context.Background()
	model := &githubRunPolicyResourceModel{}
	hardenRunnerTargetLabels := []string{"ubuntu-step-security", "linux-secure"}
	hardenRunnerCustomActions := []string{"my-org/harden-runner", "octo/harden-runner-action"}

	apiResponse := &stepsecurityapi.RunPolicy{
		Owner:         "test-org",
		Customer:      "test-customer",
		PolicyID:      "test-policy-123",
		Name:          "Test Policy",
		CreatedBy:     "test-user",
		CreatedAt:     time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		LastUpdatedBy: "test-user",
		LastUpdatedAt: time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
		AllRepos:      true,
		AllOrgs:       false,
		Repositories:  []string{"repo1", "repo2"},
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                    "test-org",
			Name:                     "Test Policy",
			EnableActionPolicy:       true,
			EnableHardenRunnerPolicy: true,
			AllowedActions: map[string]string{
				"actions/checkout": "allow",
			},
			EnableRunsOnPolicy: true,
			DisallowedRunnerLabels: map[string]struct{}{
				"self-hosted": {},
			},
			RequirePinnedActions:      true,
			PinnedActionsExemptions:   []string{"actions/*", "my-org/*"},
			HardenRunnerTargetLabels:  hardenRunnerTargetLabels,
			HardenRunnerCustomActions: hardenRunnerCustomActions,
		},
	}

	var diags diag.Diagnostics
	resource.updateModelFromAPI(ctx, model, apiResponse, &diags)

	assert.Equal(t, "test-org", model.Owner.ValueString())
	assert.Equal(t, "test-policy-123", model.PolicyID.ValueString())
	assert.Equal(t, "Test Policy", model.Name.ValueString())
	assert.True(t, model.AllRepos.ValueBool())
	assert.False(t, model.AllOrgs.ValueBool())

	var policyConfig policyConfigModel
	diags = model.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError())
	assert.True(t, policyConfig.EnableHardenRunnerPolicy.ValueBool())
	assert.ElementsMatch(t, []string{"ubuntu-step-security", "linux-secure"}, setStrings(t, policyConfig.HardenRunnerTargetLabels))
	assert.ElementsMatch(t, []string{"my-org/harden-runner", "octo/harden-runner-action"}, setStrings(t, policyConfig.HardenRunnerCustomActions))
	assert.True(t, policyConfig.RequirePinnedActions.ValueBool())
	assert.False(t, policyConfig.PinnedActionsExemptions.IsNull())
	assert.ElementsMatch(t, []string{"actions/*", "my-org/*"}, setStrings(t, policyConfig.PinnedActionsExemptions))
}

func TestGithubRunPolicyResource_UpdateModelFromAPI_NilPinnedExemptions(t *testing.T) {
	resource := &githubRunPolicyResource{}

	ctx := context.Background()
	model := &githubRunPolicyResourceModel{}

	apiResponse := &stepsecurityapi.RunPolicy{
		Owner:         "test-org",
		Customer:      "test-customer",
		PolicyID:      "test-policy-456",
		Name:          "No Pinning Policy",
		CreatedBy:     "test-user",
		CreatedAt:     time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		LastUpdatedBy: "test-user",
		LastUpdatedAt: time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC),
		AllRepos:      true,
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                "test-org",
			Name:                 "No Pinning Policy",
			EnableActionPolicy:   true,
			RequirePinnedActions: false,
		},
	}

	var diags diag.Diagnostics
	resource.updateModelFromAPI(ctx, model, apiResponse, &diags)

	assert.False(t, diags.HasError())

	var policyConfig policyConfigModel
	policyConfigDiags := model.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	assert.False(t, policyConfigDiags.HasError())
	assert.False(t, policyConfig.RequirePinnedActions.ValueBool())
	assert.True(t, policyConfig.PinnedActionsExemptions.IsNull())
}

func TestGithubRunPolicyResource_PinnedActionsRequestSerialization(t *testing.T) {
	ctx := context.Background()

	pinnedExemptions, diags := types.SetValueFrom(ctx, types.StringType, []string{"actions/*", "my-org/*"})
	assert.False(t, diags.HasError())

	policyConfig := policyConfigModel{
		Owner:                          types.StringValue("test-org"),
		Name:                           types.StringValue("Test Policy"),
		EnableActionPolicy:             types.BoolValue(true),
		AllowedActions:                 types.MapNull(types.StringType),
		EnableHardenRunnerPolicy:       types.BoolValue(false),
		HardenRunnerTargetLabels:       types.SetNull(types.StringType),
		HardenRunnerCustomActions:      types.SetNull(types.StringType),
		EnableRunsOnPolicy:             types.BoolValue(false),
		DisallowedRunnerLabels:         types.SetNull(types.StringType),
		EnableSecretsPolicy:            types.BoolValue(false),
		EnableCompromisedActionsPolicy: types.BoolValue(false),
		RequirePinnedActions:           types.BoolValue(true),
		PinnedActionsExemptions:        pinnedExemptions,
		IsDryRun:                       types.BoolValue(false),
		ExemptedUsers:                  types.SetNull(types.StringType),
	}

	createRequest := stepsecurityapi.CreateRunPolicyRequest{
		Name:     "Test Policy",
		AllRepos: true,
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                          policyConfig.Owner.ValueString(),
			Name:                           policyConfig.Name.ValueString(),
			EnableActionPolicy:             policyConfig.EnableActionPolicy.ValueBool(),
			EnableRunsOnPolicy:             policyConfig.EnableRunsOnPolicy.ValueBool(),
			EnableSecretsPolicy:            policyConfig.EnableSecretsPolicy.ValueBool(),
			EnableCompromisedActionsPolicy: policyConfig.EnableCompromisedActionsPolicy.ValueBool(),
			RequirePinnedActions:           policyConfig.RequirePinnedActions.ValueBool(),
			IsDryRun:                       policyConfig.IsDryRun.ValueBool(),
		},
	}

	if !policyConfig.PinnedActionsExemptions.IsNull() {
		var exemptions []string
		exemptionDiags := policyConfig.PinnedActionsExemptions.ElementsAs(ctx, &exemptions, false)
		assert.False(t, exemptionDiags.HasError())
		createRequest.PolicyConfig.PinnedActionsExemptions = exemptions
	}

	assert.True(t, createRequest.PolicyConfig.RequirePinnedActions)
	assert.ElementsMatch(t, []string{"actions/*", "my-org/*"}, createRequest.PolicyConfig.PinnedActionsExemptions)

	updateRequest := stepsecurityapi.UpdateRunPolicyRequest{
		Name:     "Test Policy",
		AllRepos: true,
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                          policyConfig.Owner.ValueString(),
			Name:                           policyConfig.Name.ValueString(),
			EnableActionPolicy:             policyConfig.EnableActionPolicy.ValueBool(),
			EnableRunsOnPolicy:             policyConfig.EnableRunsOnPolicy.ValueBool(),
			EnableSecretsPolicy:            policyConfig.EnableSecretsPolicy.ValueBool(),
			EnableCompromisedActionsPolicy: policyConfig.EnableCompromisedActionsPolicy.ValueBool(),
			RequirePinnedActions:           policyConfig.RequirePinnedActions.ValueBool(),
			IsDryRun:                       policyConfig.IsDryRun.ValueBool(),
		},
	}

	if !policyConfig.PinnedActionsExemptions.IsNull() {
		var exemptions []string
		exemptionDiags := policyConfig.PinnedActionsExemptions.ElementsAs(ctx, &exemptions, false)
		assert.False(t, exemptionDiags.HasError())
		updateRequest.PolicyConfig.PinnedActionsExemptions = exemptions
	}

	assert.True(t, updateRequest.PolicyConfig.RequirePinnedActions)
	assert.ElementsMatch(t, []string{"actions/*", "my-org/*"}, updateRequest.PolicyConfig.PinnedActionsExemptions)
}

func TestGithubRunPolicyResource_PinnedActionsRequestSerialization_NullExemptions(t *testing.T) {
	policyConfig := policyConfigModel{
		Owner:                          types.StringValue("test-org"),
		Name:                           types.StringValue("Test Policy"),
		EnableActionPolicy:             types.BoolValue(true),
		AllowedActions:                 types.MapNull(types.StringType),
		EnableHardenRunnerPolicy:       types.BoolValue(false),
		HardenRunnerTargetLabels:       types.SetNull(types.StringType),
		HardenRunnerCustomActions:      types.SetNull(types.StringType),
		EnableRunsOnPolicy:             types.BoolValue(false),
		DisallowedRunnerLabels:         types.SetNull(types.StringType),
		EnableSecretsPolicy:            types.BoolValue(false),
		EnableCompromisedActionsPolicy: types.BoolValue(false),
		RequirePinnedActions:           types.BoolValue(true),
		PinnedActionsExemptions:        types.SetNull(types.StringType),
		IsDryRun:                       types.BoolValue(false),
		ExemptedUsers:                  types.SetNull(types.StringType),
	}

	createRequest := stepsecurityapi.CreateRunPolicyRequest{
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			RequirePinnedActions: policyConfig.RequirePinnedActions.ValueBool(),
		},
	}

	if !policyConfig.PinnedActionsExemptions.IsNull() {
		t.Fatal("expected PinnedActionsExemptions to be null")
	}

	assert.True(t, createRequest.PolicyConfig.RequirePinnedActions)
	assert.Nil(t, createRequest.PolicyConfig.PinnedActionsExemptions)
}

func TestGithubRunPolicyResource_UpdateSendsEmptyHardenRunnerSets(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	previousLabels := []string{"ubuntu-step-security"}
	previousActions := []string{"my-org/harden-runner"}
	now := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)

	state := githubRunPolicyResourceModel{
		Owner:        types.StringValue("test-org"),
		Name:         types.StringValue("Test Policy"),
		PolicyID:     types.StringValue("policy-123"),
		AllRepos:     types.BoolValue(true),
		AllOrgs:      types.BoolValue(false),
		Repositories: types.ListNull(types.StringType),
		PolicyConfig: testRunPolicyConfigObjectValue(policyConfigModel{
			Owner:                          types.StringValue("test-org"),
			Name:                           types.StringValue("Test Policy"),
			EnableActionPolicy:             types.BoolValue(false),
			AllowedActions:                 types.MapNull(types.StringType),
			EnableHardenRunnerPolicy:       types.BoolValue(true),
			HardenRunnerTargetLabels:       types.SetValueMust(types.StringType, testStringAttrValues(previousLabels)),
			HardenRunnerCustomActions:      types.SetValueMust(types.StringType, testStringAttrValues(previousActions)),
			EnableRunsOnPolicy:             types.BoolValue(false),
			DisallowedRunnerLabels:         types.SetNull(types.StringType),
			EnableSecretsPolicy:            types.BoolValue(false),
			EnableCompromisedActionsPolicy: types.BoolValue(false),
			IsDryRun:                       types.BoolValue(false),
			ExemptedUsers:                  types.SetNull(types.StringType),
		}),
		CreatedBy:     types.StringValue("test-user"),
		CreatedAt:     types.StringValue(now.Format(time.RFC3339)),
		LastUpdatedBy: types.StringValue("test-user"),
		LastUpdatedAt: types.StringValue(now.Format(time.RFC3339)),
	}

	plan := githubRunPolicyResourceModel{
		Owner:        types.StringValue("test-org"),
		Name:         types.StringValue("Updated Policy"),
		PolicyID:     types.StringValue("policy-123"),
		AllRepos:     types.BoolValue(true),
		AllOrgs:      types.BoolValue(false),
		Repositories: types.ListNull(types.StringType),
		PolicyConfig: testRunPolicyConfigObjectValue(policyConfigModel{
			Owner:                          types.StringValue("test-org"),
			Name:                           types.StringValue("Updated Policy"),
			EnableActionPolicy:             types.BoolValue(false),
			AllowedActions:                 types.MapNull(types.StringType),
			EnableHardenRunnerPolicy:       types.BoolValue(true),
			HardenRunnerTargetLabels:       types.SetValueMust(types.StringType, []attr.Value{}),
			HardenRunnerCustomActions:      types.SetValueMust(types.StringType, []attr.Value{}),
			EnableRunsOnPolicy:             types.BoolValue(false),
			DisallowedRunnerLabels:         types.SetNull(types.StringType),
			EnableSecretsPolicy:            types.BoolValue(false),
			EnableCompromisedActionsPolicy: types.BoolValue(false),
			IsDryRun:                       types.BoolValue(false),
			ExemptedUsers:                  types.SetNull(types.StringType),
		}),
		CreatedBy:     types.StringNull(),
		CreatedAt:     types.StringNull(),
		LastUpdatedBy: types.StringNull(),
		LastUpdatedAt: types.StringNull(),
	}

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.
		On("UpdateRunPolicy", mock.Anything, "test-org", "policy-123", mock.MatchedBy(func(req stepsecurityapi.UpdateRunPolicyRequest) bool {
			if req.Name != "Updated Policy" || !req.PolicyConfig.EnableHardenRunnerPolicy {
				return false
			}
			if req.PolicyConfig.Owner != "test-org" || req.PolicyConfig.Name != "Updated Policy" {
				return false
			}
			return len(req.PolicyConfig.HardenRunnerTargetLabels) == 0 &&
				len(req.PolicyConfig.HardenRunnerCustomActions) == 0
		})).
		Return(&stepsecurityapi.RunPolicy{
			Owner:         "test-org",
			PolicyID:      "policy-123",
			Name:          "Updated Policy",
			CreatedBy:     "test-user",
			CreatedAt:     now,
			LastUpdatedBy: "reviewer",
			LastUpdatedAt: now,
			AllRepos:      true,
			AllOrgs:       false,
			PolicyConfig: stepsecurityapi.RunPolicyConfig{
				Owner:                    "test-org",
				Name:                     "Updated Policy",
				EnableHardenRunnerPolicy: true,
				// agent-api uses []string with `omitempty`, so cleared values can come back omitted (nil) or as empty slice — both mean "match all jobs" under PR 7814.
				HardenRunnerTargetLabels:  nil,
				HardenRunnerCustomActions: nil,
			},
		}, nil).
		Once()

	r := &githubRunPolicyResource{client: mockClient}
	req := fwresource.UpdateRequest{
		Config: testGithubRunPolicyConfig(t, plan),
		Plan:   testGithubRunPolicyPlan(t, plan),
		State:  testGithubRunPolicyState(t, state),
	}
	resp := &fwresource.UpdateResponse{
		State: tfsdk.State{Schema: testGithubRunPolicyResourceSchema(t)},
	}

	r.Update(ctx, req, resp)

	require.False(t, resp.Diagnostics.HasError())
	mockClient.AssertExpectations(t)

	var updatedState githubRunPolicyResourceModel
	diags := resp.State.Get(ctx, &updatedState)
	require.False(t, diags.HasError())

	var policyConfig policyConfigModel
	diags = updatedState.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError())

	assert.True(t, policyConfig.EnableHardenRunnerPolicy.ValueBool())
	assert.False(t, policyConfig.HardenRunnerTargetLabels.IsNull())
	assert.False(t, policyConfig.HardenRunnerCustomActions.IsNull())
	assert.Empty(t, setStrings(t, policyConfig.HardenRunnerTargetLabels))
	assert.Empty(t, setStrings(t, policyConfig.HardenRunnerCustomActions))
}

func TestGithubRunPolicyResource_UpdatePreservesUnmanagedHardenRunnerFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	previousLabels := []string{"ubuntu-step-security"}
	previousActions := []string{"my-org/harden-runner"}
	now := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)

	state := githubRunPolicyResourceModel{
		Owner:        types.StringValue("test-org"),
		Name:         types.StringValue("Test Policy"),
		PolicyID:     types.StringValue("policy-123"),
		AllRepos:     types.BoolValue(true),
		AllOrgs:      types.BoolValue(false),
		Repositories: types.ListNull(types.StringType),
		PolicyConfig: testRunPolicyConfigObjectValue(policyConfigModel{
			Owner:                          types.StringValue("test-org"),
			Name:                           types.StringValue("Test Policy"),
			EnableActionPolicy:             types.BoolValue(false),
			AllowedActions:                 types.MapNull(types.StringType),
			EnableHardenRunnerPolicy:       types.BoolValue(true),
			HardenRunnerTargetLabels:       types.SetValueMust(types.StringType, testStringAttrValues(previousLabels)),
			HardenRunnerCustomActions:      types.SetValueMust(types.StringType, testStringAttrValues(previousActions)),
			EnableRunsOnPolicy:             types.BoolValue(false),
			DisallowedRunnerLabels:         types.SetNull(types.StringType),
			EnableSecretsPolicy:            types.BoolValue(false),
			EnableCompromisedActionsPolicy: types.BoolValue(false),
			IsDryRun:                       types.BoolValue(false),
			ExemptedUsers:                  types.SetNull(types.StringType),
		}),
		CreatedBy:     types.StringValue("test-user"),
		CreatedAt:     types.StringValue(now.Format(time.RFC3339)),
		LastUpdatedBy: types.StringValue("test-user"),
		LastUpdatedAt: types.StringValue(now.Format(time.RFC3339)),
	}

	plan := githubRunPolicyResourceModel{
		Owner:        types.StringValue("test-org"),
		Name:         types.StringValue("Updated Policy"),
		PolicyID:     types.StringValue("policy-123"),
		AllRepos:     types.BoolValue(true),
		AllOrgs:      types.BoolValue(false),
		Repositories: types.ListNull(types.StringType),
		PolicyConfig: testRunPolicyConfigObjectValue(policyConfigModel{
			Owner:                          types.StringValue("test-org"),
			Name:                           types.StringValue("Updated Policy"),
			EnableActionPolicy:             types.BoolValue(false),
			AllowedActions:                 types.MapNull(types.StringType),
			EnableHardenRunnerPolicy:       types.BoolValue(false),
			HardenRunnerTargetLabels:       types.SetNull(types.StringType),
			HardenRunnerCustomActions:      types.SetNull(types.StringType),
			EnableRunsOnPolicy:             types.BoolValue(false),
			DisallowedRunnerLabels:         types.SetNull(types.StringType),
			EnableSecretsPolicy:            types.BoolValue(false),
			EnableCompromisedActionsPolicy: types.BoolValue(false),
			IsDryRun:                       types.BoolValue(false),
			ExemptedUsers:                  types.SetNull(types.StringType),
		}),
		CreatedBy:     types.StringNull(),
		CreatedAt:     types.StringNull(),
		LastUpdatedBy: types.StringNull(),
		LastUpdatedAt: types.StringNull(),
	}

	config := githubRunPolicyResourceModel{
		Owner:        types.StringValue("test-org"),
		Name:         types.StringValue("Updated Policy"),
		PolicyID:     types.StringNull(),
		AllRepos:     types.BoolValue(true),
		AllOrgs:      types.BoolNull(),
		Repositories: types.ListNull(types.StringType),
		PolicyConfig: testRunPolicyConfigObjectValue(policyConfigModel{
			Owner:                          types.StringValue("test-org"),
			Name:                           types.StringValue("Updated Policy"),
			EnableActionPolicy:             types.BoolNull(),
			AllowedActions:                 types.MapNull(types.StringType),
			EnableHardenRunnerPolicy:       types.BoolNull(),
			HardenRunnerTargetLabels:       types.SetNull(types.StringType),
			HardenRunnerCustomActions:      types.SetNull(types.StringType),
			EnableRunsOnPolicy:             types.BoolNull(),
			DisallowedRunnerLabels:         types.SetNull(types.StringType),
			EnableSecretsPolicy:            types.BoolNull(),
			EnableCompromisedActionsPolicy: types.BoolNull(),
			IsDryRun:                       types.BoolNull(),
			ExemptedUsers:                  types.SetNull(types.StringType),
		}),
		CreatedBy:     types.StringNull(),
		CreatedAt:     types.StringNull(),
		LastUpdatedBy: types.StringNull(),
		LastUpdatedAt: types.StringNull(),
	}

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.
		On("UpdateRunPolicy", mock.Anything, "test-org", "policy-123", mock.MatchedBy(func(req stepsecurityapi.UpdateRunPolicyRequest) bool {
			if req.Name != "Updated Policy" || !req.PolicyConfig.EnableHardenRunnerPolicy {
				return false
			}
			if req.PolicyConfig.Owner != "test-org" || req.PolicyConfig.Name != "Updated Policy" {
				return false
			}
			return reflect.DeepEqual(req.PolicyConfig.HardenRunnerTargetLabels, previousLabels) &&
				reflect.DeepEqual(req.PolicyConfig.HardenRunnerCustomActions, previousActions)
		})).
		Return(&stepsecurityapi.RunPolicy{
			Owner:         "test-org",
			PolicyID:      "policy-123",
			Name:          "Updated Policy",
			CreatedBy:     "test-user",
			CreatedAt:     now,
			LastUpdatedBy: "reviewer",
			LastUpdatedAt: now,
			AllRepos:      true,
			AllOrgs:       false,
			PolicyConfig: stepsecurityapi.RunPolicyConfig{
				Owner:                     "test-org",
				Name:                      "Updated Policy",
				EnableHardenRunnerPolicy:  true,
				HardenRunnerTargetLabels:  previousLabels,
				HardenRunnerCustomActions: previousActions,
			},
		}, nil).
		Once()

	r := &githubRunPolicyResource{client: mockClient}
	req := fwresource.UpdateRequest{
		Config: testGithubRunPolicyConfig(t, config),
		Plan:   testGithubRunPolicyPlan(t, plan),
		State:  testGithubRunPolicyState(t, state),
	}
	resp := &fwresource.UpdateResponse{
		State: tfsdk.State{Schema: testGithubRunPolicyResourceSchema(t)},
	}

	r.Update(ctx, req, resp)

	require.False(t, resp.Diagnostics.HasError())
	mockClient.AssertExpectations(t)
}

func TestGithubRunPolicyResource_EmptyLabelsMatchAllJobs(t *testing.T) {
	t.Parallel()

	// Documents the contract introduced in agent-api PR #7814: an empty
	// harden_runner_target_labels list applies the policy to all jobs. The provider
	// must round-trip `harden_runner_target_labels = []` without drift even though
	// the backend struct serializes the empty slice as omitted JSON.
	ctx := context.Background()
	now := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)

	plan := githubRunPolicyResourceModel{
		Owner:        types.StringValue("test-org"),
		Name:         types.StringValue("All Jobs Policy"),
		PolicyID:     types.StringNull(),
		AllRepos:     types.BoolValue(true),
		AllOrgs:      types.BoolValue(false),
		Repositories: types.ListNull(types.StringType),
		PolicyConfig: testRunPolicyConfigObjectValue(policyConfigModel{
			Owner:                          types.StringValue("test-org"),
			Name:                           types.StringValue("All Jobs Policy"),
			EnableActionPolicy:             types.BoolValue(false),
			AllowedActions:                 types.MapNull(types.StringType),
			EnableHardenRunnerPolicy:       types.BoolValue(true),
			HardenRunnerTargetLabels:       types.SetValueMust(types.StringType, []attr.Value{}),
			HardenRunnerCustomActions:      types.SetValueMust(types.StringType, []attr.Value{}),
			EnableRunsOnPolicy:             types.BoolValue(false),
			DisallowedRunnerLabels:         types.SetNull(types.StringType),
			EnableSecretsPolicy:            types.BoolValue(false),
			EnableCompromisedActionsPolicy: types.BoolValue(false),
			IsDryRun:                       types.BoolValue(false),
			ExemptedUsers:                  types.SetNull(types.StringType),
		}),
		CreatedBy:     types.StringNull(),
		CreatedAt:     types.StringNull(),
		LastUpdatedBy: types.StringNull(),
		LastUpdatedAt: types.StringNull(),
	}

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.
		On("CreateRunPolicy", mock.Anything, "test-org", mock.MatchedBy(func(req stepsecurityapi.CreateRunPolicyRequest) bool {
			if !req.PolicyConfig.EnableHardenRunnerPolicy {
				return false
			}
			// nil and []string{} both signal "match all jobs" under PR 7814.
			return len(req.PolicyConfig.HardenRunnerTargetLabels) == 0 &&
				len(req.PolicyConfig.HardenRunnerCustomActions) == 0
		})).
		Return(&stepsecurityapi.RunPolicy{
			Owner:         "test-org",
			PolicyID:      "policy-allmatch",
			Name:          "All Jobs Policy",
			CreatedBy:     "test-user",
			CreatedAt:     now,
			LastUpdatedBy: "test-user",
			LastUpdatedAt: now,
			AllRepos:      true,
			PolicyConfig: stepsecurityapi.RunPolicyConfig{
				Owner:                    "test-org",
				Name:                     "All Jobs Policy",
				EnableHardenRunnerPolicy: true,
				// Backend round-trips the empty slice as omitted JSON, so the
				// response carries nil — preservePreviousEmptySet must keep []
				// in state to avoid spurious diffs.
				HardenRunnerTargetLabels:  nil,
				HardenRunnerCustomActions: nil,
			},
		}, nil).
		Once()

	r := &githubRunPolicyResource{client: mockClient}
	req := fwresource.CreateRequest{
		Plan: testGithubRunPolicyPlan(t, plan),
	}
	resp := &fwresource.CreateResponse{
		State: tfsdk.State{Schema: testGithubRunPolicyResourceSchema(t)},
	}

	r.Create(ctx, req, resp)

	require.False(t, resp.Diagnostics.HasError())
	mockClient.AssertExpectations(t)

	var state githubRunPolicyResourceModel
	diags := resp.State.Get(ctx, &state)
	require.False(t, diags.HasError())

	var policyConfig policyConfigModel
	diags = state.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	require.False(t, diags.HasError())

	assert.True(t, policyConfig.EnableHardenRunnerPolicy.ValueBool())
	assert.False(t, policyConfig.HardenRunnerTargetLabels.IsNull(), "empty set must not drift to null")
	assert.False(t, policyConfig.HardenRunnerCustomActions.IsNull(), "empty set must not drift to null")
	assert.Empty(t, setStrings(t, policyConfig.HardenRunnerTargetLabels))
	assert.Empty(t, setStrings(t, policyConfig.HardenRunnerCustomActions))
}

func TestGithubRunPolicyResource_ImportAllJobsPolicyLandsAsNull(t *testing.T) {
	t.Parallel()

	// Documents the import/fresh-Read UX for an "all jobs" Harden Runner
	// policy (enabled + empty labels on the backend, arriving as nil due to
	// JSON omitempty). On first Read, the resource has no prior config to
	// anchor an empty set to, so state lands as null. The user's HCL must
	// then set `harden_runner_target_labels = []` to reconcile on the next apply.
	//
	// This behavior is intentional: surfacing `[]` unconditionally would
	// break the additive-only contract, since users who omit the attribute
	// would see a perpetual drift (plan=null vs state=[]). The prior-state
	// signal is what lets `preservePreviousEmptySet` choose correctly in the
	// update path.
	ctx := context.Background()
	now := time.Date(2024, 7, 8, 9, 10, 11, 0, time.UTC)

	model := &githubRunPolicyResourceModel{
		Owner:    types.StringValue("test-org"),
		PolicyID: types.StringValue("policy-allmatch"),
	}
	apiResponse := &stepsecurityapi.RunPolicy{
		Owner:         "test-org",
		PolicyID:      "policy-allmatch",
		Name:          "All Jobs Policy",
		CreatedBy:     "test-user",
		CreatedAt:     now,
		LastUpdatedBy: "test-user",
		LastUpdatedAt: now,
		AllRepos:      true,
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner:                    "test-org",
			Name:                     "All Jobs Policy",
			EnableHardenRunnerPolicy: true,
			// Backend stored an empty labels list; omitempty strips it from the
			// response, so the provider sees a nil slice.
			HardenRunnerTargetLabels:  nil,
			HardenRunnerCustomActions: nil,
		},
	}

	r := &githubRunPolicyResource{}
	var diags diag.Diagnostics
	r.updateModelFromAPI(ctx, model, apiResponse, &diags)
	require.False(t, diags.HasError())

	var policyConfig policyConfigModel
	asDiags := model.PolicyConfig.As(ctx, &policyConfig, basetypes.ObjectAsOptions{})
	require.False(t, asDiags.HasError())

	assert.True(t, policyConfig.EnableHardenRunnerPolicy.ValueBool())
	// Expected: null, because there is no prior config to signal that the
	// user wants an empty-set representation. One `terraform apply` after
	// import with `harden_runner_target_labels = []` in HCL reconciles the state.
	assert.True(t, policyConfig.HardenRunnerTargetLabels.IsNull(), "fresh Read must land as null; prior-state signal drives the empty-set preservation")
	assert.True(t, policyConfig.HardenRunnerCustomActions.IsNull())
}

func testGithubRunPolicyResourceSchema(t *testing.T) resourceschema.Schema {
	t.Helper()

	r := &githubRunPolicyResource{}
	resp := &fwresource.SchemaResponse{}
	r.Schema(context.Background(), fwresource.SchemaRequest{}, resp)
	require.False(t, resp.Diagnostics.HasError())

	return resp.Schema
}

func testGithubRunPolicyPlan(t *testing.T, model githubRunPolicyResourceModel) tfsdk.Plan {
	t.Helper()
	model = withRepoPropertyFiltersDefault(model)

	plan := tfsdk.Plan{Schema: testGithubRunPolicyResourceSchema(t)}
	diags := plan.Set(context.Background(), model)
	require.False(t, diags.HasError())

	return plan
}

func testGithubRunPolicyState(t *testing.T, model githubRunPolicyResourceModel) tfsdk.State {
	t.Helper()
	model = withRepoPropertyFiltersDefault(model)

	state := tfsdk.State{Schema: testGithubRunPolicyResourceSchema(t)}
	diags := state.Set(context.Background(), model)
	require.False(t, diags.HasError())

	return state
}

func testGithubRunPolicyConfig(t *testing.T, model githubRunPolicyResourceModel) tfsdk.Config {
	t.Helper()

	plan := testGithubRunPolicyPlan(t, model)
	return tfsdk.Config{Raw: plan.Raw, Schema: testGithubRunPolicyResourceSchema(t)}
}

func testRunPolicyConfigObjectValue(policyConfig policyConfigModel) types.Object {
	pinnedActionsExemptions := policyConfig.PinnedActionsExemptions
	if reflect.DeepEqual(pinnedActionsExemptions, types.Set{}) {
		pinnedActionsExemptions = types.SetNull(types.StringType)
	}

	hardenRunnerExcludedLabels := policyConfig.HardenRunnerExcludedLabels
	if reflect.DeepEqual(hardenRunnerExcludedLabels, types.Set{}) {
		hardenRunnerExcludedLabels = types.SetNull(types.StringType)
	}

	allowedRunnerLabels := policyConfig.AllowedRunnerLabels
	if reflect.DeepEqual(allowedRunnerLabels, types.Set{}) {
		allowedRunnerLabels = types.SetNull(types.StringType)
	}

	allowedRunnerConstraints := policyConfig.AllowedRunnerConstraints
	if reflect.DeepEqual(allowedRunnerConstraints, types.Map{}) {
		allowedRunnerConstraints = types.MapNull(types.SetType{ElemType: types.StringType})
	}

	prejobAllowedRunnerLabels := policyConfig.PrejobAllowedRunnerLabels
	if reflect.DeepEqual(prejobAllowedRunnerLabels, types.Set{}) {
		prejobAllowedRunnerLabels = types.SetNull(types.StringType)
	}

	prejobDisallowedRunnerLabels := policyConfig.PrejobDisallowedRunnerLabels
	if reflect.DeepEqual(prejobDisallowedRunnerLabels, types.Set{}) {
		prejobDisallowedRunnerLabels = types.SetNull(types.StringType)
	}

	runnerLabelRequirements := policyConfig.RunnerLabelRequirements
	if reflect.DeepEqual(runnerLabelRequirements, types.List{}) {
		runnerLabelRequirements = types.ListNull(runnerLabelRequirementObjectType)
	}

	return types.ObjectValueMust(map[string]attr.Type{
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
		"exempted_users":                    types.SetType{ElemType: types.StringType},
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
	}, map[string]attr.Value{
		"owner":                             policyConfig.Owner,
		"name":                              policyConfig.Name,
		"enable_action_policy":              policyConfig.EnableActionPolicy,
		"allowed_actions":                   policyConfig.AllowedActions,
		"enable_harden_runner_policy":       policyConfig.EnableHardenRunnerPolicy,
		"harden_runner_target_labels":       policyConfig.HardenRunnerTargetLabels,
		"harden_runner_excluded_labels":     hardenRunnerExcludedLabels,
		"harden_runner_custom_actions":      policyConfig.HardenRunnerCustomActions,
		"enable_runs_on_policy":             policyConfig.EnableRunsOnPolicy,
		"enable_standard_runner_labels":     policyConfig.EnableStandardRunnerLabels,
		"disallowed_runner_labels":          policyConfig.DisallowedRunnerLabels,
		"enable_secrets_policy":             policyConfig.EnableSecretsPolicy,
		"enable_compromised_actions_policy": policyConfig.EnableCompromisedActionsPolicy,
		"require_pinned_actions":            policyConfig.RequirePinnedActions,
		"actions_to_exempt_while_pinning":   pinnedActionsExemptions,
		"is_dry_run":                        policyConfig.IsDryRun,
		"exempted_users":                    policyConfig.ExemptedUsers,
		"bulk_secrets_only_mode":            policyConfig.BulkSecretsOnlyMode,
		"pr_comment_template":               policyConfig.PrCommentTemplate,
		"runs_on_mode":                      policyConfig.RunsOnMode,
		"allowed_runner_labels":             allowedRunnerLabels,
		"allowed_runner_constraints":        allowedRunnerConstraints,
		"require_policy_store":              policyConfig.RequirePolicyStore,
		"block_job_container":               policyConfig.BlockJobContainer,
		"secrets_analyze_default_branch":    policyConfig.SecretsAnalyzeDefaultBranch,
		"enforce_method":                    policyConfig.EnforceMethod,
		"prejob_allowed_runner_labels":      prejobAllowedRunnerLabels,
		"prejob_disallowed_runner_labels":   prejobDisallowedRunnerLabels,
		"runner_label_requirements":         runnerLabelRequirements,
	})
}

func testStringAttrValues(values []string) []attr.Value {
	result := make([]attr.Value, len(values))
	for i, value := range values {
		result[i] = types.StringValue(value)
	}

	return result
}

func setStrings(t *testing.T, value types.Set) []string {
	t.Helper()

	var result []string
	diags := value.ElementsAs(context.Background(), &result, false)
	require.False(t, diags.HasError())
	return result
}

func testAccGithubRunPolicyResourceConfig(owner, name string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_run_policy" "test" {
  owner     = %[1]q
  name      = %[2]q
  all_repos = true

  policy_config = {
    owner                        = %[1]q
    name                         = %[2]q
    enable_action_policy         = true
    enable_harden_runner_policy  = true
    harden_runner_target_labels  = ["ubuntu-step-security"]
    harden_runner_custom_actions = ["my-org/harden-runner"]
    allowed_actions = {
      "actions/checkout" = "allow"
    }
  }
}
`, owner, name)
}

func testAccGithubRunPolicyResourceConfigWithPinning(owner, name string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_run_policy" "test" {
  owner     = %[1]q
  name      = %[2]q
  all_repos = true

  policy_config = {
    owner                           = %[1]q
    name                            = %[2]q
    enable_action_policy            = true
    require_pinned_actions          = true
    actions_to_exempt_while_pinning = ["actions/*"]
    allowed_actions = {
      "actions/checkout" = "allow"
    }
  }
}
`, owner, name)
}

func testAccGithubRunPolicyResourceConfigUpdated(owner, name string) string {
	return fmt.Sprintf(`
resource "stepsecurity_github_run_policy" "test" {
  owner     = %[1]q
  name      = %[2]q
  all_repos = true

  policy_config = {
    owner                        = %[1]q
    name                         = %[2]q
    enable_action_policy         = true
    enable_harden_runner_policy  = true
    enable_secrets_policy        = true
    harden_runner_target_labels  = ["ubuntu-step-security"]
    harden_runner_custom_actions = ["my-org/harden-runner"]
    allowed_actions = {
      "actions/checkout"             = "allow"
      "step-security/harden-runner" = "allow"
    }
  }
}
`, owner, name)
}

// withRepoPropertyFiltersDefault types a zero-value custom_property_rule as a
// null list, so fixtures written before the attribute existed still convert.
func withRepoPropertyFiltersDefault(model githubRunPolicyResourceModel) githubRunPolicyResourceModel {
	if model.RepoPropertyFilters.ElementType(context.Background()) == nil {
		model.RepoPropertyFilters = types.ListNull(repoPropertyFilterObjectType)
	}
	return model
}
