package provider

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	fwdatasource "github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

func testPropertyFilterRow(name string, values []string, match string, combine types.String) attr.Value {
	vals := make([]attr.Value, len(values))
	for i, v := range values {
		vals[i] = types.StringValue(v)
	}
	return types.ObjectValueMust(repoPropertyFilterObjectType.AttrTypes, map[string]attr.Value{
		"property": types.StringValue(name),
		"values":   types.SetValueMust(types.StringType, vals),
		"match":    types.StringValue(match),
		"combine":  combine,
	})
}

func testPropertyScopedPlan(filters types.List) githubRunPolicyResourceModel {
	return githubRunPolicyResourceModel{
		Owner:               types.StringValue("test-org"),
		Name:                types.StringValue("Tier 1 Policy"),
		PolicyID:            types.StringValue("policy-123"),
		AllRepos:            types.BoolValue(false),
		AllOrgs:             types.BoolValue(false),
		Repositories:        types.ListNull(types.StringType),
		RepoPropertyFilters: filters,
		PolicyConfig: testRunPolicyConfigObjectValue(policyConfigModel{
			Owner:                          types.StringValue("test-org"),
			Name:                           types.StringValue("Tier 1 Policy"),
			EnableActionPolicy:             types.BoolValue(false),
			AllowedActions:                 types.MapNull(types.StringType),
			EnableHardenRunnerPolicy:       types.BoolValue(false),
			HardenRunnerTargetLabels:       types.SetNull(types.StringType),
			HardenRunnerCustomActions:      types.SetNull(types.StringType),
			EnableRunsOnPolicy:             types.BoolValue(false),
			DisallowedRunnerLabels:         types.SetNull(types.StringType),
			EnableSecretsPolicy:            types.BoolValue(true),
			EnableCompromisedActionsPolicy: types.BoolValue(false),
			IsDryRun:                       types.BoolValue(true),
			ExemptedUsers:                  types.SetNull(types.StringType),
		}),
		CreatedBy:     types.StringNull(),
		CreatedAt:     types.StringNull(),
		LastUpdatedBy: types.StringNull(),
		LastUpdatedAt: types.StringNull(),
	}
}

func testTwoRowRule() types.List {
	return types.ListValueMust(repoPropertyFilterObjectType, []attr.Value{
		testPropertyFilterRow("sensitive_app_level", []string{"Tier 1"}, "any", types.StringNull()),
		testPropertyFilterRow("compliance_scope", []string{"pci", "sox"}, "all", types.StringValue("or")),
	})
}

func testStoredRule() []stepsecurityapi.RepoPropertyFilter {
	return []stepsecurityapi.RepoPropertyFilter{
		{Name: "sensitive_app_level", Values: []string{"Tier 1"}, Match: "any"},
		{Name: "compliance_scope", Values: []string{"pci", "sox"}, Match: "all", Join: "or"},
	}
}

func testPolicyResponse(filters []stepsecurityapi.RepoPropertyFilter) *stepsecurityapi.RunPolicy {
	now := time.Date(2026, 11, 5, 1, 2, 3, 0, time.UTC)
	return &stepsecurityapi.RunPolicy{
		Owner: "test-org", PolicyID: "policy-123", Name: "Tier 1 Policy",
		CreatedBy: "test-user", CreatedAt: now, LastUpdatedBy: "test-user", LastUpdatedAt: now,
		RepoPropertyFilters: filters,
		PolicyConfig: stepsecurityapi.RunPolicyConfig{
			Owner: "test-org", Name: "Tier 1 Policy", EnableSecretsPolicy: true, IsDryRun: true,
		},
	}
}

func stateFilters(t *testing.T, state tfsdk.State) []repoPropertyFilterModel {
	t.Helper()
	var model githubRunPolicyResourceModel
	require.False(t, state.Get(context.Background(), &model).HasError())
	if model.RepoPropertyFilters.IsNull() {
		return nil
	}
	var rows []repoPropertyFilterModel
	require.False(t, model.RepoPropertyFilters.ElementsAs(context.Background(), &rows, false).HasError())
	return rows
}

func TestGithubRunPolicyResource_CreateSendsAndStoresPropertyFilters(t *testing.T) {
	t.Parallel()

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.
		On("CreateRunPolicy", mock.Anything, "test-org", mock.MatchedBy(func(req stepsecurityapi.CreateRunPolicyRequest) bool {
			f := req.RepoPropertyFilters
			return !req.AllRepos && len(f) == 2 &&
				f[0].Name == "sensitive_app_level" && f[0].Match == "any" && f[0].Join == "" &&
				f[1].Name == "compliance_scope" && f[1].Match == "all" && f[1].Join == "or" &&
				assert.ElementsMatch(t, []string{"pci", "sox"}, f[1].Values)
		})).
		Return(testPolicyResponse(testStoredRule()), nil).
		Once()

	r := &githubRunPolicyResource{client: mockClient}
	resp := &fwresource.CreateResponse{State: tfsdk.State{Schema: testGithubRunPolicyResourceSchema(t)}}
	r.Create(context.Background(), fwresource.CreateRequest{Plan: testGithubRunPolicyPlan(t, testPropertyScopedPlan(testTwoRowRule()))}, resp)

	require.False(t, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)
	mockClient.AssertExpectations(t)

	rows := stateFilters(t, resp.State)
	require.Len(t, rows, 2)
	assert.True(t, rows[0].Combine.IsNull(), "first-row combine must stay null to match config")
	assert.Equal(t, "or", rows[1].Combine.ValueString())
	assert.Equal(t, "all", rows[1].Match.ValueString())
	assert.Equal(t, []string{"Tier 1"}, setStrings(t, rows[0].Values))
}

// Removing the rule from config must clear it: the backend keeps a stored rule
// when the field is absent, so Update has to send an explicit empty list.
func TestGithubRunPolicyResource_UpdateWithoutRuleSendsEmptyList(t *testing.T) {
	t.Parallel()

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.
		On("UpdateRunPolicy", mock.Anything, "test-org", "policy-123", mock.MatchedBy(func(req stepsecurityapi.UpdateRunPolicyRequest) bool {
			body, err := json.Marshal(req)
			return err == nil && req.RepoPropertyFilters != nil &&
				assert.Contains(t, string(body), `"repo_property_filters":[]`)
		})).
		Return(testPolicyResponse(nil), nil).
		Once()

	plan := testPropertyScopedPlan(types.ListNull(repoPropertyFilterObjectType))
	plan.Repositories = types.ListValueMust(types.StringType, []attr.Value{types.StringValue("widgets")})
	prior := testPropertyScopedPlan(testTwoRowRule())

	r := &githubRunPolicyResource{client: mockClient}
	resp := &fwresource.UpdateResponse{State: tfsdk.State{Schema: testGithubRunPolicyResourceSchema(t)}}
	r.Update(context.Background(), fwresource.UpdateRequest{
		Config: testGithubRunPolicyConfig(t, plan),
		Plan:   testGithubRunPolicyPlan(t, plan),
		State:  testGithubRunPolicyState(t, prior),
	}, resp)

	require.False(t, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)
	mockClient.AssertExpectations(t)
	assert.Nil(t, stateFilters(t, resp.State))
}

func TestGithubRunPolicyResource_CreateWithoutRuleOmitsField(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(stepsecurityapi.CreateRunPolicyRequest{Name: "p", AllRepos: true})
	require.NoError(t, err)
	assert.NotContains(t, string(body), "repo_property_filters")
}

func TestGithubRunPolicyResource_ImportStoredRule(t *testing.T) {
	t.Parallel()

	var diags diag.Diagnostics
	r := &githubRunPolicyResource{}
	model := testPropertyScopedPlan(types.ListNull(repoPropertyFilterObjectType))
	r.updateModelFromAPI(context.Background(), &model, testPolicyResponse(testStoredRule()), &diags)
	require.False(t, diags.HasError(), "diagnostics: %v", diags)

	state := testGithubRunPolicyState(t, model)
	rows := stateFilters(t, state)
	require.Len(t, rows, 2)
	assert.True(t, rows[0].Combine.IsNull())
	assert.Equal(t, "or", rows[1].Combine.ValueString())

	r.updateModelFromAPI(context.Background(), &model, testPolicyResponse(nil), &diags)
	require.False(t, diags.HasError())
	assert.True(t, model.RepoPropertyFilters.IsNull(), "no stored rule reads back as null")
}

func TestGithubRunPolicyResource_ValidateConfigPropertyFilters(t *testing.T) {
	t.Parallel()

	repos := types.ListValueMust(types.StringType, []attr.Value{types.StringValue("widgets")})
	cases := []struct {
		name    string
		mutate  func(m *githubRunPolicyResourceModel)
		wantErr string
	}{
		{name: "valid rule", mutate: func(*githubRunPolicyResourceModel) {}},
		{name: "no rule with all_repos", mutate: func(m *githubRunPolicyResourceModel) {
			m.RepoPropertyFilters = types.ListNull(repoPropertyFilterObjectType)
			m.AllRepos = types.BoolValue(true)
		}},
		{name: "with all_repos", mutate: func(m *githubRunPolicyResourceModel) { m.AllRepos = types.BoolValue(true) }, wantErr: "Conflicting repository scope"},
		{name: "with all_orgs", mutate: func(m *githubRunPolicyResourceModel) { m.AllOrgs = types.BoolValue(true) }, wantErr: "Conflicting repository scope"},
		{name: "with repositories", mutate: func(m *githubRunPolicyResourceModel) { m.Repositories = repos }, wantErr: "Conflicting repository scope"},
		{name: "combine on first row", mutate: func(m *githubRunPolicyResourceModel) {
			m.RepoPropertyFilters = types.ListValueMust(repoPropertyFilterObjectType, []attr.Value{
				testPropertyFilterRow("team", []string{"payments"}, "any", types.StringValue("and")),
			})
		}, wantErr: "Invalid combine on the first row"},
		{name: "duplicate property ignoring case", mutate: func(m *githubRunPolicyResourceModel) {
			m.RepoPropertyFilters = types.ListValueMust(repoPropertyFilterObjectType, []attr.Value{
				testPropertyFilterRow("Team", []string{"payments"}, "any", types.StringNull()),
				testPropertyFilterRow("team", []string{"billing"}, "any", types.StringValue("or")),
			})
		}, wantErr: "Duplicate property"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := testPropertyScopedPlan(testTwoRowRule())
			tc.mutate(&m)
			r := &githubRunPolicyResource{}
			resp := &fwresource.ValidateConfigResponse{}
			r.ValidateConfig(context.Background(), fwresource.ValidateConfigRequest{Config: testGithubRunPolicyConfig(t, m)}, resp)
			if tc.wantErr == "" {
				assert.False(t, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)
				return
			}
			require.True(t, resp.Diagnostics.HasError())
			assert.Equal(t, tc.wantErr, resp.Diagnostics.Errors()[0].Summary())
		})
	}
}

func TestGithubRunPoliciesDataSource_ReadMapsPropertyFilters(t *testing.T) {
	t.Parallel()

	mockClient := &stepsecurityapi.MockStepSecurityClient{}
	mockClient.On("ListRunPolicies", mock.Anything, "test-org").
		Return([]stepsecurityapi.RunPolicy{*testPolicyResponse(testStoredRule()), *testPolicyResponse(nil)}, nil).
		Once()

	d := &githubRunPoliciesDataSource{client: mockClient}
	req := fwdatasource.ReadRequest{
		Config: testGithubRunPoliciesDataSourceConfigValue(t, githubRunPoliciesDataSourceModel{
			Owner:       types.StringValue("test-org"),
			RunPolicies: types.ListNull(types.ObjectType{AttrTypes: testRunPolicyDataSourceAttrTypes()}),
		}),
	}
	resp := &fwdatasource.ReadResponse{State: tfsdk.State{Schema: testGithubRunPoliciesDataSourceSchema(t)}}
	d.Read(context.Background(), req, resp)
	require.False(t, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)

	var state githubRunPoliciesDataSourceModel
	require.False(t, resp.State.Get(context.Background(), &state).HasError())
	var entries []githubRunPolicyDataSourceEntryModel
	require.False(t, state.RunPolicies.ElementsAs(context.Background(), &entries, false).HasError())
	require.Len(t, entries, 2)

	var rows []repoPropertyFilterModel
	require.False(t, entries[0].RepoPropertyFilters.ElementsAs(context.Background(), &rows, false).HasError())
	require.Len(t, rows, 2)
	assert.Equal(t, "compliance_scope", rows[1].Property.ValueString())
	assert.Equal(t, "or", rows[1].Combine.ValueString())
	assert.True(t, entries[1].RepoPropertyFilters.IsNull(), "policy without a rule reads back as null")
}

// A rule element built from another resource is unknown at validate time and
// must not fail validation.
func TestGithubRunPolicyResource_ValidateConfigUnknownRow(t *testing.T) {
	t.Parallel()

	m := testPropertyScopedPlan(types.ListValueMust(repoPropertyFilterObjectType, []attr.Value{
		types.ObjectUnknown(repoPropertyFilterObjectType.AttrTypes),
	}))
	r := &githubRunPolicyResource{}
	resp := &fwresource.ValidateConfigResponse{}
	r.ValidateConfig(context.Background(), fwresource.ValidateConfigRequest{Config: testGithubRunPolicyConfig(t, m)}, resp)
	assert.False(t, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)
}

// Removing combine = "or" from a later row must plan "and" (the API default), not
// keep the prior "or" with an empty plan.
func TestGithubRunPolicyResource_ModifyPlanResolvesOmittedJoin(t *testing.T) {
	t.Parallel()

	cfgRule := types.ListValueMust(repoPropertyFilterObjectType, []attr.Value{
		testPropertyFilterRow("sensitive_app_level", []string{"Tier 1"}, "any", types.StringNull()),
		testPropertyFilterRow("compliance_scope", []string{"pci", "sox"}, "all", types.StringNull()),
	})
	priorRule := testTwoRowRule() // second row combines with "or"

	r := &githubRunPolicyResource{}
	cfg := testGithubRunPolicyConfig(t, testPropertyScopedPlan(cfgRule))
	plan := testGithubRunPolicyPlan(t, testPropertyScopedPlan(priorRule))
	resp := &fwresource.ModifyPlanResponse{Plan: plan}
	r.ModifyPlan(context.Background(), fwresource.ModifyPlanRequest{Config: cfg, Plan: plan}, resp)
	require.False(t, resp.Diagnostics.HasError(), "diagnostics: %v", resp.Diagnostics)

	var model githubRunPolicyResourceModel
	require.False(t, resp.Plan.Get(context.Background(), &model).HasError())
	var rows []repoPropertyFilterModel
	require.False(t, model.RepoPropertyFilters.ElementsAs(context.Background(), &rows, false).HasError())
	require.Len(t, rows, 2)
	assert.True(t, rows[0].Combine.IsNull(), "first row has no combine")
	assert.Equal(t, "and", rows[1].Combine.ValueString(), "omitted combine plans the API default")
	assert.True(t, model.LastUpdatedAt.IsUnknown(), "update stamps change on apply")
	assert.True(t, model.LastUpdatedBy.IsUnknown())
}

func TestTrimmedTokenRejectsUnicodeWhitespace(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value string
		ok    bool
	}{
		{"Tier 1", true},
		{"\u00a0Tier 1", false}, // non-breaking space
		{"Tier 1\u2003", false}, // em space
		{" Tier 1", false},
	} {
		resp := &validator.StringResponse{}
		trimmedToken{}.ValidateString(context.Background(), validator.StringRequest{ConfigValue: types.StringValue(tc.value)}, resp)
		assert.Equal(t, !tc.ok, resp.Diagnostics.HasError(), "value %q", tc.value)
	}
}

func TestRepoPropertyTokenLengthCountsCharacters(t *testing.T) {
	t.Parallel()

	attrs := repoPropertyFiltersSchemaAttribute().NestedObject.Attributes
	validators := attrs["property"].(schema.StringAttribute).Validators
	for _, tc := range []struct {
		label string
		value string
		ok    bool
	}{
		{"75 ASCII characters", strings.Repeat("a", 75), true},
		{"76 ASCII characters", strings.Repeat("a", 76), false},
		{"30 CJK characters (90 bytes)", strings.Repeat("層", 30), true},
		{"75 accented characters (150 bytes)", strings.Repeat("é", 75), true},
		{"76 accented characters", strings.Repeat("é", 76), false},
	} {
		resp := &validator.StringResponse{}
		for _, v := range validators {
			v.ValidateString(context.Background(), validator.StringRequest{ConfigValue: types.StringValue(tc.value)}, resp)
		}
		assert.Equal(t, !tc.ok, resp.Diagnostics.HasError(), tc.label)
	}
}
