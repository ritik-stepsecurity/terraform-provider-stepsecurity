package stepsecurityapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// PolicyDrivenPRPolicy represents the Terraform resource model
type PolicyDrivenPRPolicy struct {
	Owner                 string                              `json:"owner"`
	AutoRemdiationOptions AutoRemdiationOptions               `json:"auto_remediation_options"`
	SelectedRepos         []string                            `json:"selected_repos"`
	SelectedReposFilter   ApplyIssuePRConfigForAllReposFilter `json:"selected_repos_filter"`
	UseRepoLevelConfig    bool                                `json:"use_repo_level_config"`
	UseOrgLevelConfig     bool                                `json:"use_org_level_config"`
	// OrgConfigNotAppliedToAllRepos is set on a wildcard read when the org-level [all]
	// config still carries settings but "apply to all repositories" is turned off, so
	// those settings are not reaching every repo. It is read-only and never sent.
	OrgConfigNotAppliedToAllRepos bool `json:"-"`
}

type AutoRemdiationOptions struct {
	CreatePR                                bool                   `json:"create_pr"`
	CreateIssue                             bool                   `json:"create_issue"`
	CreateGitHubAdvancedSecurityAlert       bool                   `json:"create_github_advanced_security_alert"`
	HardenGitHubHostedRunner                bool                   `json:"harden_github_hosted_runner"`
	PinActionsToSHA                         bool                   `json:"pin_actions_to_sha"`
	RestrictGitHubTokenPermissions          bool                   `json:"restrict_github_token_permissions"`
	SecureDockerFile                        bool                   `json:"secure_docker_file"`
	ActionsToExemptWhilePinning             []string               `json:"actions_to_exempt_while_pinning"`
	ImagesToExemptWhilePinning              []string               `json:"images_to_exempt_while_pinning"`
	ActionsToReplaceWithStepSecurityActions []string               `json:"actions_to_replace_with_step_security_actions"`
	CustomActionsToReplace                  map[string]string      `json:"custom_actions_to_replace,omitempty"`
	ReplaceByMajorTag                       *bool                  `json:"replace_by_major_tag,omitempty"`
	ExemptedFromReplacement                 []string               `json:"exempted_from_replacement,omitempty"`
	UpdatePrecommitFile                     []string               `json:"update_precommit_file,omitempty"`
	CustomPrecommitConfig                   *CustomPrecommitConfig `json:"custom_precommit_config,omitempty"`
	PackageEcosystem                        []DependabotConfig     `json:"package_ecosystem,omitempty"`
	DockerfilePatterns                      []string               `json:"dockerfile_patterns,omitempty"`
	Subtractive                             *bool                  `json:"subtractive,omitempty"`
	AddWorkflows                            string                 `json:"add_workflows,omitempty"`
	ActionCommitMap                         map[string]string      `json:"action_commit_map"`
	HardenRunnerConfig                      *HardenRunnerConfig    `json:"harden_runner_config,omitempty"`
	LabelsToReplace                         map[string]string      `json:"labels_to_replace,omitempty"`
}

// API request/response structures matching agent-api
type policyDrivenPRConfigOptions struct {
	UseRepoLevelConfig      *bool                       `json:"use_repo_level_config,omitempty"`
	UseOrgLevelConfig       *bool                       `json:"use_org_level_config,omitempty"`
	ControlChecksConfig     *controlChecksFeatureConfig `json:"control_checks_config,omitempty"`
	TriggerGithubAlert      *bool                       `json:"trigger_github_alert,omitempty"`
	TriggerPRInsteadOfIssue *bool                       `json:"trigger_pr_instead_of_issue,omitempty"`
	ControlSettings         *controlSettings            `json:"control_settings,omitempty"`
}

type controlChecksFeatureConfig map[string]issuePRConfig

type issuePRConfig struct {
	TriggerGithubIssue bool `json:"trigger_github_issue"`
	TriggerGithubPr    bool `json:"trigger_github_pr"`
}

// controlSettings is the control_settings object sent to the API.
//
// DockerfilePatterns has no omitempty: the API keeps the stored patterns when the key
// is missing, so removing them from the config has to reach it as an explicit empty
// list.
type controlSettings struct {
	ExemptedActions                     []string                             `json:"exempted_actions"`
	ActionsToReplace                    map[string]string                    `json:"actions_to_replace"`
	CustomActionsToReplace              map[string]string                    `json:"custom_actions_to_replace"`
	ReplaceByMajorTag                   *bool                                `json:"replace_by_major_tag,omitempty"`
	ExemptedFromReplacement             []string                             `json:"exempted_from_replacement"`
	ReplaceAllActions                   *bool                                `json:"replace_all_actions,omitempty"`
	LabelsToReplace                     map[string]string                    `json:"labels_to_replace"`
	UpdatePrecommitFile                 map[string]bool                      `json:"update_precommit_file"`
	CustomPrecommitConfig               *CustomPrecommitConfig               `json:"custom_precommit_config,omitempty"`
	PackageEcosystem                    []DependabotConfig                   `json:"package_ecosystem,omitempty"`
	DockerfilePatterns                  []string                             `json:"dockerfile_patterns"`
	Subtractive                         *bool                                `json:"subtractive,omitempty"`
	AddWorkflows                        string                               `json:"add_workflows,omitempty"`
	ApplyIssuePRConfigForAllRepos       *bool                                `json:"apply_issue_pr_config_for_all_repos,omitempty"`
	ApplyIssuePRConfigForAllReposFilter *ApplyIssuePRConfigForAllReposFilter `json:"apply_issue_pr_config_for_all_repos_filter,omitempty"`
	ActionCommitMap                     map[string]string                    `json:"action_commit_map"`
	ExemptedImages                      []string                             `json:"exempted_images"`
	HardenRunnerConfig                  *HardenRunnerConfig                  `json:"harden_runner_config,omitempty"`
}

type ApplyIssuePRConfigForAllReposFilter struct {
	ReposTopics []string `json:"repos_topics,omitempty"`
}

type DependabotConfig struct {
	Package      string `json:"package"`
	Interval     string `json:"interval"`
	CoolDownYAML string `json:"cooldown_yaml,omitempty"`
	GroupsYAML   string `json:"groups_yaml,omitempty"`
	OptionsYAML  string `json:"options_yaml,omitempty"`
	// The API parses cooldown_yaml and groups_yaml when a config is written and stores
	// the result in these structured fields; it does not keep or return the YAML text.
	// options_yaml is stored as written. Reads use these to recover the YAML.
	CoolDown *DependabotCoolDown        `json:"cooldown,omitempty"`
	Groups   map[string]DependabotGroup `json:"groups,omitempty"`
}

// DependabotCoolDown is the parsed form of cooldown_yaml as the API returns it. The JSON
// names are the API's Go field names; the yaml tags are Dependabot's own keys, which is
// what the provider renders back into cooldown_yaml.
type DependabotCoolDown struct {
	DefaultDays     int      `json:"DefaultDays,omitempty" yaml:"default-days,omitempty"`
	SemverMajorDays int      `json:"SemverMajorDays,omitempty" yaml:"semver-major-days,omitempty"`
	SemverMinorDays int      `json:"SemverMinorDays,omitempty" yaml:"semver-minor-days,omitempty"`
	SemverPatchDays int      `json:"SemverPatchDays,omitempty" yaml:"semver-patch-days,omitempty"`
	Include         []string `json:"Include,omitempty" yaml:"include,omitempty"`
	Exclude         []string `json:"Exclude,omitempty" yaml:"exclude,omitempty"`
}

// DependabotGroup is the parsed form of one entry of groups_yaml as the API returns it.
type DependabotGroup struct {
	AppliesTo       string   `json:"AppliesTo,omitempty" yaml:"applies-to,omitempty"`
	Patterns        []string `json:"Patterns,omitempty" yaml:"patterns,omitempty"`
	ExcludePatterns []string `json:"ExcludePatterns,omitempty" yaml:"exclude-patterns,omitempty"`
	DependencyType  string   `json:"DependencyType,omitempty" yaml:"dependency-type,omitempty"`
	UpdateTypes     []string `json:"UpdateTypes,omitempty" yaml:"update-types,omitempty"`
	GroupBy         string   `json:"GroupBy,omitempty" yaml:"group-by,omitempty"`
}

// HardenRunnerConfig is sent as a whole object: the API replaces it rather than merging
// it field by field. Both label fields are serialized unconditionally, without omitempty,
// so clearing either one reaches the API as an explicit empty list instead of a missing
// key, and does not depend on that replace-vs-merge behavior staying as it is.
type HardenRunnerConfig struct {
	Config             string   `json:"config"`
	Subtractive        bool     `json:"subtractive"`
	SkipHardenRunner   bool     `json:"skipHardenRunner"`
	RunnerLabels       []string `json:"runnerLabels"`
	ExemptRunnerLabels []string `json:"exemptRunnerLabels"`
}

// CustomPrecommitConfig is a full .pre-commit-config.yaml provided verbatim.
// UpdateExistingConfiguration gates overwriting an existing file: false leaves an
// existing config untouched (only creates when absent); true overwrites it.
//
// Neither field carries omitempty. The API stores this object wholesale, so both an
// empty config and update_existing_configuration=false have to travel as explicit
// values: with omitempty, turning the flag back off would drop the key and leave the
// request unable to say "false" at all. Whether the object itself is present is carried
// by the enclosing pointer, which is where omitempty belongs, since a nil pointer is the
// only way to express "no custom config configured".
type CustomPrecommitConfig struct {
	Config                      string `json:"config"`
	UpdateExistingConfiguration bool   `json:"update_existing_configuration"`
}

type featureConfigResponse struct {
	FullRepoName                string                 `json:"full_repo_name"`
	PolicyDrivenPRConfiguration policyDrivenPRInternal `json:"policy_driven_pr_configuration"`
}

type policyDrivenPRInternal struct {
	UseRepoLevelConfig      bool                       `json:"use_repo_level_config"`
	UseOrgLevelConfig       bool                       `json:"use_org_level_config"`
	ControlChecksConfig     controlChecksFeatureConfig `json:"control_checks_config"`
	TriggerGithubAlert      bool                       `json:"trigger_github_alert"`
	TriggerPRInsteadOfIssue bool                       `json:"trigger_pr_instead_of_issue"`
	ControlSettings         controlSettings            `json:"control_settings,omitempty"`
}

// pagedConfigResponse is the v2 envelope returned when chunk_response=true.
type pagedConfigResponse struct {
	Repos []featureConfigResponse `json:"repos"`
}

func (c *APIClient) CreatePolicyDrivenPRPolicy(ctx context.Context, createRequest PolicyDrivenPRPolicy) error {
	tflog.Info(ctx, "Creating policy-driven PR policy", map[string]interface{}{
		"owner":                 createRequest.Owner,
		"selected_repos":        createRequest.SelectedRepos,
		"use_repo_level_config": createRequest.UseRepoLevelConfig,
		"use_org_level_config":  createRequest.UseOrgLevelConfig,
	})

	// Convert update_precommit_file from array to map
	updatePrecommitFileMap := make(map[string]bool)
	for _, file := range createRequest.AutoRemdiationOptions.UpdatePrecommitFile {
		updatePrecommitFileMap[file] = true
	}

	// Build actions to replace map
	// If the list is exactly ["*"], treat it as replace-all instead of a literal map entry
	actionsToReplace := make(map[string]string)
	var replaceAllActions *bool
	if len(createRequest.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions) == 1 &&
		createRequest.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions[0] == "*" {
		t := true
		replaceAllActions = &t
	} else {
		for _, action := range createRequest.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions {
			actionsToReplace[action] = ""
		}
	}

	// If exempted_from_replacement is set, replace_all_actions must also be true
	if len(createRequest.AutoRemdiationOptions.ExemptedFromReplacement) > 0 {
		t := true
		replaceAllActions = &t
	}

	// actions_to_replace and replace_all_actions are mutually exclusive on the API side,
	// and the check there is for presence rather than content: a non-nil empty map still
	// counts as sending the field. actions_to_replace is serialized without omitempty so
	// that an empty map clears the stored value, which means an empty map built for a
	// replace-all request would reach the API and be rejected. Drop it, since it carries
	// no information. A non-empty map is left alone so a genuine conflict is still
	// reported by the API instead of silently discarding the configured actions.
	if replaceAllActions != nil && len(actionsToReplace) == 0 {
		actionsToReplace = nil
	}

	// Build control checks config
	controlChecksConfig := make(controlChecksFeatureConfig)
	createPR := createRequest.AutoRemdiationOptions.CreatePR
	createIssue := createRequest.AutoRemdiationOptions.CreateIssue

	if createRequest.AutoRemdiationOptions.HardenGitHubHostedRunner {
		controlChecksConfig["GitHubHostedRunnerShouldBeHardened"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if createRequest.AutoRemdiationOptions.PinActionsToSHA {
		controlChecksConfig["ActionsShouldBePinned"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if createRequest.AutoRemdiationOptions.RestrictGitHubTokenPermissions {
		controlChecksConfig["GithubTokenShouldHaveMinPermission"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if createRequest.AutoRemdiationOptions.SecureDockerFile {
		controlChecksConfig["SecureDockerFile"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if len(createRequest.AutoRemdiationOptions.LabelsToReplace) > 0 {
		controlChecksConfig["ReplaceRunnerLabels"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if len(createRequest.AutoRemdiationOptions.ActionsToReplaceWithStepSecurityActions) > 0 ||
		len(createRequest.AutoRemdiationOptions.ExemptedFromReplacement) > 0 ||
		len(createRequest.AutoRemdiationOptions.CustomActionsToReplace) > 0 {
		controlChecksConfig["MaintainedGitHubActionsShouldBeUsed"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if len(createRequest.AutoRemdiationOptions.UpdatePrecommitFile) > 0 ||
		createRequest.AutoRemdiationOptions.CustomPrecommitConfig != nil {
		controlChecksConfig["UpdatePrecommitFile"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if len(createRequest.AutoRemdiationOptions.PackageEcosystem) > 0 {
		controlChecksConfig["UpdateDependabotFile"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	if createRequest.AutoRemdiationOptions.AddWorkflows != "" {
		controlChecksConfig["AddWorkflows"] = issuePRConfig{
			TriggerGithubIssue: createIssue,
			TriggerGithubPr:    createPR,
		}
	}

	// Build control settings
	// ApplyIssuePRConfigForAllRepos should only be true when applying org-level config to ALL repos (wildcard)
	// When applying org-level config to specific repos, it should be false
	hasWildcard := len(createRequest.SelectedRepos) == 1 && createRequest.SelectedRepos[0] == "*"
	applyToAllRepos := createRequest.UseOrgLevelConfig && hasWildcard
	cs := &controlSettings{
		ExemptedActions:                     createRequest.AutoRemdiationOptions.ActionsToExemptWhilePinning,
		ActionsToReplace:                    actionsToReplace,
		CustomActionsToReplace:              createRequest.AutoRemdiationOptions.CustomActionsToReplace,
		ReplaceByMajorTag:                   createRequest.AutoRemdiationOptions.ReplaceByMajorTag,
		ExemptedFromReplacement:             createRequest.AutoRemdiationOptions.ExemptedFromReplacement,
		ReplaceAllActions:                   replaceAllActions,
		LabelsToReplace:                     createRequest.AutoRemdiationOptions.LabelsToReplace,
		UpdatePrecommitFile:                 updatePrecommitFileMap,
		CustomPrecommitConfig:               createRequest.AutoRemdiationOptions.CustomPrecommitConfig,
		PackageEcosystem:                    createRequest.AutoRemdiationOptions.PackageEcosystem,
		DockerfilePatterns:                  createRequest.AutoRemdiationOptions.DockerfilePatterns,
		Subtractive:                         createRequest.AutoRemdiationOptions.Subtractive,
		AddWorkflows:                        createRequest.AutoRemdiationOptions.AddWorkflows,
		ActionCommitMap:                     createRequest.AutoRemdiationOptions.ActionCommitMap,
		ExemptedImages:                      createRequest.AutoRemdiationOptions.ImagesToExemptWhilePinning,
		HardenRunnerConfig:                  createRequest.AutoRemdiationOptions.HardenRunnerConfig,
		ApplyIssuePRConfigForAllRepos:       &applyToAllRepos,
		ApplyIssuePRConfigForAllReposFilter: &createRequest.SelectedReposFilter,
	}

	useRepoLevel := createRequest.UseRepoLevelConfig
	useOrgLevel := createRequest.UseOrgLevelConfig
	triggerAlert := createRequest.AutoRemdiationOptions.CreateGitHubAdvancedSecurityAlert
	triggerPR := createPR

	// Build the config options
	configOptions := policyDrivenPRConfigOptions{
		UseRepoLevelConfig:      &useRepoLevel,
		UseOrgLevelConfig:       &useOrgLevel,
		ControlChecksConfig:     &controlChecksConfig,
		TriggerGithubAlert:      &triggerAlert,
		TriggerPRInsteadOfIssue: &triggerPR,
		ControlSettings:         cs,
	}

	// Handle different scenarios based on config level and selected repos
	if createRequest.UseOrgLevelConfig && hasWildcard {
		// For org-level config with wildcard, use [all] endpoint to apply to all repos
		return c.updateConfigForRepo(ctx, createRequest.Owner, "[all]", configOptions)
	}

	// For org-level config with specific repos OR repo-level config, apply to each specific repo
	for _, repo := range createRequest.SelectedRepos {
		if err := c.updateConfigForRepo(ctx, createRequest.Owner, repo, configOptions); err != nil {
			return fmt.Errorf("failed to update config for repo %s: %w", repo, err)
		}
	}

	return nil
}

func (c *APIClient) updateConfigForRepo(ctx context.Context, owner string, repo string, config policyDrivenPRConfigOptions) error {
	URI := fmt.Sprintf("%s/v1/github/%s/%s/policy-driven-pr/configs", c.BaseURL, owner, repo)

	uuid, err := uuid.GenerateUUID()
	if err != nil {
		return fmt.Errorf("error getting async event id: %w", err)
	}
	httpHeaders := map[string]string{
		"x-async-event-id": uuid,
	}

	// First attempt
	_, err = c.post(ctx, URI, config, WithHttpHeaders(httpHeaders))
	if err == nil {
		return nil
	}

	// If it's not a 503, fail immediately
	if !strings.Contains(err.Error(), "status: 503") {
		return fmt.Errorf("failed to update config for repo: %w", err)
	}

	// when status = 503 retry same request until it is completed or retry count is exhausted
	timeoutTimer := time.NewTimer(3 * time.Minute)
	periodicTicker := time.NewTicker(10 * time.Second) // poll for every 10 seconds
	defer func() {
		timeoutTimer.Stop()
		periodicTicker.Stop()
	}()

	type retryResp struct {
		Status int    `json:"status"`
		State  string `json:"state"` // in_progress, completed
		Data   any    `json:"data"`
	}

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while retrying update config for repo: %w", ctx.Err())
		case <-timeoutTimer.C:
			return fmt.Errorf("timeout exceeded while updating config for repo")
		case <-periodicTicker.C:
			response, err1 := c.post(ctx, URI, config, WithHttpHeaders(httpHeaders))
			if err1 != nil {
				return fmt.Errorf("failed to update config for repo: %w", err)
			}

			var resp retryResp
			err2 := json.Unmarshal(response, &resp)
			if err2 != nil {
				return fmt.Errorf("failed to update config for repo: %w", err)
			}

			if resp.State == "completed" {
				// check if status code is not 200 and return original error
				if resp.Status != 200 {
					return fmt.Errorf("failed to update config for repo: %w", err)
				}
				return nil
			}
		}
	}

}

func (c *APIClient) GetPolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) (*PolicyDrivenPRPolicy, error) {
	policy := &PolicyDrivenPRPolicy{
		Owner: owner,
	}

	if len(repos) == 0 {
		return policy, nil
	}

	tflog.Info(ctx, "Reading policy-driven PR policy", map[string]interface{}{
		"owner": owner,
		"repos": repos,
	})

	// Determine if this is org-level or repo-level based on repos parameter
	isOrgLevel := len(repos) > 0 && repos[0] == "*"

	var selectedConfig policyDrivenPRInternal
	var configFound bool

	if isOrgLevel {
		// Query org-level config
		config, err := c.getConfigForRepoV2(ctx, owner, "[all]")
		if err != nil {
			return policy, fmt.Errorf("failed to get org-level config: %w", err)
		}

		if config != nil && isConfigEnabled(*config) {
			if isAppliedToAllRepos(*config) {
				selectedConfig = *config
				configFound = true
			} else {
				// The [all] row outlives "apply to all repositories" being turned off: the
				// console keeps it as the org template for individually selected repos. Its
				// settings no longer reach every repo, so it does not back a wildcard.
				policy.OrgConfigNotAppliedToAllRepos = true
			}
		}
	} else {
		// Query each repo individually for repo-level config
		// Use first repo's config as the template (all should be the same)
		for _, repo := range repos {
			config, err := c.getConfigForRepoV2(ctx, owner, repo)
			if err != nil {
				tflog.Warn(ctx, "Failed to get config for repo", map[string]interface{}{
					"repo":  repo,
					"error": err.Error(),
				})
				continue
			}

			if config != nil && isConfigEnabled(*config) {
				selectedConfig = *config
				configFound = true
				break
			}
		}
	}

	if !configFound {
		// No enabled configs found
		tflog.Info(ctx, "No enabled configs found", map[string]interface{}{
			"owner": owner,
			"repos": repos,
		})
		return policy, nil
	}

	// Set policy fields - repos will be set by the caller based on state
	policy.UseRepoLevelConfig = !isOrgLevel
	policy.UseOrgLevelConfig = isOrgLevel
	policy.AutoRemdiationOptions = autoRemediationOptionsFromConfig(selectedConfig)

	// Populate SelectedReposFilter from API response
	if selectedConfig.ControlSettings.ApplyIssuePRConfigForAllReposFilter != nil {
		policy.SelectedReposFilter = *selectedConfig.ControlSettings.ApplyIssuePRConfigForAllReposFilter
	}

	return policy, nil
}

// getConfigForRepo queries repo's config
// NOTE: please don't use this function, use getConfigForRepoV2 instead
func (c *APIClient) getConfigForRepo(ctx context.Context, owner string, repo string) (*policyDrivenPRInternal, error) {
	URI := fmt.Sprintf("%s/v1/github/%s/%s/policy-driven-pr/configs", c.BaseURL, owner, repo)
	respBody, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get config for repo %s: %w", repo, err)
	}

	var configs []featureConfigResponse
	if err := json.Unmarshal(respBody, &configs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configs: %w", err)
	}

	if len(configs) == 0 {
		return nil, nil
	}

	// when repos is "[all]", we may have multiple configs
	// we need to find the config for the specific repo and return it
	var selectedConfig *policyDrivenPRInternal
	for _, config := range configs {
		if config.FullRepoName == fmt.Sprintf("%s/%s", owner, repo) {
			selectedConfig = &config.PolicyDrivenPRConfiguration
			break
		}
	}

	// Return the first config (should only be one for a specific repo)
	return selectedConfig, nil
}

// getConfigForRepoV2 queries repo's config using the v2 chunked response model.
// It sends X-Version: v2 and chunk_response=true, then follows X-Page-Token
// pagination headers to collect all pages before searching for the target repo.
func (c *APIClient) getConfigForRepoV2(ctx context.Context, owner string, repo string) (*policyDrivenPRInternal, error) {

	configs, err := c.getConfigsV2Util(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get configs for repo %s: %w", repo, err)
	}

	for _, config := range configs {
		if config.FullRepoName == fmt.Sprintf("%s/%s", owner, repo) {
			return &config.PolicyDrivenPRConfiguration, nil
		}
	}

	return nil, nil
}

func (c *APIClient) getConfigsV2Util(ctx context.Context, owner, repo string) ([]featureConfigResponse, error) {
	var allConfigs []featureConfigResponse
	pageToken := ""
	totalPages := 1

	for page := 1; page <= totalPages; page++ {
		var uri string
		if pageToken != "" {
			uri = fmt.Sprintf("%s/v1/github/%s/%s/policy-driven-pr/configs?page_token=%s&chunk_page=%d",
				c.BaseURL, owner, repo, pageToken, page)
		} else {
			uri = fmt.Sprintf("%s/v1/github/%s/%s/policy-driven-pr/configs?chunk_response=true", c.BaseURL, owner, repo)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
		req.Header.Set("X-Api-Version", "v2")

		res, err := c.HTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to get config for repo %s (page %d): %w", repo, page, err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close() //nolint:errcheck
		if err != nil {
			return nil, fmt.Errorf("failed to read response body (page %d): %w", page, err)
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status %d (page %d): %s", res.StatusCode, page, body)
		}

		// On the first page, read pagination headers to know how many pages to fetch.
		if page == 1 && res.Header.Get("X-Response-Chunked") == "true" {
			pageToken = res.Header.Get("X-Page-Token")
			if tp, err := strconv.Atoi(res.Header.Get("X-Total-Pages")); err == nil && tp > 1 {
				totalPages = tp
			}
		}
		tflog.Info(ctx, "Response", map[string]interface{}{
			"page": page,
			"body": string(body),
		})

		var pr pagedConfigResponse
		if err := json.Unmarshal(body, &pr); err != nil {
			return nil, fmt.Errorf("failed to unmarshal configs (page %d): %w", page, err)
		}
		allConfigs = append(allConfigs, pr.Repos...)
	}
	return allConfigs, nil
}

// DiscoverPolicyDrivenPRConfig queries [all] to discover if org-level or repo-level config exists
// Used during import to determine the configuration type
func (c *APIClient) DiscoverPolicyDrivenPRConfig(ctx context.Context, owner string) (*PolicyDrivenPRPolicy, error) {
	policy := &PolicyDrivenPRPolicy{
		Owner: owner,
	}

	configs, err := c.getConfigsV2Util(ctx, owner, "[all]")
	if err != nil {
		return policy, fmt.Errorf("failed to discover policy configs: %w", err)
	}

	if len(configs) == 0 {
		return policy, nil
	}

	// Separate org-level and repo-level configs
	var orgLevelConfig *policyDrivenPRInternal
	var repoConfigs []string
	selectedRepoConfigs := make(map[string]policyDrivenPRInternal)

	for _, cfg := range configs {
		// Check if this is the org-level config
		if cfg.FullRepoName == fmt.Sprintf("%s/[all]", owner) {
			orgLevelConfig = &cfg.PolicyDrivenPRConfiguration
		} else {
			// Extract repo name from full_repo_name (owner/repo)
			repoName := cfg.FullRepoName[len(owner)+1:]
			if isRepoSelected(cfg.PolicyDrivenPRConfiguration) {
				repoConfigs = append(repoConfigs, repoName)
				selectedRepoConfigs[repoName] = cfg.PolicyDrivenPRConfiguration
			}
		}
	}

	// Determine which config to use
	var selectedConfig policyDrivenPRInternal
	var selectedRepos []string
	var useOrgLevel bool

	if orgLevelConfig != nil && isConfigEnabled(*orgLevelConfig) && isAppliedToAllRepos(*orgLevelConfig) {
		// Org-level config applied to all repositories
		selectedConfig = *orgLevelConfig
		selectedRepos = []string{"*"}
		useOrgLevel = true
	} else if len(repoConfigs) > 0 {
		// Repo-level configs exist. One resource holds one set of settings, so the
		// selected repos can only be imported together when they all share it.
		if groups := groupReposBySettings(repoConfigs, selectedRepoConfigs); len(groups) > 1 {
			return policy, mixedSettingsImportError(owner, groups)
		}
		useOrgLevel = false
		// Use first repo config as template
		config, _ := c.getConfigForRepoV2(ctx, owner, repoConfigs[0])
		if config != nil {
			selectedConfig = *config
			selectedRepos = repoConfigs
		}
	} else {
		// No enabled configs found
		return policy, nil
	}

	policy.SelectedRepos = selectedRepos
	policy.UseRepoLevelConfig = !useOrgLevel
	policy.UseOrgLevelConfig = useOrgLevel
	policy.AutoRemdiationOptions = autoRemediationOptionsFromConfig(selectedConfig)

	// Populate SelectedReposFilter from API response
	if selectedConfig.ControlSettings.ApplyIssuePRConfigForAllReposFilter != nil {
		policy.SelectedReposFilter = *selectedConfig.ControlSettings.ApplyIssuePRConfigForAllReposFilter
	}

	return policy, nil
}

// autoRemediationOptionsFromConfig converts a stored config into the resource's
// auto_remediation_options. Lists built from maps are sorted so a config always
// converts to the same value.
func autoRemediationOptionsFromConfig(config policyDrivenPRInternal) AutoRemdiationOptions {
	// Extract feature flags
	enabledHardenRunner := config.ControlChecksConfig["GitHubHostedRunnerShouldBeHardened"].TriggerGithubIssue ||
		config.ControlChecksConfig["GitHubHostedRunnerShouldBeHardened"].TriggerGithubPr
	enabledPinning := config.ControlChecksConfig["ActionsShouldBePinned"].TriggerGithubIssue ||
		config.ControlChecksConfig["ActionsShouldBePinned"].TriggerGithubPr
	enabledTokenPermissions := config.ControlChecksConfig["GithubTokenShouldHaveMinPermission"].TriggerGithubIssue ||
		config.ControlChecksConfig["GithubTokenShouldHaveMinPermission"].TriggerGithubPr
	enabledSecureDocker := config.ControlChecksConfig["SecureDockerFile"].TriggerGithubIssue ||
		config.ControlChecksConfig["SecureDockerFile"].TriggerGithubPr

	// Extract actions to replace (sorted for deterministic ordering)
	actionsToReplace := []string{}
	for action := range config.ControlSettings.ActionsToReplace {
		actionsToReplace = append(actionsToReplace, action)
	}
	sort.Strings(actionsToReplace)

	// Convert update_precommit_file from map to array (sorted for deterministic ordering).
	// The map holds every hook the console knows about, with false for the disabled
	// ones, so only the enabled hooks belong in the list.
	updatePrecommitFiles := []string{}
	for file, enabled := range config.ControlSettings.UpdatePrecommitFile {
		if enabled {
			updatePrecommitFiles = append(updatePrecommitFiles, file)
		}
	}
	sort.Strings(updatePrecommitFiles)

	return AutoRemdiationOptions{
		CreatePR:                                config.TriggerPRInsteadOfIssue,
		CreateIssue:                             !config.TriggerPRInsteadOfIssue,
		CreateGitHubAdvancedSecurityAlert:       config.TriggerGithubAlert,
		HardenGitHubHostedRunner:                enabledHardenRunner,
		PinActionsToSHA:                         enabledPinning,
		RestrictGitHubTokenPermissions:          enabledTokenPermissions,
		SecureDockerFile:                        enabledSecureDocker,
		LabelsToReplace:                         config.ControlSettings.LabelsToReplace,
		ActionsToExemptWhilePinning:             config.ControlSettings.ExemptedActions,
		ImagesToExemptWhilePinning:              config.ControlSettings.ExemptedImages,
		ActionsToReplaceWithStepSecurityActions: actionsToReplace,
		CustomActionsToReplace:                  config.ControlSettings.CustomActionsToReplace,
		ReplaceByMajorTag:                       config.ControlSettings.ReplaceByMajorTag,
		ExemptedFromReplacement:                 config.ControlSettings.ExemptedFromReplacement,
		UpdatePrecommitFile:                     updatePrecommitFiles,
		CustomPrecommitConfig:                   config.ControlSettings.CustomPrecommitConfig,
		PackageEcosystem:                        config.ControlSettings.PackageEcosystem,
		DockerfilePatterns:                      config.ControlSettings.DockerfilePatterns,
		Subtractive:                             config.ControlSettings.Subtractive,
		AddWorkflows:                            config.ControlSettings.AddWorkflows,
		HardenRunnerConfig:                      config.ControlSettings.HardenRunnerConfig,
	}
}

// sameSettingsOptions compares auto_remediation_options by content: list order and the
// difference between an absent and an empty list or map carry no meaning in the API.
var sameSettingsOptions = cmp.Options{
	cmpopts.EquateEmpty(),
	cmpopts.SortSlices(func(a, b string) bool { return a < b }),
	cmpopts.SortSlices(func(a, b DependabotConfig) bool {
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.Interval < b.Interval
	}),
}

// repoSettingsGroup is a set of selected repos that share the same settings.
type repoSettingsGroup struct {
	options AutoRemdiationOptions
	repos   []string
}

// groupReposBySettings groups the selected repos by their settings, in the order the
// repos are listed.
func groupReposBySettings(repos []string, configs map[string]policyDrivenPRInternal) []repoSettingsGroup {
	var groups []repoSettingsGroup
	for _, repo := range repos {
		options := autoRemediationOptionsFromConfig(configs[repo])
		matched := false
		for i := range groups {
			if cmp.Equal(groups[i].options, options, sameSettingsOptions) {
				groups[i].repos = append(groups[i].repos, repo)
				matched = true
				break
			}
		}
		if !matched {
			groups = append(groups, repoSettingsGroup{options: options, repos: []string{repo}})
		}
	}
	return groups
}

// maxReposListedPerGroup bounds how many repos the mixed-settings import error names
// for each group, so an org with thousands of repos still gets a readable message.
const maxReposListedPerGroup = 10

// mixedSettingsImportError explains why repos with different settings cannot be
// imported into one resource. A single resource sends one set of settings to every
// repo it selects, so importing them together would overwrite all but one group on
// the next apply.
func mixedSettingsImportError(owner string, groups []repoSettingsGroup) error {
	var b strings.Builder
	fmt.Fprintf(&b, "the selected repositories in '%s' do not all have the same policy-driven PR settings, "+
		"and one stepsecurity_policy_driven_pr resource applies a single set of settings to every repository it selects. "+
		"Importing them together would overwrite the settings of some repositories on the next apply.\n\n"+
		"Repositories grouped by settings:\n", owner)
	for _, group := range groups {
		listed := group.repos
		more := 0
		if len(listed) > maxReposListedPerGroup {
			more = len(listed) - maxReposListedPerGroup
			listed = listed[:maxReposListedPerGroup]
		}
		fmt.Fprintf(&b, "  - %s", strings.Join(listed, ", "))
		if more > 0 {
			fmt.Fprintf(&b, " and %d more", more)
		}
		fmt.Fprintf(&b, ": %s\n", describeSettings(group.options))
	}
	b.WriteString("\nGroups with the same enabled options differ in other settings, such as exemptions or replacements.\n\n" +
		"To import, give these repositories the same settings in StepSecurity and import again. " +
		"To keep different settings, do not import: declare one stepsecurity_policy_driven_pr resource per group " +
		"with the repositories listed in selected_repos.")
	return errors.New(b.String())
}

// describeSettings names the options a settings group turns on.
func describeSettings(options AutoRemdiationOptions) string {
	var enabled []string
	for _, opt := range []struct {
		name string
		on   bool
	}{
		{"create_pr", options.CreatePR},
		{"create_issue", options.CreateIssue},
		{"create_github_advanced_security_alert", options.CreateGitHubAdvancedSecurityAlert},
		{"harden_github_hosted_runner", options.HardenGitHubHostedRunner},
		{"pin_actions_to_sha", options.PinActionsToSHA},
		{"restrict_github_token_permissions", options.RestrictGitHubTokenPermissions},
		{"secure_docker_file", options.SecureDockerFile},
		{"labels_to_replace", len(options.LabelsToReplace) > 0},
		{"actions_to_replace_with_step_security_actions", len(options.ActionsToReplaceWithStepSecurityActions) > 0},
		{"custom_actions_to_replace", len(options.CustomActionsToReplace) > 0},
		{"update_precommit_file", len(options.UpdatePrecommitFile) > 0},
		{"custom_precommit_config", options.CustomPrecommitConfig != nil},
		{"package_ecosystem", len(options.PackageEcosystem) > 0},
		{"add_workflows", options.AddWorkflows != ""},
		{"harden_runner_config", options.HardenRunnerConfig != nil},
	} {
		if opt.on {
			enabled = append(enabled, opt.name)
		}
	}
	if len(enabled) == 0 {
		return "no options enabled"
	}
	return strings.Join(enabled, ", ")
}

// isConfigEnabled checks if a config has any enabled features
func isConfigEnabled(config policyDrivenPRInternal) bool {
	return config.TriggerGithubAlert ||
		config.TriggerPRInsteadOfIssue ||
		len(config.ControlChecksConfig) > 0
}

// isAppliedToAllRepos reports whether the org-level [all] config is applied to every
// repo. The backend only fans the [all] config out to repos when this flag is set;
// with it off, [all] is just the template for repos that opt into the org config.
func isAppliedToAllRepos(config policyDrivenPRInternal) bool {
	return config.ControlSettings.ApplyIssuePRConfigForAllRepos != nil &&
		*config.ControlSettings.ApplyIssuePRConfigForAllRepos
}

// isRepoSelected reports whether a repo row is part of the policy. A repo is selected
// when it uses either the org-level or its own repo-level config, which is how the
// console decides it; settings left on a row with both flags off do not apply.
func isRepoSelected(config policyDrivenPRInternal) bool {
	return (config.UseOrgLevelConfig || config.UseRepoLevelConfig) && isConfigEnabled(config)
}

func (c *APIClient) DeletePolicyDrivenPRPolicy(ctx context.Context, owner string, repos []string) error {
	for _, repo := range repos {
		if repo == "*" {
			repo = "[all]"
		}
		URI := fmt.Sprintf("%s/v1/github/%s/%s/policy-driven-pr/configs", c.BaseURL, owner, repo)
		if _, err := c.delete(ctx, URI); err != nil {
			return fmt.Errorf("failed to delete config for repo %s: %w", repo, err)
		}
	}

	return nil
}

func (c *APIClient) UpdatePolicyDrivenPRPolicy(ctx context.Context, policy PolicyDrivenPRPolicy, removedRepos []string) error {
	// Remove configs for repos that were removed
	if len(removedRepos) > 0 {
		if err := c.DeletePolicyDrivenPRPolicy(ctx, policy.Owner, removedRepos); err != nil {
			return fmt.Errorf("failed to remove repos from policy: %w", err)
		}
	}

	// Update/create policy for current repos
	if err := c.CreatePolicyDrivenPRPolicy(ctx, policy); err != nil {
		return fmt.Errorf("failed to update policy driven PR policy: %w", err)
	}

	return nil
}
