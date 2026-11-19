package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"gopkg.in/yaml.v3"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// fakePolicyDrivenPRBackend is a stand-in for the policy-driven PR API that stores
// exactly what the provider writes and hands it back verbatim on read.
//
// The point is to isolate the provider. The POST body (policyDrivenPRConfigOptions) and
// the GET response's policy_driven_pr_configuration (policyDrivenPRInternal) are the same
// object, so echoing the stored write is what a lossless backend looks like. Any plan that
// is non-empty after a clean apply against this backend is therefore a provider-side
// round-trip defect, not backend behaviour.
type fakePolicyDrivenPRBackend struct {
	mu      sync.Mutex
	configs map[string]json.RawMessage // repo -> stored config
	v2      bool
	// onStore, when set, edits each written config before it is stored, so a test can
	// model data the real backend holds but the provider never writes.
	onStore func(config map[string]any)
}

func newFakePolicyDrivenPRBackend(v2Enabled bool) *fakePolicyDrivenPRBackend {
	return &fakePolicyDrivenPRBackend{
		configs: map[string]json.RawMessage{},
		v2:      v2Enabled,
	}
}

func (b *fakePolicyDrivenPRBackend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Paths: /v1/github/{owner}/{repo}/policy-driven-pr/configs
	//        /v1/github/{owner}/{repo}/actions/subscription-status
	parts := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(parts) < 4 {
		http.Error(w, "unexpected path", http.StatusNotFound)
		return
	}
	owner, repo := parts[2], parts[3]
	tail := strings.Join(parts[4:], "/")

	w.Header().Set("Content-Type", "application/json")

	switch {
	case tail == "actions/subscription-status":
		fmt.Fprintf(w, `{"tier":"enterprise","status":"active","app_feature_flags":{"is_policy_driven_pr_v2_enabled":%t}}`, b.v2)

	case tail == "policy-driven-pr/configs" && req.Method == http.MethodPost:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		if b.onStore != nil {
			var config map[string]any
			if err := json.Unmarshal(body, &config); err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			b.onStore(config)
			if body, err = json.Marshal(config); err != nil {
				http.Error(w, "unencodable body", http.StatusInternalServerError)
				return
			}
		}
		b.mu.Lock()
		b.configs[repo] = json.RawMessage(body)
		b.mu.Unlock()
		fmt.Fprint(w, `{"status":200,"state":"completed"}`)

	case tail == "policy-driven-pr/configs" && req.Method == http.MethodGet:
		b.mu.Lock()
		stored, ok := b.configs[repo]
		b.mu.Unlock()
		if !ok {
			fmt.Fprint(w, `{"repos":[]}`)
			return
		}
		fmt.Fprintf(w, `{"repos":[{"full_repo_name":"%s/%s","policy_driven_pr_configuration":%s}]}`, owner, repo, stored)

	case tail == "policy-driven-pr/configs" && req.Method == http.MethodDelete:
		b.mu.Lock()
		delete(b.configs, repo)
		b.mu.Unlock()
		fmt.Fprint(w, `{}`)

	default:
		http.Error(w, "unexpected request: "+req.Method+" "+req.URL.Path, http.StatusNotFound)
	}
}

// phase7Fixture mirrors the complex-scenario fixture from the integration-test suite
// (terraform/scenarios/policy_driven_pr_suite.go, GetComplexFixture), which is the one
// still reporting "Plan is not stable" after a clean apply.
const phase7Fixture = `
resource "stepsecurity_policy_driven_pr" "test" {
  owner          = "step-terraform-tests"
  selected_repos = ["test-repo-one"]

  auto_remediation_options = {
    create_pr = true

    harden_github_hosted_runner = true

    pin_actions_to_sha              = true
    actions_to_exempt_while_pinning = ["actions/*", "github/*"]

    restrict_github_token_permissions = true

    actions_to_replace_with_step_security_actions = [
      "amannn/action-semantic-pull-request",
      "crazy-max/ghaction-import-gpg",
      "fkirc/skip-duplicate-actions"
    ]

    add_workflows = "https://github.com/step-security/secure-repo"

    update_precommit_file = ["gitleaks", "shellcheck", "trailing-whitespace"]

    secure_docker_file = true

    package_ecosystem = [
      {
        package  = "npm"
        interval = "daily"
      },
      {
        package  = "pip"
        interval = "weekly"
      }
    ]
  }
}
`

func testAccPolicyDrivenPRAgainstFake(t *testing.T, backend *fakePolicyDrivenPRBackend, config string) {
	t.Helper()
	// The harness plans again after applying and fails the step when that plan is
	// non-empty, which is the same assertion the integration test's idempotency check
	// makes.
	testAccPolicyDrivenPRStepsAgainstFake(t, backend, resource.TestStep{Config: config})
}

// testAccPolicyDrivenPRStepsAgainstFake runs the given steps against backend.
func testAccPolicyDrivenPRStepsAgainstFake(t *testing.T, backend *fakePolicyDrivenPRBackend, steps ...resource.TestStep) {
	t.Helper()

	// Resolve a Terraform CLI before enabling acceptance mode, and pin it via
	// TF_ACC_TERRAFORM_PATH so the harness uses it directly.
	//
	// Without this the harness falls back to downloading a CLI through hc-install, which
	// fails on any runner that has no terraform installed - currently with "unable to
	// verify checksums signature: openpgp: key expired", because the HashiCorp release
	// signing key embedded in hc-install v0.9.2 has expired. These tests are otherwise
	// hermetic (the backend is an httptest server), so skipping when there is no CLI
	// keeps `go test ./...` offline and self-contained rather than failing on a network
	// download nobody asked for.
	tfPath := os.Getenv("TF_ACC_TERRAFORM_PATH")
	if tfPath == "" {
		found, err := exec.LookPath("terraform")
		if err != nil {
			t.Skip("terraform CLI not found in PATH; set TF_ACC_TERRAFORM_PATH to run this test")
		}
		tfPath = found
	}

	server := httptest.NewServer(backend)
	t.Cleanup(server.Close)

	t.Setenv("TF_ACC", "1")
	t.Setenv("TF_ACC_TERRAFORM_PATH", tfPath)
	t.Setenv("STEP_SECURITY_API_BASE_URL", server.URL)
	t.Setenv("STEP_SECURITY_API_KEY", "test-key")
	t.Setenv("STEP_SECURITY_CUSTOMER", "test-customer")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

// TestAccPolicyDrivenPRPhase7PlanIsEmptyAfterApply reproduces the integration suite's
// Phase 7 idempotency check against a lossless backend. Terraform reported "Plan: 0 to
// add, 1 to change, 0 to destroy" with every attribute rendered as unchanged, which points
// at a value the provider writes back in a form the configuration cannot produce: the
// package_ecosystem entries came back with cooldown_yaml and groups_yaml as "" where the
// configuration holds null.
func TestAccPolicyDrivenPRPhase7PlanIsEmptyAfterApply(t *testing.T) {
	testAccPolicyDrivenPRAgainstFake(t, newFakePolicyDrivenPRBackend(true), phase7Fixture)
}

// unsortedListsFixture is the configuration from
// terraform-provider-stepsecurity#47: an update_precommit_file whose order is not
// alphabetical, which is what the sort in #78 alone could not converge on.
const unsortedListsFixture = `
resource "stepsecurity_policy_driven_pr" "test" {
  owner          = "step-terraform-tests"
  selected_repos = ["test-repo-one"]

  auto_remediation_options = {
    create_pr                         = true
    pin_actions_to_sha                = true
    restrict_github_token_permissions = true
    harden_github_hosted_runner       = true
    secure_docker_file                = true

    update_precommit_file = [
      "eslint",
      "gitleaks",
      "php-lint-all",
      "shellcheck",
      "trailing-whitespace",
      "end-of-file-fixer",
    ]

    actions_to_replace_with_step_security_actions = [
      "fkirc/skip-duplicate-actions",
      "amannn/action-semantic-pull-request",
    ]

    actions_to_exempt_while_pinning = ["github/*", "actions/*"]
  }
}
`

// dependabotYAMLFixture holds cooldown_yaml and groups_yaml in a non-canonical form:
// keys out of order, mixed quoting, four-space indentation. The backend keeps none of
// that text, so the read has to recover it from the parsed values.
const dependabotYAMLFixture = `
resource "stepsecurity_policy_driven_pr" "test" {
  owner          = "step-terraform-tests"
  selected_repos = ["test-repo-one"]

  auto_remediation_options = {
    create_pr          = true
    pin_actions_to_sha = true

    package_ecosystem = [
      {
        package       = "npm"
        interval      = "daily"
        cooldown_yaml = "include:\n    - '*'\ndefault-days: 5\nsemver-major-days: 30\n"
        groups_yaml   = "development-dependencies:\n    patterns: [\"*\"]\n    dependency-type: development\nproduction-dependencies:\n    update-types:\n        - minor\n        - patch\n    dependency-type: production\n"
        options_yaml  = "time: \"09:00\"\nopen-pull-requests-limit: 10\n"
      },
      {
        package  = "pip"
        interval = "weekly"
      }
    ]
  }
}
`

// withParsedDependabotYAML makes the fake store package_ecosystem entries the way the
// real backend does: cooldown_yaml and groups_yaml are parsed into cooldown and groups
// (with the API's Go field names as JSON keys) and the YAML text is dropped;
// options_yaml is kept as written.
func withParsedDependabotYAML(backend *fakePolicyDrivenPRBackend) *fakePolicyDrivenPRBackend {
	backend.onStore = func(config map[string]any) {
		settings, _ := config["control_settings"].(map[string]any)
		ecosystems, _ := settings["package_ecosystem"].([]any)
		for _, raw := range ecosystems {
			entry, _ := raw.(map[string]any)
			if entry == nil {
				continue
			}
			if text, _ := entry["cooldown_yaml"].(string); text != "" {
				var cooldown stepsecurityapi.DependabotCoolDown
				if err := yaml.Unmarshal([]byte(text), &cooldown); err != nil {
					panic(err)
				}
				entry["cooldown"] = jsonRoundTrip(cooldown)
				delete(entry, "cooldown_yaml")
			}
			if text, _ := entry["groups_yaml"].(string); text != "" {
				var groups map[string]stepsecurityapi.DependabotGroup
				if err := yaml.Unmarshal([]byte(text), &groups); err != nil {
					panic(err)
				}
				entry["groups"] = jsonRoundTrip(groups)
				delete(entry, "groups_yaml")
			}
		}
	}
	return backend
}

// jsonRoundTrip returns v as the generic value its JSON encoding decodes to.
func jsonRoundTrip(v any) any {
	encoded, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out any
	if err := json.Unmarshal(encoded, &out); err != nil {
		panic(err)
	}
	return out
}

// TestAccPolicyDrivenPRDependabotYAMLPlanIsEmptyAfterApply is the case a practitioner hit
// on v0.0.50: every plan after apply showed an in-place change on groups_yaml. The
// backend returns cooldown and groups parsed and never the YAML, so the provider read
// them as null and re-applied the configuration's text each time.
func TestAccPolicyDrivenPRDependabotYAMLPlanIsEmptyAfterApply(t *testing.T) {
	testAccPolicyDrivenPRAgainstFake(t, withParsedDependabotYAML(newFakePolicyDrivenPRBackend(true)), dependabotYAMLFixture)
}

// TestAccPolicyDrivenPRUnsortedListsPlanIsEmptyAfterApply is the end-to-end version of
// issue #47: the practitioner's list order is not alphabetical, so the read has to realign
// to it rather than merely being self-consistent.
func TestAccPolicyDrivenPRUnsortedListsPlanIsEmptyAfterApply(t *testing.T) {
	testAccPolicyDrivenPRAgainstFake(t, newFakePolicyDrivenPRBackend(true), unsortedListsFixture)
}

// withConsolePrecommitHooks makes the fake store update_precommit_file the way the
// console does once its pre-commit settings have been opened: every known hook is
// present, and only the ones the provider asked for are true.
func withConsolePrecommitHooks(backend *fakePolicyDrivenPRBackend) *fakePolicyDrivenPRBackend {
	known := []string{"end-of-file-fixer", "eslint", "gitleaks", "php-lint-all", "shellcheck", "trailing-whitespace"}
	backend.onStore = func(config map[string]any) {
		settings, _ := config["control_settings"].(map[string]any)
		if settings == nil {
			settings = map[string]any{}
			config["control_settings"] = settings
		}
		hooks, _ := settings["update_precommit_file"].(map[string]any)
		if hooks == nil {
			hooks = map[string]any{}
		}
		for _, hook := range known {
			if _, ok := hooks[hook]; !ok {
				hooks[hook] = false
			}
		}
		settings["update_precommit_file"] = hooks
	}
	return backend
}

const noPrecommitHooksFixture = `
resource "stepsecurity_policy_driven_pr" "test" {
  owner          = "step-terraform-tests"
  selected_repos = ["test-repo-one"]

  auto_remediation_options = {
    create_pr             = true
    pin_actions_to_sha    = true
    update_precommit_file = []
  }
}
`

const somePrecommitHooksFixture = `
resource "stepsecurity_policy_driven_pr" "test" {
  owner          = "step-terraform-tests"
  selected_repos = ["test-repo-one"]

  auto_remediation_options = {
    create_pr             = true
    pin_actions_to_sha    = true
    update_precommit_file = ["shellcheck", "gitleaks"]
  }
}
`

// TestAccPolicyDrivenPRDisabledPrecommitHooksPlanIsEmpty: hooks stored as false were read
// back as enabled, so a configuration with no hooks drifted on every plan once the
// console had saved its hook list.
func TestAccPolicyDrivenPRDisabledPrecommitHooksPlanIsEmpty(t *testing.T) {
	testAccPolicyDrivenPRAgainstFake(t, withConsolePrecommitHooks(newFakePolicyDrivenPRBackend(true)), noPrecommitHooksFixture)
}

// TestAccPolicyDrivenPRMixedPrecommitHooksPlanIsEmpty: with some hooks enabled and the rest
// stored as false, only the enabled ones are read back.
func TestAccPolicyDrivenPRMixedPrecommitHooksPlanIsEmpty(t *testing.T) {
	testAccPolicyDrivenPRAgainstFake(t, withConsolePrecommitHooks(newFakePolicyDrivenPRBackend(true)), somePrecommitHooksFixture)
}

func dockerfilePatternsFixture(patterns string) string {
	return fmt.Sprintf(`
resource "stepsecurity_policy_driven_pr" "test" {
  owner          = "step-terraform-tests"
  selected_repos = ["test-repo-one"]

  auto_remediation_options = {
    create_pr           = true
    secure_docker_file  = true
    dockerfile_patterns = %s
  }
}
`, patterns)
}

// TestAccPolicyDrivenPRDockerfilePatternsPlanIsEmptyAfterApply: real patterns round-trip,
// and a reordered or duplicated list is the same set, so the plan stays clean.
func TestAccPolicyDrivenPRDockerfilePatternsPlanIsEmptyAfterApply(t *testing.T) {
	testAccPolicyDrivenPRAgainstFake(t, newFakePolicyDrivenPRBackend(true),
		dockerfilePatternsFixture(`["Dockerfile.*", "Containerfile", "Dockerfile.*"]`))
}

// TestAccPolicyDrivenPREmptyDockerfilePatternsIsRejected: the API does not return an
// empty list, so dockerfile_patterns = [] read back as null and never settled. It is
// rejected at plan time instead; leaving the attribute out means no extra patterns.
func TestAccPolicyDrivenPREmptyDockerfilePatternsIsRejected(t *testing.T) {
	testAccPolicyDrivenPRStepsAgainstFake(t, newFakePolicyDrivenPRBackend(true), resource.TestStep{
		Config:      dockerfilePatternsFixture(`[]`),
		ExpectError: regexp.MustCompile(`Invalid Attribute Value`),
	})
}

// TestAccPolicyDrivenPREmptyDependabotYAMLIsRejected: an empty cooldown_yaml, groups_yaml
// or options_yaml is never sent to the API and reads back as null, so accepting it left a
// diff on every plan. It is rejected at plan time instead.
func TestAccPolicyDrivenPREmptyDependabotYAMLIsRejected(t *testing.T) {
	for _, attr := range []string{"cooldown_yaml", "groups_yaml", "options_yaml"} {
		t.Run(attr, func(t *testing.T) {
			config := fmt.Sprintf(`
resource "stepsecurity_policy_driven_pr" "test" {
  owner          = "step-terraform-tests"
  selected_repos = ["test-repo-one"]

  auto_remediation_options = {
    create_pr = true
    package_ecosystem = [
      { package = "npm", interval = "daily", %s = "" }
    ]
  }
}
`, attr)
			testAccPolicyDrivenPRStepsAgainstFake(t, newFakePolicyDrivenPRBackend(true), resource.TestStep{
				Config:      config,
				ExpectError: regexp.MustCompile(`Invalid Attribute Value Length`),
			})
		})
	}
}
