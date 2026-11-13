terraform {
  required_providers {
    stepsecurity = {
      source = "step-security/stepsecurity"
    }
  }
}

provider "stepsecurity" {
  api_key  = "xxxxxxxx" # can also be set as env variable STEP_SECURITY_API_KEY
  customer = "abcdefg"  # can also be set as env variable STEP_SECURITY_CUSTOMER
}

# Action Policy Example (all_orgs) - Allows only specific GitHub Actions across all orgs
resource "stepsecurity_github_run_policy" "action_policy_all_orgs" {
  owner    = "my-org"
  name     = "Allowed Actions Policy - All Orgs"
  all_orgs = true

  policy_config = {
    owner                = "my-org"
    name                 = "Allowed Actions Policy - All Orgs"
    enable_action_policy = true
    allowed_actions = {
      "actions/checkout"            = "allow"
      "step-security/harden-runner" = "allow"
      "actions/setup-node"          = "allow"
      "actions/setup-python"        = "allow"
      "actions/upload-artifact"     = "allow"
    }
  }
}

# Action Policy Example (all_repos) - Allows only specific GitHub Actions across all repos
resource "stepsecurity_github_run_policy" "action_policy_all_repos" {
  owner     = "my-org"
  name      = "Allowed Actions Policy - All Repos"
  all_repos = true

  policy_config = {
    owner                = "my-org"
    name                 = "Allowed Actions Policy - All Repos"
    enable_action_policy = true
    allowed_actions = {
      "actions/checkout"            = "allow"
      "step-security/harden-runner" = "allow"
      "actions/setup-node"          = "allow"
      "actions/setup-python"        = "allow"
      "actions/upload-artifact"     = "allow"
    }
  }
}

# Action Policy Example (dry_run) - Test action policy without enforcement
resource "stepsecurity_github_run_policy" "action_policy_dry_run" {
  owner     = "my-org"
  name      = "Action Policy - Dry Run"
  all_repos = true

  policy_config = {
    owner                = "my-org"
    name                 = "Action Policy - Dry Run"
    enable_action_policy = true
    allowed_actions = {
      "actions/checkout"            = "allow"
      "step-security/harden-runner" = "allow"
    }
    is_dry_run = true
  }
}

# Runner Label Policy Example (all_repos) - Restricts which runners can be used
resource "stepsecurity_github_run_policy" "runner_policy_all_repos" {
  owner     = "my-org"
  name      = "Runner Label Policy - All Repos"
  all_repos = true

  policy_config = {
    owner                    = "my-org"
    name                     = "Runner Label Policy - All Repos"
    enable_runs_on_policy    = true
    disallowed_runner_labels = ["self-hosted", "windows-latest", "macos-latest"]
  }
}

# Runner Label Policy Example (generic labels) - Blocks every GitHub-hosted
# standard runner via the enable_standard_runner_labels boolean: the standard
# label set (ubuntu-latest, windows-latest, macos-*, arm variants, ...) is
# added to disallowed_runner_labels at evaluation time and kept up to date
# automatically. Additional custom labels can still be listed.
resource "stepsecurity_github_run_policy" "runner_policy_generic_labels" {
  owner     = "my-org"
  name      = "Runner Label Policy - Generic Labels"
  all_repos = true

  policy_config = {
    owner                         = "my-org"
    name                          = "Runner Label Policy - Generic Labels"
    enable_runs_on_policy         = true
    enable_standard_runner_labels = true
    disallowed_runner_labels      = ["self-hosted"]
  }
}

# Runner Label Policy Example (all_orgs) - Restricts which runners can be used across all orgs
resource "stepsecurity_github_run_policy" "runner_policy_all_orgs" {
  owner    = "my-org"
  name     = "Runner Label Policy - All Orgs"
  all_orgs = true

  policy_config = {
    owner                    = "my-org"
    name                     = "Runner Label Policy - All Orgs"
    enable_runs_on_policy    = true
    disallowed_runner_labels = ["self-hosted", "windows-latest"]
  }
}

# Runner Label Policy Example (dry_run) - Test runner policy without enforcement
resource "stepsecurity_github_run_policy" "runner_policy_dry_run" {
  owner     = "my-org"
  name      = "Runner Label Policy - Dry Run"
  all_repos = true

  policy_config = {
    owner                    = "my-org"
    name                     = "Runner Label Policy - Dry Run"
    enable_runs_on_policy    = true
    disallowed_runner_labels = ["self-hosted"]
    is_dry_run               = true
  }
}

# Harden Runner Policy Example (targeted) - Enforces Harden Runner only on jobs whose runs-on matches the listed labels
resource "stepsecurity_github_run_policy" "harden_runner_policy_targeted" {
  owner     = "my-org"
  name      = "Harden Runner Policy - Targeted"
  all_repos = true

  policy_config = {
    owner                       = "my-org"
    name                        = "Harden Runner Policy - Targeted"
    enable_harden_runner_policy = true
    harden_runner_target_labels = ["ubuntu-step-security", "linux-secure"]
  }
}

# Harden Runner Policy Example (generic labels) - Enforces Harden Runner on
# every job running on a GitHub-hosted standard runner via the
# enable_standard_runner_labels boolean: the standard label set (ubuntu-latest,
# windows-latest, macos-*, arm variants, ...) becomes the target labels at
# evaluation time and stays current automatically. Self-hosted jobs are not
# targeted; add harden_runner_target_labels entries to also target custom
# runners.
resource "stepsecurity_github_run_policy" "harden_runner_policy_generic_labels" {
  owner     = "my-org"
  name      = "Harden Runner Policy - Generic Labels"
  all_repos = true

  policy_config = {
    owner                         = "my-org"
    name                          = "Harden Runner Policy - Generic Labels"
    enable_harden_runner_policy   = true
    enable_standard_runner_labels = true
  }
}

# Harden Runner Policy Example (all jobs) - Empty harden_runner_target_labels applies the policy to every job
resource "stepsecurity_github_run_policy" "harden_runner_policy_all_jobs" {
  owner     = "my-org"
  name      = "Harden Runner Policy - All Jobs"
  all_repos = true

  policy_config = {
    owner                       = "my-org"
    name                        = "Harden Runner Policy - All Jobs"
    enable_harden_runner_policy = true
    harden_runner_target_labels = []
  }
}

# Harden Runner Policy Example (excluded runners) - Applies to every job except those on
# runners that cannot run Harden Runner. A job is skipped when its runs-on matches any
# excluded label; "*" wildcards are supported, but a lone "*" is rejected.
resource "stepsecurity_github_run_policy" "harden_runner_policy_excluded_labels" {
  owner     = "my-org"
  name      = "Harden Runner Policy - Excluded Runners"
  all_repos = true

  policy_config = {
    owner                         = "my-org"
    name                          = "Harden Runner Policy - Excluded Runners"
    enable_harden_runner_policy   = true
    harden_runner_target_labels   = []
    harden_runner_excluded_labels = ["self-hosted-gpu", "custom-runner-*"]
  }
}

# Harden Runner Policy Example (custom actions) - Accepts additional Harden Runner-equivalent actions
resource "stepsecurity_github_run_policy" "harden_runner_policy_custom_actions" {
  owner     = "my-org"
  name      = "Harden Runner Policy - Custom Actions"
  all_repos = true

  policy_config = {
    owner                        = "my-org"
    name                         = "Harden Runner Policy - Custom Actions"
    enable_harden_runner_policy  = true
    harden_runner_target_labels  = []
    harden_runner_custom_actions = ["my-org/harden-runner"]
  }
}

# Secrets Policy Example (all_orgs) - Prevents secrets from being exfiltrated across all orgs
resource "stepsecurity_github_run_policy" "secrets_policy_all_orgs" {
  owner    = "my-org"
  name     = "Secrets Policy - All Orgs"
  all_orgs = true

  policy_config = {
    owner                 = "my-org"
    name                  = "Secrets Policy - All Orgs"
    enable_secrets_policy = true
    exempted_users        = ["dependabot[bot]", "renovate[bot]"]
  }
}

# Secrets Policy Example (all_repos) - Prevents secrets from being exfiltrated across all repos
resource "stepsecurity_github_run_policy" "secrets_policy_all_repos" {
  owner     = "my-org"
  name      = "Secrets Policy - All Repos"
  all_repos = true

  policy_config = {
    owner                 = "my-org"
    name                  = "Secrets Policy - All Repos"
    enable_secrets_policy = true
    exempted_users        = ["dependabot[bot]", "github_username"]
  }
}

# Secrets Policy Example (dry_run) - Test secrets policy without enforcement
resource "stepsecurity_github_run_policy" "secrets_policy_dry_run" {
  owner     = "my-org"
  name      = "Secrets Policy - Dry Run"
  all_repos = true

  policy_config = {
    owner                 = "my-org"
    name                  = "Secrets Policy - Dry Run"
    enable_secrets_policy = true
    is_dry_run            = true
  }
}

# Secrets Policy Example (bulk-secrets-only mode + custom PR comment) -
# Restricts enforcement to high-risk bulk secret-exposure attempts rather than all
# secret references, and customizes the comment posted when a run is blocked.
resource "stepsecurity_github_run_policy" "secrets_policy_bulk_only" {
  owner     = "my-org"
  name      = "Secrets Policy - Bulk Only"
  all_repos = true

  policy_config = {
    owner                 = "my-org"
    name                  = "Secrets Policy - Bulk Only"
    enable_secrets_policy = true

    # When true, restrict the secrets policy to high-risk bulk secret-exposure
    # attempts instead of all secret references. See the StepSecurity
    # run-policies documentation for details.
    bulk_secrets_only_mode = true

    exempted_users = ["dependabot[bot]", "renovate[bot]"]

    # Optional: override the comment posted on the pull request when this policy
    # blocks a run. Supported placeholders: {{workflow_run_url}}, {{policy_type}},
    # {{policy_name}}, {{policy_details}}, {{remediation}}, {{actor}}, {{owner}},
    # {{repo}}, {{docs_url}}. Leave unset or "" to use the built-in comment.
    pr_comment_template = <<-EOT
    ## {{policy_type}} Violation

    [This workflow run]({{workflow_run_url}}) was blocked by the **{{policy_name}}** run policy.

    {{policy_details}}
    {{remediation}}

    For more information, see [StepSecurity's documentation]({{docs_url}}).
    EOT
  }
}

# Compromised Actions Policy Example (all_orgs) - Blocks known compromised actions across all orgs
resource "stepsecurity_github_run_policy" "compromised_actions_policy_all_orgs" {
  owner    = "my-org"
  name     = "Compromised Actions Policy - All Orgs"
  all_orgs = true

  policy_config = {
    owner                             = "my-org"
    name                              = "Compromised Actions Policy - All Orgs"
    enable_compromised_actions_policy = true
  }
}

# Compromised Actions Policy Example (all_repos) - Blocks known compromised actions across all repos
resource "stepsecurity_github_run_policy" "compromised_actions_policy_all_repos" {
  owner     = "my-org"
  name      = "Compromised Actions Policy - All Repos"
  all_repos = true

  policy_config = {
    owner                             = "my-org"
    name                              = "Compromised Actions Policy - All Repos"
    enable_compromised_actions_policy = true
  }
}

# Compromised Actions Policy Example (dry_run) - Test compromised actions policy without enforcement
resource "stepsecurity_github_run_policy" "compromised_actions_policy_dry_run" {
  owner     = "my-org"
  name      = "Compromised Actions Policy - Dry Run"
  all_repos = true

  policy_config = {
    owner                             = "my-org"
    name                              = "Compromised Actions Policy - Dry Run"
    enable_compromised_actions_policy = true
    is_dry_run                        = true
  }
}

# Repository-Specific Policy Example - Applies action policy to specific repositories only
resource "stepsecurity_github_run_policy" "repo_specific_action_policy" {
  owner        = "my-org"
  name         = "Critical Repositories Action Policy"
  repositories = ["critical-app", "payment-service", "user-auth"]

  policy_config = {
    owner                = "my-org"
    name                 = "Critical Repositories Action Policy"
    enable_action_policy = true
    allowed_actions = {
      "actions/checkout"            = "allow"
      "step-security/harden-runner" = "allow"
      "actions/setup-node"          = "allow"
    }
  }
}

# Repository-Specific Policy Example - Applies runner policy to specific repositories only
resource "stepsecurity_github_run_policy" "repo_specific_runner_policy" {
  owner        = "my-org"
  name         = "Critical Repositories Runner Policy"
  repositories = ["critical-app", "payment-service"]

  policy_config = {
    owner                    = "my-org"
    name                     = "Critical Repositories Runner Policy"
    enable_runs_on_policy    = true
    disallowed_runner_labels = ["self-hosted", "windows-latest"]
  }
}

# Allowed Actions Policy Example (all_repos, pinned actions enforcement)
resource "stepsecurity_github_run_policy" "pinned_actions_policy" {
  owner     = "my-org"
  name      = "Allowed Actions Policy - Pinned Actions Enforcement"
  all_repos = true

  policy_config = {
    owner                           = "my-org"
    name                            = "Allowed Actions Policy - Pinned Actions Enforcement"
    enable_action_policy            = true
    require_pinned_actions          = true
    actions_to_exempt_while_pinning = ["actions/*", "my-trusted-org/*"]
    allowed_actions = {
      "actions/checkout"            = "allow"
      "step-security/harden-runner" = "allow"
    }
  }
}

# Allowed Actions Policy Example (pinning only, every action allowed)
# require_pinned_actions is a sub-feature of the allowed actions policy, so
# enable_action_policy must be true and the allow list is evaluated alongside it.
# Use the global wildcard "*/*" to allow every action, leaving the pinning
# requirement as the only thing this policy enforces.
resource "stepsecurity_github_run_policy" "pinning_only_policy" {
  owner     = "my-org"
  name      = "Allowed Actions Policy - Pinning Only"
  all_repos = true

  policy_config = {
    owner                  = "my-org"
    name                   = "Allowed Actions Policy - Pinning Only"
    enable_action_policy   = true
    require_pinned_actions = true
    allowed_actions = {
      "*/*" = "allow"
    }
  }
}

# Allowed Actions Policy Example (dry_run, pinned actions enforcement)
resource "stepsecurity_github_run_policy" "pinned_actions_policy_dry_run" {
  owner     = "my-org"
  name      = "Allowed Actions Policy - Pinned Actions Enforcement - Dry Run"
  all_repos = true

  policy_config = {
    owner                  = "my-org"
    name                   = "Allowed Actions Policy - Pinned Actions Enforcement - Dry Run"
    enable_action_policy   = true
    require_pinned_actions = true
    allowed_actions = {
      "actions/checkout"            = "allow"
      "step-security/harden-runner" = "allow"
    }
    is_dry_run = true
  }
}

# Runner Label Policy Example (allowed mode) - Instead of a block list, only
# permit jobs whose runners are on an allow list. runs_on_mode defaults to
# "disallowed" (block list, using disallowed_runner_labels); set it to "allowed"
# to switch to allow-list behavior. Plain labels are matched verbatim, while
# runs-on.com constraints are matched per dimension: a runs-on token of the form
# key=value is allowed when the key is unconfigured, or when its value is listed
# for that key.
resource "stepsecurity_github_run_policy" "runner_policy_allowed_mode" {
  owner     = "my-org"
  name      = "Runner Label Policy - Allowed Mode"
  all_repos = true

  policy_config = {
    owner                 = "my-org"
    name                  = "Runner Label Policy - Allowed Mode"
    enable_runs_on_policy = true
    runs_on_mode          = "allowed"
    allowed_runner_labels = ["ubuntu-latest", "ubuntu-22.04"]
    allowed_runner_constraints = {
      family = ["c7a", "m7a"]
      cpu    = ["2", "4", "8"]
    }
  }
}

# Harden Runner Policy Example (opt-in checks) - In addition to requiring Harden
# Runner on targeted jobs, require every targeted job to read its configuration
# from the policy store (use-policy-store: true on the Harden Runner step; the
# legacy policy: input does not satisfy this check), and block jobs that run
# entirely inside a job-level container: (Harden Runner cannot monitor a fully
# containerized job on GitHub-hosted standard runners; container steps are fine).
resource "stepsecurity_github_run_policy" "harden_runner_policy_checks" {
  owner     = "my-org"
  name      = "Harden Runner Policy - Policy Store and Container"
  all_repos = true

  policy_config = {
    owner                       = "my-org"
    name                        = "Harden Runner Policy - Policy Store and Container"
    enable_harden_runner_policy = true
    harden_runner_target_labels = []
    require_policy_store        = true
    block_job_container         = true
  }
}

# Secrets Policy Example (analyze default branch) - By default the secrets policy
# only evaluates non-default-branch runs; enable secrets_analyze_default_branch to
# also evaluate runs on the repository default branch. Pairs well with
# bulk_secrets_only_mode to limit enforcement to high-risk bulk exposure.
resource "stepsecurity_github_run_policy" "secrets_policy_default_branch" {
  owner     = "my-org"
  name      = "Secrets Policy - Analyze Default Branch"
  all_repos = true

  policy_config = {
    owner                          = "my-org"
    name                           = "Secrets Policy - Analyze Default Branch"
    enable_secrets_policy          = true
    secrets_analyze_default_branch = true
    bulk_secrets_only_mode         = true
  }
}

# Custom Property Rule Example - Applies to repositories by GitHub custom
# property, including repositories tagged later (the console's "Repositories
# with a custom property" scope). Rows after the first combine with the row
# above using "and" (default) or "or"; "and" binds first. Property names ignore
# case; values match exactly, and a row matches when the repository has any
# of its values. This rule reads:
# (sensitive_app_level is Tier 1) OR (compliance_scope is pci or sox).
resource "stepsecurity_github_run_policy" "tier1_secrets_policy" {
  owner = "my-org"
  name  = "Secrets Policy - Tier 1 Repositories"

  custom_property_rule = [
    {
      property = "sensitive_app_level"
      values   = ["Tier 1"]
    },
    {
      combine  = "or"
      property = "compliance_scope"
      values   = ["pci", "sox"]
    },
  ]

  policy_config = {
    owner                 = "my-org"
    name                  = "Secrets Policy - Tier 1 Repositories"
    enable_secrets_policy = true
  }
}

# For importing existing run policy to terraform state
# this will be helpful to manage existing policy using terraform
# alternative to this is to use terraform import command
import {
  to = stepsecurity_github_run_policy.action_policy_all_orgs
  id = "my-org/ACTUAL_POLICY_ID"
}
