package provider

import (
	"bytes"

	"gopkg.in/yaml.v3"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// recoverDependabotYAML fills cooldown_yaml and groups_yaml on package ecosystems read
// from the API.
//
// The API parses both strings when a config is written and keeps only the parsed
// cooldown and groups, so a read returns them structured and the YAML text absent.
// Left as is, that reads back as null against the YAML in the configuration, and
// every plan shows an in-place change that applies the same value again.
//
// For each ecosystem whose YAML is absent but whose parsed value is present, the text
// in prior state is kept when it parses to the same value, so the practitioner's own
// formatting survives a refresh. Otherwise, on import or after a change made outside
// Terraform, the value is rendered as YAML. Ecosystems are matched to prior state by
// package name. options_yaml is stored as written and needs no recovery.
func recoverDependabotYAML(ecosystems []stepsecurityapi.DependabotConfig, prior []packageEcosystemModel) []stepsecurityapi.DependabotConfig {
	priorByPackage := make(map[string]packageEcosystemModel, len(prior))
	for _, model := range prior {
		if _, seen := priorByPackage[model.Package.ValueString()]; !seen {
			priorByPackage[model.Package.ValueString()] = model
		}
	}

	out := make([]stepsecurityapi.DependabotConfig, len(ecosystems))
	for i, ecosystem := range ecosystems {
		model, hasPrior := priorByPackage[ecosystem.Package]

		if ecosystem.CoolDownYAML == "" && ecosystem.CoolDown != nil {
			var priorYAML string
			if hasPrior && !model.CoolDownYAML.IsNull() && !model.CoolDownYAML.IsUnknown() {
				priorYAML = model.CoolDownYAML.ValueString()
			}
			ecosystem.CoolDownYAML = recoverYAML(priorYAML, *ecosystem.CoolDown, new(stepsecurityapi.DependabotCoolDown))
		}

		if ecosystem.GroupsYAML == "" && len(ecosystem.Groups) > 0 {
			var priorYAML string
			if hasPrior && !model.GroupsYAML.IsNull() && !model.GroupsYAML.IsUnknown() {
				priorYAML = model.GroupsYAML.ValueString()
			}
			ecosystem.GroupsYAML = recoverYAML(priorYAML, ecosystem.Groups, new(map[string]stepsecurityapi.DependabotGroup))
		}

		out[i] = ecosystem
	}
	return out
}

// recoverYAML returns priorYAML when it parses into the same value as parsed, and
// otherwise renders parsed as YAML. target is a pointer to a zero value of parsed's
// type, used to decode priorYAML.
func recoverYAML[T any](priorYAML string, parsed T, target *T) string {
	if priorYAML != "" {
		if err := yaml.Unmarshal([]byte(priorYAML), target); err == nil &&
			canonicalYAML(*target) == canonicalYAML(parsed) {
			return priorYAML
		}
	}
	return canonicalYAML(parsed)
}

// canonicalYAML renders v with Dependabot's keys, two-space indentation and map keys
// sorted, so two values compare equal exactly when they mean the same thing.
func canonicalYAML(v any) string {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(v); err != nil {
		return ""
	}
	_ = encoder.Close()
	return buf.String()
}
