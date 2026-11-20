package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	stepsecurityapi "github.com/step-security/terraform-provider-stepsecurity/internal/stepsecurity-api"
)

// The API returns cooldown and groups parsed. A read must hand back the practitioner's
// own YAML when it means the same thing, whatever its key order, quoting or indentation,
// and render YAML only when there is nothing in state to keep or the value changed.
func TestRecoverDependabotYAMLKeepsEquivalentStateText(t *testing.T) {
	fromAPI := []stepsecurityapi.DependabotConfig{{
		Package:  "npm",
		Interval: "daily",
		CoolDown: &stepsecurityapi.DependabotCoolDown{DefaultDays: 5, Include: []string{"*"}},
		Groups: map[string]stepsecurityapi.DependabotGroup{
			"production-dependencies":  {DependencyType: "production", UpdateTypes: []string{"minor", "patch"}},
			"development-dependencies": {DependencyType: "development", Patterns: []string{"*"}},
		},
		OptionsYAML: "time: \"09:00\"\n",
	}}

	// Not the canonical rendering: different key order, quoting and indentation.
	stateCoolDown := "include:\n    - '*'\ndefault-days: 5\n"
	stateGroups := "development-dependencies:\n    patterns: [\"*\"]\n    dependency-type: development\nproduction-dependencies:\n    update-types:\n        - minor\n        - patch\n    dependency-type: production\n"
	prior := []packageEcosystemModel{{
		Package:      types.StringValue("npm"),
		Interval:     types.StringValue("daily"),
		CoolDownYAML: types.StringValue(stateCoolDown),
		GroupsYAML:   types.StringValue(stateGroups),
	}}

	got := recoverDependabotYAML(fromAPI, prior)
	if got[0].CoolDownYAML != stateCoolDown {
		t.Errorf("cooldown_yaml: state text must be kept when equivalent, got %q", got[0].CoolDownYAML)
	}
	if got[0].GroupsYAML != stateGroups {
		t.Errorf("groups_yaml: state text must be kept when equivalent, got %q", got[0].GroupsYAML)
	}
	if got[0].OptionsYAML != "time: \"09:00\"\n" {
		t.Errorf("options_yaml must pass through untouched, got %q", got[0].OptionsYAML)
	}
}

func TestRecoverDependabotYAMLRendersWhenStateDiffersOrIsAbsent(t *testing.T) {
	fromAPI := []stepsecurityapi.DependabotConfig{{
		Package:  "pip",
		Interval: "weekly",
		CoolDown: &stepsecurityapi.DependabotCoolDown{DefaultDays: 3},
		Groups:   map[string]stepsecurityapi.DependabotGroup{"all": {Patterns: []string{"*"}}},
	}}

	wantCoolDown := "default-days: 3\n"
	wantGroups := "all:\n  patterns:\n    - '*'\n"

	// No prior state, as on import.
	got := recoverDependabotYAML(fromAPI, nil)
	if got[0].CoolDownYAML != wantCoolDown || got[0].GroupsYAML != wantGroups {
		t.Errorf("import must render YAML, got cooldown %q groups %q", got[0].CoolDownYAML, got[0].GroupsYAML)
	}

	// Prior state holds a different value: the API wins and the change shows.
	prior := []packageEcosystemModel{{
		Package:      types.StringValue("pip"),
		Interval:     types.StringValue("weekly"),
		CoolDownYAML: types.StringValue("default-days: 10\n"),
		GroupsYAML:   types.StringValue("all:\n  patterns:\n    - 'requests*'\n"),
	}}
	got = recoverDependabotYAML(fromAPI, prior)
	if got[0].CoolDownYAML != wantCoolDown || got[0].GroupsYAML != wantGroups {
		t.Errorf("a changed value must be rendered from the API, got cooldown %q groups %q", got[0].CoolDownYAML, got[0].GroupsYAML)
	}

	// Nothing parsed on the API side: the strings stay absent, as for an entry that
	// never had cooldown or groups.
	plain := recoverDependabotYAML([]stepsecurityapi.DependabotConfig{{Package: "npm", Interval: "daily"}}, prior)
	if plain[0].CoolDownYAML != "" || plain[0].GroupsYAML != "" {
		t.Errorf("an entry without cooldown or groups must stay without YAML, got %+v", plain[0])
	}
}
