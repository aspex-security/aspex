package rules

import "testing"

// The embedded YAML is the source of truth for catalog rules. If it is
// malformed or a severity is invalid, init() panics and every test fails; these
// tests assert the loaded result is well-formed so a bad contribution is caught
// in CI rather than at a user's terminal.

func TestCatalogLoadedFromYAML(t *testing.T) {
	if len(toolCatalogRules) < 100 {
		t.Errorf("expected the tool catalog to load from YAML, got %d rules", len(toolCatalogRules))
	}
	if len(resourceCatalogRules) == 0 || len(promptCatalogRules) == 0 {
		t.Error("resource and prompt catalogs should load from YAML")
	}
}

func TestEveryCatalogRuleIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	checkCommon := func(id, name, mapping string, sev Severity) {
		if id == "" || name == "" || mapping == "" {
			t.Errorf("rule %q: id, name, and mapping are required", id)
		}
		if seen[id] {
			t.Errorf("duplicate rule id %q", id)
		}
		seen[id] = true
		if sev < SeverityInfo || sev > SeverityCritical {
			t.Errorf("rule %q: severity out of range", id)
		}
	}
	for _, r := range toolCatalogRules {
		checkCommon(r.ruleID, r.name, r.mapping, r.sev)
		if len(r.toolNames)+len(r.descWords)+len(r.schemaKeys) == 0 {
			t.Errorf("tool rule %q has no matchers; it can never fire", r.ruleID)
		}
	}
	for _, r := range resourceCatalogRules {
		checkCommon(r.ruleID, r.name, r.mapping, r.sev)
		if len(r.uriWords)+len(r.mimeTypes) == 0 {
			t.Errorf("resource rule %q has no matchers", r.ruleID)
		}
	}
	for _, r := range promptCatalogRules {
		checkCommon(r.ruleID, r.name, r.mapping, r.sev)
		if len(r.descWords)+len(r.nameWords) == 0 && r.minLen == 0 {
			t.Errorf("prompt rule %q has no matchers", r.ruleID)
		}
	}
}
