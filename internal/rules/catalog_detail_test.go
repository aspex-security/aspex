package rules

import (
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/mcpclient"
)

// A catalog match must justify itself by the capability it detects, not by the
// raw substring that matched. "name contains 'r_eval'" reads like a bug and
// makes a correct finding look crude; the human-facing detail must not leak the
// pattern. The pattern is kept in Evidence for debugging.
func TestCatalogDetailDoesNotLeakMatchedPattern(t *testing.T) {
	tool := &mcpclient.Tool{Name: "browser_evaluate", Description: "Run JS in the page."}
	findings := EvalToolCatalog(tool)

	var got *Finding
	for i := range findings {
		if findings[i].RuleID == "MCP034" {
			got = &findings[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("expected MCP034 (REPL/eval) to fire on browser_evaluate; got %+v", findings)
	}
	// The old, embarrassing format was "name contains 'r_eval'". The detail must
	// no longer expose the raw pattern that way. (The tool name itself may
	// happen to contain the pattern's characters; what matters is we don't
	// present the match as "contains '<pattern>'".)
	if strings.Contains(got.Detail, "contains '") {
		t.Errorf("detail leaks the matched substring: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, "consistent with") {
		t.Errorf("detail should describe the capability, got: %q", got.Detail)
	}
	if !strings.Contains(got.Detail, "browser_evaluate") {
		t.Errorf("detail should still name the tool: %q", got.Detail)
	}
	// The matched pattern is preserved in evidence, not the detail.
	var evHasPattern bool
	for _, e := range got.Evidence {
		if strings.Contains(e.Text, "pattern") {
			evHasPattern = true
		}
	}
	if !evHasPattern {
		t.Errorf("expected the matched pattern to be recorded in evidence for debugging; evidence: %+v", got.Evidence)
	}
}

func TestLowerFirstLeavesAcronyms(t *testing.T) {
	cases := map[string]string{
		"Language REPL or eval capability": "language REPL or eval capability",
		"SSRF capability":                  "SSRF capability", // acronym untouched
		"":                                 "",
	}
	for in, want := range cases {
		if got := lowerFirst(in); got != want {
			t.Errorf("lowerFirst(%q) = %q, want %q", in, got, want)
		}
	}
}
