package rules_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/mcpclient"
	"github.com/aspex-security/aspex/internal/rules"
)

// corpusFixture is one server in testdata/corpus. Malicious fixtures declare
// the rule IDs Aspex MUST fire; benign fixtures declare the highest severity
// Aspex MAY report. Together they are the tool's detection and
// false-positive contract - a rule change that breaks either fails CI.
type corpusFixture struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Entry       discover.ServerEntry `json:"entry"`
	Tools       []mcpclient.Tool     `json:"tools"`
	Resources   []mcpclient.Resource `json:"resources,omitempty"`
	// Malicious only: every listed rule must fire.
	ExpectRules []string `json:"expect_rules,omitempty"`
	// Benign only: no finding may exceed this severity. Default "medium".
	MaxSeverity string `json:"max_severity,omitempty"`
}

func loadCorpus(t *testing.T, kind string) []corpusFixture {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "corpus", kind, "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no %s corpus fixtures found: %v", kind, err)
	}
	var out []corpusFixture
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var fx corpusFixture
		if err := json.Unmarshal(data, &fx); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if fx.Name == "" {
			fx.Name = strings.TrimSuffix(filepath.Base(p), ".json")
		}
		out = append(out, fx)
	}
	return out
}

func evalFixture(fx corpusFixture) []rules.Finding {
	srv := &inspect.Server{Entry: fx.Entry, Tools: fx.Tools, Resources: fx.Resources}
	return rules.EvalServer(srv)
}

func parseSev(t *testing.T, s string) rules.Severity {
	t.Helper()
	switch strings.ToLower(s) {
	case "", "medium":
		return rules.SeverityMedium
	case "low":
		return rules.SeverityLow
	case "high":
		return rules.SeverityHigh
	case "critical":
		return rules.SeverityCritical
	}
	t.Fatalf("bad max_severity %q", s)
	return 0
}

// TestCorpusMalicious proves Aspex catches every known-bad pattern in the corpus.
func TestCorpusMalicious(t *testing.T) {
	for _, fx := range loadCorpus(t, "malicious") {
		t.Run(fx.Name, func(t *testing.T) {
			if len(fx.ExpectRules) == 0 {
				t.Fatal("malicious fixture must declare expect_rules")
			}
			findings := evalFixture(fx)
			got := map[string]bool{}
			for _, f := range findings {
				got[f.RuleID] = true
			}
			for _, want := range fx.ExpectRules {
				if !got[want] {
					t.Errorf("expected %s to fire; fired: %v", want, keys(got))
				}
			}
		})
	}
}

// TestCorpusBenign proves Aspex does not cry wolf on popular, well-behaved servers.
func TestCorpusBenign(t *testing.T) {
	for _, fx := range loadCorpus(t, "benign") {
		t.Run(fx.Name, func(t *testing.T) {
			max := parseSev(t, fx.MaxSeverity)
			for _, f := range evalFixture(fx) {
				if f.Severity > max {
					t.Errorf("false positive: %s (%s) at %s exceeds allowed %s - %s",
						f.RuleID, f.Name, f.Severity, max, f.Detail)
				}
			}
		})
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
