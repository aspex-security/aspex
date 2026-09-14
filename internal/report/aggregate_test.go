package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/score"
)

// A rule that fires on many tools of one server (e.g. MCP018 long descriptions)
// must collapse to a single line, so it does not bury the criticals. Rules that
// fire once or twice stay in full.
func TestServerFindingsAggregateRepeatedRule(t *testing.T) {
	var findings []rules.Finding
	tools := []string{"read_file", "write_file", "write_pdf", "move_file", "list_directory"}
	for _, tl := range tools {
		findings = append(findings, rules.Finding{
			RuleID: "MCP018", Name: "Suspiciously long tool description", Severity: rules.SeverityMedium,
			Detail: "Tool '" + tl + "' description is 3000 characters.",
			Fix:    "Review the full description manually.",
		})
	}
	// A distinct single finding must still print in full.
	findings = append(findings, rules.Finding{
		RuleID: "MCP003", Name: "Dangerous capability: shell/exec (schema pattern)", Severity: rules.SeverityCritical,
		Detail: "Tool 'start_process' schema implies command execution.",
		Fix:    "Remove this tool grant.",
	})

	srv := &inspect.Server{Entry: discover.ServerEntry{Name: "desktop-commander", Client: "cursor"}}
	sc := score.ServerScore{Score: 0, Band: score.BandHighRisk, Findings: findings}

	var buf bytes.Buffer
	printServerBlock(&buf, newColorizer(true), colorBrRed, srv, sc, false)
	out := buf.String()

	// Aggregated: one count marker, the tool list, and exactly one MCP018 line.
	if !strings.Contains(out, "×5") {
		t.Errorf("expected an aggregate count ×5 for MCP018, got:\n%s", out)
	}
	if strings.Count(out, "MCP018") != 1 {
		t.Errorf("MCP018 should appear once (aggregated), got %d:\n%s", strings.Count(out, "MCP018"), out)
	}
	if !strings.Contains(out, "tools:") || !strings.Contains(out, "read_file") {
		t.Errorf("aggregate should list the tools, got:\n%s", out)
	}
	// The individual long-description details must NOT each be printed.
	if strings.Contains(out, "is 3000 characters") {
		t.Errorf("aggregated findings should not repeat each per-tool detail:\n%s", out)
	}
	// The singleton critical prints in full.
	if !strings.Contains(out, "MCP003") || !strings.Contains(out, "command execution") {
		t.Errorf("singleton critical should print in full, got:\n%s", out)
	}
}
