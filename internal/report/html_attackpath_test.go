package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/report"
	"github.com/aspex-security/aspex/internal/score"
)

// The HTML report renders attack-path and blast-radius fields that originate
// from untrusted server metadata. html/template must escape them: a server
// name or step must never inject markup or script into the shared report.
func TestHTMLReportEscapesAttackPathContent(t *testing.T) {
	out := report.JSONScanOutput{
		Version: "t",
		Overall: score.OverallScore{Score: 39, Band: "HIGH RISK", High: 1},
		ScoreCapReason: `critical attack path <script>alert(1)</script>`,
		AttackPaths: []attackpath.AttackChain{{
			ID:          "AP001",
			Name:        `Exfil <img src=x onerror=alert(1)>`,
			Severity:    "critical",
			Confidence:  "medium",
			Description: "composed path",
			Servers:     []string{`filesystem"><b>`, "browser"},
			Steps:       []string{"instruction", `reads </div><script>x</script>`},
			Impact:      "credentials could leave the machine",
			Remediation: "scope the filesystem root",
		}},
		BlastRadius: &report.BlastRadius{
			Level: "HIGH",
			Why: []report.BlastReason{
				{Present: true, Text: `reads creds <b>bold</b>`},
				{Present: false, Text: "command execution"},
			},
		},
	}

	var buf bytes.Buffer
	if err := report.WriteHTMLScan(&buf, out); err != nil {
		t.Fatalf("WriteHTMLScan: %v", err)
	}
	html := buf.String()

	// The visible text survives (escaped, not dropped).
	for _, want := range []string{"AP001", "Exfil", "browser", "credentials could leave", "command execution"} {
		if !strings.Contains(html, want) {
			t.Errorf("expected %q in report", want)
		}
	}
	// No raw injected markup: the dangerous substrings must be entity-escaped.
	for _, bad := range []string{"<script>alert(1)</script>", "<img src=x onerror", `filesystem"><b>`, "</div><script>x</script>", "<b>bold</b>"} {
		if strings.Contains(html, bad) {
			t.Errorf("unescaped untrusted content leaked into report: %q", bad)
		}
	}
}
