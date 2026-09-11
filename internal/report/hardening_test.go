package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/mcpclient"
	"github.com/aspex-security/aspex/internal/report"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/score"
)

// Aspex renders adversarial content: tool names and descriptions come from
// servers Aspex does not trust. A malicious server must not be able to inject
// terminal control sequences (color, cursor moves, title-setting, hyperlinks)
// into a user's terminal through the scan report.
func TestScanReportStripsTerminalControlFromUntrustedContent(t *testing.T) {
	evil := "\x1b[31mRED\x1b[0m\x1b]0;pwned\x07\x1b[2J" + "shell exec run_command" // also trips a rule
	srv := &inspect.Server{
		Entry: discover.ServerEntry{Name: "evil\x1b[1m", Client: "claude\x07", ConfigPath: "/c"},
		Tools: []mcpclient.Tool{{
			Name:        "run_command\x1b[5m",
			Description: evil,
			InputSchema: json.RawMessage(`{"type":"object","properties":{"command":{"type":"string"}}}`),
		}},
	}
	findings := rules.EvalServer(srv)
	sc := score.ScoreServer(findings)
	var buf bytes.Buffer
	report.PrintScanReport(&buf, report.ScanReport{
		Version: "t", Servers: []*inspect.Server{srv}, Scores: []score.ServerScore{sc},
		Overall: score.ScoreOverall([]score.ServerScore{sc}), NoColor: true, Explain: true,
	})
	out := buf.String()
	// No raw ESC or BEL anywhere in the rendered report.
	if strings.ContainsRune(out, '\x1b') || strings.ContainsRune(out, '\x07') {
		t.Errorf("terminal control sequence survived into the report:\n%q", out)
	}
	// The visible text is still there (stripped, not dropped).
	if !strings.Contains(out, "run_command") {
		t.Error("tool name text should remain after sanitizing")
	}
}

func TestSanitizeForTerminal(t *testing.T) {
	cases := map[string]string{
		"\x1b[31mred\x1b[0m":                   "red",
		"a\x07b":                               "ab",
		"tab\tkept\nnl":                        "tab\tkept\nnl",
		"\x1b]8;;http://x\x07link\x1b]8;;\x07": "link", // OSC 8 hyperlink
		"plain":                                "plain",
	}
	for in, want := range cases {
		if got := report.SanitizeForTerminal(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
