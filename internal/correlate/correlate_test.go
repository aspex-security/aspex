package correlate

import (
	"testing"
	"time"

	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/rules"
)

func call(server, tool string, args map[string]string, ts time.Time) logparse.Event {
	return logparse.Event{Timestamp: ts, Client: "claude-code", Server: server, Event: logparse.EventToolsCall, Tool: tool, Args: args}
}

func TestSummarizeCountsCallsToolsAndFlags(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	events := []logparse.Event{
		call("postgres", "execute_sql", map[string]string{"sql": "select 1"}, t0),
		call("postgres", "execute_sql", nil, t0.Add(time.Minute)),
		call("postgres", "list_tables", nil, t0.Add(2*time.Minute)),
		// AT001: credential file read - must count as flagged.
		call("filesystem", "read_file", map[string]string{"path": "/Users/x/.aws/credentials"}, t0.Add(3*time.Minute)),
		{Timestamp: t0, Client: "claude-code", Server: "postgres", Event: logparse.EventToolsList},
		{Timestamp: t0, Client: "claude-code", Server: "", Event: logparse.EventToolsCall, Tool: "orphan"},
	}
	act := Summarize(events)

	pg := act["postgres"]
	if pg == nil || pg.Calls != 3 || len(pg.Tools) != 2 || pg.Tools[0] != "execute_sql" {
		t.Fatalf("postgres = %+v", pg)
	}
	if !pg.LastSeen.Equal(t0.Add(2 * time.Minute)) {
		t.Errorf("LastSeen = %v", pg.LastSeen)
	}
	fs := act["filesystem"]
	if fs == nil || fs.Flagged == 0 || fs.MaxSev == "" {
		t.Fatalf("credential read should be flagged: %+v", fs)
	}
	if _, ok := act[""]; ok {
		t.Error("events with no server must be dropped")
	}
}

func TestNormalizeAndMatch(t *testing.T) {
	norm := map[string]string{
		"plugin_slack_slack": "slack-slack",
		"claude_ai_ClickUp":  "clickup",
		"Claude_Browser":     "claude-browser",
		"  Filesystem ":      "filesystem",
		"mcp-server-github":  "github",
	}
	for in, want := range norm {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}

	act := map[string]*Activity{
		"plugin_slack_slack": {Server: "plugin_slack_slack", Calls: 4},
		"claude_ai_ClickUp":  {Server: "claude_ai_ClickUp", Calls: 6},
		"filesystem":         {Server: "filesystem", Calls: 88},
		"slacker-tools":      {Server: "slacker-tools", Calls: 99},
	}
	if a := Match(act, "filesystem"); a == nil || a.Calls != 88 {
		t.Error("exact match failed")
	}
	if a := Match(act, "slack"); a == nil || a.Server != "plugin_slack_slack" {
		t.Errorf("token match failed: %+v", a)
	}
	if a := Match(act, "ClickUp"); a == nil || a.Calls != 6 {
		t.Error("case-insensitive prefix-stripped match failed")
	}
	if a := Match(act, "github"); a != nil {
		t.Errorf("unrelated name must not match, got %+v", a)
	}
	if Match(act, "") != nil {
		t.Error("empty name must not match")
	}
}

func TestIsClientBuiltin(t *testing.T) {
	if !IsClientBuiltin("claude-code") || !IsClientBuiltin("Claude_Code") {
		t.Error("client names are builtin tool surfaces")
	}
	if IsClientBuiltin("filesystem") {
		t.Error("a real server is not builtin")
	}
}

func TestPriority(t *testing.T) {
	crit := rules.SeverityCritical
	if Priority(0, &Activity{Calls: 100}) != 0 {
		t.Error("no static findings -> 0")
	}
	latent := Priority(crit, nil)
	used := Priority(crit, &Activity{Calls: 1})
	flagged := Priority(crit, &Activity{Calls: 1, Flagged: 1})
	if !(latent < used && used < flagged) {
		t.Errorf("ordering broken: latent=%d used=%d flagged=%d", latent, used, flagged)
	}
}
