package snapshot

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aspex-security/aspex/internal/testenv"
)

// tenYears comfortably includes testenv.LogTime regardless of when tests run.
const tenYears = 10 * 365 * 24 * time.Hour

func TestBuildJoinsConfigsWithLogs(t *testing.T) {
	testenv.FakeHome(t)
	t.Chdir(t.TempDir())

	s := Build(context.Background(), "test", tenYears)

	if len(s.Servers) != 3 {
		t.Fatalf("expected 3 configured servers, got %d", len(s.Servers))
	}
	if s.Calls != testenv.CallsMCP {
		t.Errorf("Calls = %d, want %d (built-in tools must be excluded)", s.Calls, testenv.CallsMCP)
	}
	if s.UnscoredCalls != testenv.CallsUnscored || len(s.Unscored) != 1 || s.Unscored[0].Server != testenv.ServerUnscored {
		t.Errorf("unscored = %d calls / %+v", s.UnscoredCalls, s.Unscored)
	}
	if s.Flagged == 0 || s.TopRule == "" {
		t.Errorf("credential read should produce a flagged event and a top rule: flagged=%d top=%q", s.Flagged, s.TopRule)
	}
	var gh *ServerLine
	for i := range s.Servers {
		if s.Servers[i].Name == testenv.ServerGitHub {
			gh = &s.Servers[i]
		}
	}
	if gh == nil || gh.Calls != testenv.CallsGitHub {
		t.Errorf("github line = %+v, want %d calls", gh, testenv.CallsGitHub)
	}
	// Worst-first ordering: the first line has a static finding.
	if s.Servers[0].MaxSev == 0 {
		t.Errorf("servers should be sorted worst-first, got %+v", s.Servers[0])
	}
}

func TestHeadlinesRenderAndShareCard(t *testing.T) {
	testenv.FakeHome(t)
	t.Chdir(t.TempDir())
	s := Build(context.Background(), "test", tenYears)

	h := s.Headlines()
	if len(h) < 3 {
		t.Fatalf("expected at least 3 headlines, got %v", h)
	}
	if !strings.Contains(h[0], "tool calls") || !strings.Contains(h[1], "no security scan had ever checked") {
		t.Errorf("headlines do not tell the story: %v", h)
	}

	var buf bytes.Buffer
	s.Render(&buf, true)
	for _, want := range []string{"Your AI agents", testenv.ServerUnscored, "In use, never scanned", "aspex share"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("render missing %q", want)
		}
	}

	card := s.ShareCard()
	// The card links to the project on github.com; that is not a server name leaking.
	body := strings.ReplaceAll(card, "https://github.com/aspex-security/aspex", "")
	for _, leak := range []string{testenv.ServerGitHub, testenv.ServerUnscored, testenv.ServerKB, "/Users/dev"} {
		if strings.Contains(body, leak) {
			t.Errorf("share card must not contain %q:\n%s", leak, card)
		}
	}
	if !strings.Contains(card, "brew install aspex-security/tap/aspex") {
		t.Error("share card should tell people how to check their own")
	}
}

func TestBuildWithNoActivity(t *testing.T) {
	testenv.FakeHome(t)
	t.Chdir(t.TempDir())
	// A window that ends before the fixture events exist.
	s := Build(context.Background(), "test", time.Hour)
	if s.Events != 0 || s.Calls != 0 {
		t.Fatalf("expected no events in a 1h window, got %d/%d", s.Events, s.Calls)
	}
	h := s.Headlines()
	if !strings.Contains(h[0], "No agent activity") {
		t.Errorf("empty-window headline wrong: %v", h)
	}
	var buf bytes.Buffer
	s.Render(&buf, true) // must not panic with no activity
}
