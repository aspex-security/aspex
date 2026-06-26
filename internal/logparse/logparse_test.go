package logparse_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aspex-security/aspex/internal/logparse"
)

var zeroTime = time.Time{}

func TestParseCursorCleanLog(t *testing.T) {
	f, err := os.Open("../../testdata/logs/cursor/clean_mcp.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := logparse.ParseCursorLogReader(f, zeroTime)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("expected events, got none")
	}
	for _, ev := range events {
		if ev.Client != "cursor" {
			t.Errorf("expected client=cursor, got %q", ev.Client)
		}
	}
}

func TestParseCursorAnomalousLog(t *testing.T) {
	f, err := os.Open("../../testdata/logs/cursor/anomalous_mcp.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := logparse.ParseCursorLogReader(f, zeroTime)
	if err != nil {
		t.Fatal(err)
	}
	toolCalls := 0
	for _, ev := range events {
		if ev.Event == logparse.EventToolsCall {
			toolCalls++
		}
	}
	if toolCalls == 0 {
		t.Error("expected tool call events in anomalous log")
	}
}

func TestParseClaudeAnomalousLog(t *testing.T) {
	f, err := os.Open("../../testdata/logs/claude/anomalous_mcp.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := logparse.ParseClaudeLogReader(f, zeroTime)
	if err != nil {
		t.Fatal(err)
	}
	hasToolCall := false
	for _, ev := range events {
		if ev.Event == logparse.EventToolsCall {
			hasToolCall = true
		}
	}
	if !hasToolCall {
		t.Error("expected tool call events in anomalous Claude log")
	}
}

func TestSinceFilter(t *testing.T) {
	line := `{"timestamp":"2026-06-25T09:00:00Z","level":"info","category":"mcp","serverName":"s","method":"tools/list"}`
	// Event is at 09:00, filter since 10:00 -- should exclude.
	future := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	events, _ := logparse.ParseCursorLogReader(strings.NewReader(line), future)
	if len(events) != 0 {
		t.Errorf("expected 0 events after since filter, got %d", len(events))
	}
	// Filter since 08:00 -- should include.
	past := time.Date(2026, 6, 25, 8, 0, 0, 0, time.UTC)
	events, _ = logparse.ParseCursorLogReader(strings.NewReader(line), past)
	if len(events) != 1 {
		t.Errorf("expected 1 event before since filter, got %d", len(events))
	}
}
