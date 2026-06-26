package discover_test

import (
	"testing"

	"github.com/aspex-security/aspex/internal/discover"
)

func TestParseClaudeDesktopConfig_Clean(t *testing.T) {
	entries, err := discover.ParseConfigFile(discover.ClientClaudeDesktop, "../../testdata/configs/clean_claude.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 servers, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Client != discover.ClientClaudeDesktop {
			t.Errorf("expected client=%s, got %s", discover.ClientClaudeDesktop, e.Client)
		}
		if e.Command == "" {
			t.Errorf("server %q: expected non-empty command", e.Name)
		}
	}
}

func TestParseClaudeDesktopConfig_Risky(t *testing.T) {
	entries, err := discover.ParseConfigFile(discover.ClientClaudeDesktop, "../../testdata/configs/risky_claude.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 servers, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Name == "filesystem-mcp" {
			if len(e.EnvKeys) == 0 {
				t.Error("expected env keys for filesystem-mcp")
			}
			// Values must never appear, only keys.
			for _, k := range e.EnvKeys {
				if k == "" {
					t.Error("env key is empty")
				}
			}
		}
	}
}

func TestParseNonExistentFile_ReturnsNil(t *testing.T) {
	entries, err := discover.ParseConfigFile(discover.ClientClaudeDesktop, "/nonexistent/path/config.json")
	if err != nil {
		t.Errorf("expected nil error for missing file, got %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no entries for missing file, got %d", len(entries))
	}
}
