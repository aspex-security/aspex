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

func TestParseRooClineConfig(t *testing.T) {
	entries, err := discover.ParseConfigFile(discover.ClientRooCline, "../../testdata/configs/clean_roo_cline.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 server, got %d", len(entries))
	}
	if entries[0].Client != discover.ClientRooCline {
		t.Errorf("expected client=%s, got %s", discover.ClientRooCline, entries[0].Client)
	}
	if entries[0].Name != "memory" {
		t.Errorf("expected name=memory, got %s", entries[0].Name)
	}
}

func TestParseContinueConfig(t *testing.T) {
	entries, err := discover.ParseConfigFile(discover.ClientContinue, "../../testdata/configs/clean_continue.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Client != discover.ClientContinue {
			t.Errorf("expected client=%s, got %s", discover.ClientContinue, e.Client)
		}
		if e.Command == "" {
			t.Errorf("server %q: expected non-empty command", e.Name)
		}
	}
}

func TestParseZedConfig(t *testing.T) {
	entries, err := discover.ParseConfigFile(discover.ClientZed, "../../testdata/configs/clean_zed.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Client != discover.ClientZed {
			t.Errorf("expected client=%s, got %s", discover.ClientZed, e.Client)
		}
		if e.Command == "" {
			t.Errorf("server %q: expected non-empty command (path)", e.Name)
		}
	}
	// Verify env keys are captured for the filesystem server.
	for _, e := range entries {
		if e.Name == "filesystem" && len(e.EnvKeys) == 0 {
			t.Error("filesystem server: expected env keys")
		}
	}
}

func TestParseClaudeCodeConfig_UserAndProjectScopes(t *testing.T) {
	entries, err := discover.ParseConfigFile(discover.ClientClaudeCode, "../../testdata/configs/clean_claude_code.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 servers (1 user + 1 project scope), got %d: %+v", len(entries), entries)
	}
	byName := map[string]discover.ServerEntry{}
	for _, e := range entries {
		byName[e.Name] = e
		if e.Client != discover.ClientClaudeCode {
			t.Errorf("%s: client = %q", e.Name, e.Client)
		}
	}
	gh, ok := byName["github"]
	if !ok || gh.Command != "npx" || gh.Description != "" {
		t.Errorf("user-scope github entry wrong: %+v", gh)
	}
	pg, ok := byName["postgres"]
	if !ok || pg.Description != "project: /Users/dev/work/api" {
		t.Errorf("project-scope postgres entry wrong: %+v", pg)
	}
	if len(pg.EnvKeys) != 1 || pg.EnvKeys[0] != "PGPASSWORD" {
		t.Errorf("env keys should be names only: %+v", pg.EnvKeys)
	}
}

func TestParseClaudeCodePluginMCP(t *testing.T) {
	entries, err := discover.ParseConfigFile(discover.ClientClaudeCode, "../../testdata/configs/plugin_claude_code.mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "slack" || entries[0].URL != "https://mcp.slack.com/mcp" {
		t.Fatalf("plugin http server not parsed: %+v", entries)
	}
	if !entries[0].OAuth {
		t.Error("oauth block should mark the server as authenticated")
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
