// Package testenv builds a fake home directory populated with MCP client
// configs and agent logs, so end-to-end tests can exercise discovery, scanning,
// policy, trace parsing, and correlation exactly as a user would, without
// touching the real machine. Only paths that resolve identically on macOS,
// Linux, and Windows are used: ~/.claude.json and ~/.claude/projects/.
package testenv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixture servers in ~/.claude.json and what a static scan should say about them.
const (
	ServerGitHub     = "github"     // plaintext GITHUB_TOKEN in env -> MCP006 (critical)
	ServerKB         = "kb"         // http:// remote, no auth -> MCP021 (critical), MCP010 (medium)
	ServerFilesystem = "filesystem" // pinned and scoped -> clean in static mode
	// A server agents call that appears in no config (a claude.ai connector).
	ServerUnscored = "Claude_Browser"
)

// Event counts written by FakeHome, so tests can assert exact totals.
const (
	CallsGitHub     = 3
	CallsUnscored   = 5
	CallsFilesystem = 1 // reads ~/.aws/credentials -> AT001 flagged
	CallsBuiltin    = 2 // Claude Code's own Bash tool; not an MCP server
	CallsMCP        = CallsGitHub + CallsUnscored + CallsFilesystem
)

// LogTime is the timestamp of every fixture event. Tests choose a window that includes it.
var LogTime = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

// FakeHome creates the fixture home, points HOME and USERPROFILE at it for the
// duration of the test, and returns its path.
func FakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	// Keep XDG lookups inside the sandbox on Linux.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))

	writeJSON(t, filepath.Join(home, ".claude.json"), map[string]any{
		"numStartups": 7,
		"mcpServers": map[string]any{
			ServerGitHub: map[string]any{
				"command": "npx",
				"args":    []string{"-y", "@modelcontextprotocol/server-github@2025.4.8"},
				"env":     map[string]string{"GITHUB_TOKEN": "ghp_fixture_not_real"},
			},
			ServerKB: map[string]any{
				"type": "http",
				"url":  "http://kb.internal.example:8080/sse",
			},
			ServerFilesystem: map[string]any{
				"command": "npx",
				"args":    []string{"-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/Users/dev/projects"},
			},
		},
	})

	var lines []string
	add := func(tool string, input map[string]any) {
		lines = append(lines, toolUseLine(tool, input))
	}
	for i := 0; i < CallsGitHub; i++ {
		add("mcp__"+ServerGitHub+"__search_repositories", map[string]any{"query": "aspex"})
	}
	for i := 0; i < CallsUnscored; i++ {
		add("mcp__"+ServerUnscored+"__navigate", map[string]any{"url": "https://docs.example.com"})
	}
	add("mcp__"+ServerFilesystem+"__read_file", map[string]any{"path": "/Users/dev/.aws/credentials"})
	for i := 0; i < CallsBuiltin; i++ {
		add("Bash", map[string]any{"command": "go test ./..."})
	}
	logDir := filepath.Join(home, ".claude", "projects", "-Users-dev-work")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "session.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return home
}

func toolUseLine(tool string, input map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"type":      "assistant",
		"timestamp": LogTime.Format(time.RFC3339),
		"message": map[string]any{
			"role": "assistant",
			"content": []map[string]any{
				{"type": "tool_use", "name": tool, "input": input},
			},
		},
	})
	return string(b)
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
