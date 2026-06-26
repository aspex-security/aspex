package logparse

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// claudeLogEntry represents a single JSON line from Claude Desktop MCP logs.
type claudeLogEntry struct {
	Level     string          `json:"level"`
	Message   string          `json:"message"`
	Timestamp string          `json:"timestamp"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// ClaudeLogPaths returns the MCP log paths for Claude Desktop on the current OS.
func ClaudeLogPaths() []string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		return []string{filepath.Join(appdata, "Claude", "Logs")}
	}
	if runtime.GOOS == "darwin" {
		return []string{filepath.Join(home, "Library", "Logs", "Claude")}
	}
	// Linux
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(home, ".config")
	}
	return []string{filepath.Join(configHome, "Claude", "logs")}
}

// ParseClaudeLogsDir reads all mcp*.log files under dir and returns parsed events.
func ParseClaudeLogsDir(dir string, since time.Time) ([]Event, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var events []Event
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "mcp") || !strings.HasSuffix(name, ".log") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		evs, _ := ParseClaudeLogReader(f, since)
		f.Close()
		events = append(events, evs...)
	}
	return events, nil
}

// ParseClaudeLogReader parses a Claude Desktop MCP log from an io.Reader.
// Tested against Claude Desktop v0.10.x log format.
func ParseClaudeLogReader(r io.Reader, since time.Time) ([]Event, error) {
	var events []Event
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		ev, ok := parseClaudeLine(line, since)
		if ok {
			events = append(events, ev)
		}
	}
	return events, scanner.Err()
}

func parseClaudeLine(line string, since time.Time) (Event, bool) {
	var entry claudeLogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return Event{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, entry.Timestamp)
	if err != nil {
		ts = time.Time{}
	}
	if !since.IsZero() && ts.Before(since) {
		return Event{}, false
	}

	ev := Event{
		Timestamp: ts,
		Client:    "claude",
		Raw:       line,
	}

	msg := entry.Message
	switch {
	case strings.Contains(msg, "initialize"):
		ev.Event = EventInitialize
	case strings.Contains(msg, "tools/list"):
		ev.Event = EventToolsList
	case strings.Contains(msg, "tools/call"):
		ev.Event = EventToolsCall
		parseClaudeToolCall(&ev, entry.Data)
	case strings.Contains(msg, "resources/read"):
		ev.Event = EventResourceRead
	case strings.Contains(msg, "prompts/get"):
		ev.Event = EventPromptsGet
	case strings.Contains(msg, "error") || entry.Level == "error":
		ev.Event = EventError
	case strings.Contains(msg, "exit") || strings.Contains(msg, "closed"):
		ev.Event = EventServerExit
	default:
		return Event{}, false
	}

	// Extract server name from message heuristic: "[server-name]" or "server: name".
	if name := extractBracketedName(msg); name != "" {
		ev.Server = name
	}

	return ev, true
}

func parseClaudeToolCall(ev *Event, data json.RawMessage) {
	if data == nil {
		return
	}
	var d struct {
		ToolName  string            `json:"toolName"`
		Arguments map[string]string `json:"arguments"`
		ServerName string           `json:"serverName"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return
	}
	ev.Tool = d.ToolName
	ev.Args = d.Arguments
	if d.ServerName != "" {
		ev.Server = d.ServerName
	}
}

func extractBracketedName(s string) string {
	start := strings.Index(s, "[")
	end := strings.Index(s, "]")
	if start >= 0 && end > start {
		return s[start+1 : end]
	}
	return ""
}
