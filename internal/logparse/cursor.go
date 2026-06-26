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

// CursorLogPaths returns the MCP log paths for Cursor on the current OS.
// Tested against Cursor v0.48.x.
func CursorLogPaths() []string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		return []string{filepath.Join(appdata, "Cursor", "logs")}
	}
	if runtime.GOOS == "darwin" {
		return []string{
			filepath.Join(home, ".cursor", "logs"),
			filepath.Join(home, "Library", "Application Support", "Cursor", "logs"),
		}
	}
	return []string{filepath.Join(home, ".cursor", "logs")}
}

// cursorLogEntry is the shape of a structured Cursor MCP log line.
type cursorLogEntry struct {
	Timestamp  string          `json:"timestamp"`
	Level      string          `json:"level"`
	Category   string          `json:"category"`
	ServerName string          `json:"serverName"`
	Method     string          `json:"method"`
	ToolName   string          `json:"toolName"`
	Arguments  json.RawMessage `json:"arguments,omitempty"`
	DurationMS int64           `json:"durationMs,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// ParseCursorLogsDir reads all relevant log files under dir and returns parsed events.
func ParseCursorLogsDir(dir string, since time.Time) ([]Event, error) {
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
		if !strings.Contains(name, "mcp") || !strings.HasSuffix(name, ".log") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		evs, _ := ParseCursorLogReader(f, since)
		f.Close()
		events = append(events, evs...)
	}
	return events, nil
}

// ParseCursorLogReader parses a Cursor MCP log from an io.Reader.
func ParseCursorLogReader(r io.Reader, since time.Time) ([]Event, error) {
	var events []Event
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		ev, ok := parseCursorLine(line, since)
		if ok {
			events = append(events, ev)
		}
	}
	return events, scanner.Err()
}

func parseCursorLine(line string, since time.Time) (Event, bool) {
	var entry cursorLogEntry
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
		Timestamp:  ts,
		Client:     "cursor",
		Server:     entry.ServerName,
		DurationMS: entry.DurationMS,
		Raw:        line,
	}

	switch entry.Method {
	case "initialize":
		ev.Event = EventInitialize
	case "tools/list":
		ev.Event = EventToolsList
	case "tools/call":
		ev.Event = EventToolsCall
		ev.Tool = entry.ToolName
		ev.Args = flattenArgs(entry.Arguments)
	case "resources/read":
		ev.Event = EventResourceRead
	case "prompts/get":
		ev.Event = EventPromptsGet
	default:
		if entry.Error != "" {
			ev.Event = EventError
		} else {
			return Event{}, false
		}
	}

	return ev, true
}

func flattenArgs(raw json.RawMessage) map[string]string {
	if raw == nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case string:
			result[k] = val
		default:
			b, _ := json.Marshal(val)
			result[k] = string(b)
		}
	}
	return result
}
