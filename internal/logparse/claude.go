package logparse

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ClaudeLogPaths returns MCP log paths for Claude Desktop.
func ClaudeLogPaths() []string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		return []string{filepath.Join(os.Getenv("APPDATA"), "Claude", "Logs")}
	case "darwin":
		return []string{filepath.Join(home, "Library", "Logs", "Claude")}
	default:
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
		return []string{filepath.Join(configHome, "Claude", "logs")}
	}
}

// ParseClaudeLogsDir reads all mcp*.log files under dir and returns parsed events.
// Claude Desktop writes plain-text logs in the format:
//
//	TIMESTAMP [level] [ServerName] Message from client: {"method":"tools/call",...}
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
		evs, parseErr := ParseClaudeLogReader(f, since)
		f.Close()
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "aspex warning: parse %s: %v\n", filepath.Join(dir, name), parseErr)
		}
		events = append(events, evs...)
	}
	return events, nil
}

// ParseClaudeLogReader parses Claude Desktop MCP logs.
// Format: `2026-04-29T10:35:35.449Z [info] [ServerName] Message from client: {...json...}`
func ParseClaudeLogReader(r io.Reader, since time.Time) ([]Event, error) {
	var events []Event
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		ev, ok := parseClaudeTextLine(line, since)
		if ok {
			events = append(events, ev)
		}
	}
	return events, scanner.Err()
}

// parseClaudeTextLine parses one line of the Claude Desktop plain-text log format.
func parseClaudeTextLine(line string, since time.Time) (Event, bool) {
	spaceIdx := strings.Index(line, " ")
	if spaceIdx < 0 {
		return Event{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, line[:spaceIdx])
	if err != nil {
		return Event{}, false
	}
	if !since.IsZero() && ts.Before(since) {
		return Event{}, false
	}

	rest := line[spaceIdx+1:]
	server := extractBracketedName(rest)

	clientMsgIdx := strings.Index(rest, "Message from client: ")
	if clientMsgIdx < 0 {
		return Event{}, false
	}
	jsonStr := rest[clientMsgIdx+len("Message from client: "):]

	ev := Event{Timestamp: ts, Client: "claude", Server: server, Raw: line}

	method, toolName, args := parseJSONRPCMethod(jsonStr)
	switch method {
	case "initialize":
		ev.Event = EventInitialize
	case "tools/list":
		ev.Event = EventToolsList
	case "tools/call":
		ev.Event = EventToolsCall
		ev.Tool = toolName
		ev.Args = args
	case "resources/read":
		ev.Event = EventResourceRead
	case "prompts/get":
		ev.Event = EventPromptsGet
	default:
		return Event{}, false
	}

	return ev, true
}
