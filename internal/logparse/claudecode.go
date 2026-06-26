package logparse

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ClaudeCodeLogPaths returns the JSONL session transcript directories for Claude Code CLI.
// Claude Code stores full conversation transcripts at ~/.claude/projects/<encoded-cwd>/*.jsonl.
func ClaudeCodeLogPaths() []string {
	home, _ := os.UserHomeDir()
	return []string{filepath.Join(home, ".claude", "projects")}
}

// ParseClaudeCodeProjectsDir walks all project subdirectories and returns parsed events.
func ParseClaudeCodeProjectsDir(rootDir string, since time.Time) ([]Event, error) {
	entries, err := os.ReadDir(rootDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var events []Event
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		projectDir := filepath.Join(rootDir, e.Name())
		files, err := os.ReadDir(projectDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".jsonl") {
				continue
			}
			fh, err := os.Open(filepath.Join(projectDir, f.Name()))
			if err != nil {
				continue
			}
			evs, parseErr := ParseClaudeCodeReader(fh, since)
			fh.Close()
			if parseErr != nil {
				fmt.Fprintf(os.Stderr, "aspex warning: parse %s: %v\n", filepath.Join(projectDir, f.Name()), parseErr)
			}
			events = append(events, evs...)
		}
	}
	return events, nil
}

// ParseClaudeCodeReader parses a Claude Code JSONL session transcript.
// Each line is a JSON object; tool calls appear as content blocks of type "tool_use"
// inside assistant messages. MCP tools have names prefixed with "mcp__".
func ParseClaudeCodeReader(r io.Reader, since time.Time) ([]Event, error) {
	var events []Event
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		evs, ok := parseClaudeCodeLine(line, since)
		if ok {
			events = append(events, evs...)
		}
	}
	return events, scanner.Err()
}

type claudeCodeLine struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Message   struct {
		Role    string `json:"role"`
		Content []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	} `json:"message"`
}

func parseClaudeCodeLine(line string, since time.Time) ([]Event, bool) {
	var entry claudeCodeLine
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, false
	}
	if entry.Type != "assistant" {
		return nil, false
	}
	if !since.IsZero() && entry.Timestamp.Before(since) {
		return nil, false
	}

	var events []Event
	for _, block := range entry.Message.Content {
		if block.Type != "tool_use" {
			continue
		}
		ev := Event{
			Timestamp: entry.Timestamp,
			Client:    "claude-code",
			Raw:       line,
		}

		if strings.HasPrefix(block.Name, "mcp__") {
			// MCP tool: mcp__<server-id>__<tool-name>
			parts := strings.SplitN(block.Name, "__", 3)
			if len(parts) == 3 {
				ev.Server = parts[1]
				ev.Tool = parts[2]
			} else {
				ev.Tool = block.Name
			}
			ev.Event = EventToolsCall
		} else {
			// Built-in Claude Code tool (Bash, Read, Edit, Write, etc.)
			ev.Server = "claude-code"
			ev.Tool = block.Name
			ev.Event = EventToolsCall
		}

		ev.Args = flattenArgs(block.Input)
		events = append(events, ev)
	}

	return events, len(events) > 0
}
