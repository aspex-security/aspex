package logparse

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ClineLogPaths returns the task storage directories for Cline (claude-dev VS Code extension).
// Cline stores each task's API conversation history as JSON under the extension's globalStorage.
func ClineLogPaths() []string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		return []string{
			filepath.Join(appdata, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "tasks"),
		}
	case "darwin":
		return []string{
			filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "tasks"),
		}
	default:
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
		return []string{
			filepath.Join(configHome, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "tasks"),
		}
	}
}

// RooCodeLogPaths returns task storage directories for Roo Code (rooveterinaryinc.roo-cline).
// Roo Code is a fork of Cline with the same storage structure under a different extension ID.
func RooCodeLogPaths() []string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		return []string{
			filepath.Join(appdata, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "tasks"),
		}
	case "darwin":
		return []string{
			filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "tasks"),
		}
	default:
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
		return []string{
			filepath.Join(configHome, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "tasks"),
		}
	}
}

// ParseClineTasksDir walks the Cline tasks directory and returns parsed MCP events.
// Each task is a subdirectory containing api_conversation_history.json.
func ParseClineTasksDir(dir string, since time.Time) ([]Event, error) {
	return parseClineCompatTasksDir(dir, "cline", since)
}

// ParseRooCodeTasksDir walks the Roo Code tasks directory and returns parsed MCP events.
func ParseRooCodeTasksDir(dir string, since time.Time) ([]Event, error) {
	return parseClineCompatTasksDir(dir, "roo-cline", since)
}

func parseClineCompatTasksDir(dir string, clientName string, since time.Time) ([]Event, error) {
	entries, err := os.ReadDir(dir)
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
		historyPath := filepath.Join(dir, e.Name(), "api_conversation_history.json")
		data, err := os.ReadFile(historyPath)
		if err != nil {
			continue
		}
		evs, parseErr := parseClineHistory(data, clientName, since)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "aspex warning: parse %s: %v\n", historyPath, parseErr)
		}
		events = append(events, evs...)
	}
	return events, nil
}

// clineMessage is a single message in the Cline API conversation history.
type clineMessage struct {
	Role    string            `json:"role"`
	Content json.RawMessage   `json:"content"`
	TS      int64             `json:"ts"` // unix milliseconds, present in some versions
}

// clineContentBlock is a content item inside a Cline message.
type clineContentBlock struct {
	Type  string          `json:"type"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
	// Some Cline versions embed a timestamp on each block.
	TS int64 `json:"ts"`
}

func parseClineHistory(data []byte, clientName string, since time.Time) ([]Event, error) {
	var messages []clineMessage
	if err := json.Unmarshal(data, &messages); err != nil {
		return nil, err
	}

	var events []Event
	for _, msg := range messages {
		if msg.Role != "assistant" {
			continue
		}

		// Content can be a string (older format) or an array of blocks (newer).
		var blocks []clineContentBlock
		if err := json.Unmarshal(msg.Content, &blocks); err != nil {
			// Might be a string; skip — no tool_use blocks in string content.
			continue
		}

		for _, block := range blocks {
			if block.Type != "tool_use" {
				continue
			}

			// Reconstruct timestamp: prefer block-level TS, fall back to message TS.
			ts := time.Time{}
			tsMillis := block.TS
			if tsMillis == 0 {
				tsMillis = msg.TS
			}
			if tsMillis > 0 {
				ts = time.UnixMilli(tsMillis)
			}

			if !since.IsZero() && !ts.IsZero() && ts.Before(since) {
				continue
			}

			ev := Event{
				Timestamp: ts,
				Client:    clientName,
				Event:     EventToolsCall,
				Tool:      block.Name,
				Args:      flattenArgs(block.Input),
			}

			// Cline MCP tools: the server name is not directly in the conversation
			// history. We infer it from common Cline naming conventions or leave it
			// as the tool name prefix if the tool name contains "__".
			if strings.Contains(block.Name, "__") {
				parts := strings.SplitN(block.Name, "__", 2)
				ev.Server = parts[0]
				ev.Tool = parts[1]
			} else {
				ev.Server = inferClineServer(block.Name)
			}

			events = append(events, ev)
		}
	}
	return events, nil
}

// inferClineServer maps Cline's built-in tool names to a logical server name.
// MCP tools from external servers retain their original name.
func inferClineServer(toolName string) string {
	switch toolName {
	case "read_file", "write_to_file", "create_directory", "list_directory",
		"list_files", "move_file", "copy_file", "delete_file":
		return "filesystem"
	case "execute_command", "run_command":
		return "bash"
	case "search_files", "grep_search":
		return "search"
	case "browser_action":
		return "browser"
	case "ask_followup_question", "attempt_completion", "use_mcp_tool",
		"access_mcp_resource", "apply_diff", "insert_content",
		"search_and_replace":
		return "cline-builtin"
	default:
		return ""
	}
}
