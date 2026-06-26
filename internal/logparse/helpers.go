package logparse

import (
	"encoding/json"
	"strings"
)

// extractBracketedName extracts the first [name] token from a log line.
// e.g. "2026-04-29 [info] [filesystem] ..." returns "filesystem".
func extractBracketedName(s string) string {
	// Skip the first bracket pair (usually the log level like [info])
	first := strings.Index(s, "[")
	if first < 0 {
		return ""
	}
	second := strings.Index(s[first+1:], "[")
	if second < 0 {
		return ""
	}
	offset := first + 1 + second
	end := strings.Index(s[offset:], "]")
	if end < 0 {
		return ""
	}
	return s[offset+1 : offset+end]
}

// parseJSONRPCMethod extracts the method, tool name, and arguments from a JSON-RPC payload.
func parseJSONRPCMethod(jsonStr string) (method, toolName string, args map[string]string) {
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &msg); err != nil {
		return "", "", nil
	}
	method = msg.Method
	toolName = msg.Params.Name
	if msg.Params.Arguments != nil {
		args = flattenArgs(msg.Params.Arguments)
	}
	return
}
