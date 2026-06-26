// Package logparse defines the unified event model for agent-trace and per-client log parsers.
package logparse

import "time"

// EventType is the kind of MCP event.
type EventType string

const (
	EventInitialize   EventType = "initialize"
	EventToolsList    EventType = "tools/list"
	EventToolsCall    EventType = "tools/call"
	EventResourceRead EventType = "resources/read"
	EventPromptsGet   EventType = "prompts/get"
	EventError        EventType = "error"
	EventServerExit   EventType = "server-exit"
)

// Event is one normalized entry in the agent-trace audit trail.
type Event struct {
	Timestamp  time.Time         `json:"ts"`
	Client     string            `json:"client"`
	Server     string            `json:"server"`
	Event      EventType         `json:"event"`
	Tool       string            `json:"tool,omitempty"`
	Args       map[string]string `json:"args,omitempty"`
	DurationMS int64             `json:"duration_ms,omitempty"`
	Flags      []string          `json:"flags,omitempty"`
	Raw        string            `json:"-"`
}
