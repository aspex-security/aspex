// Package agentenv assembles one deterministic model of the local agent
// environment: which agents exist, what MCP servers, hooks, skills and
// instruction files they trust, what each can do (with evidence), what
// sensitive resources and destinations are reachable, which compositions
// form attack paths, and the resulting blast radius.
//
// It is the single input to lock, verify, diff, explain, tighten, bom and the
// read-only MCP interface. It does not detect anything itself: capabilities
// come from internal/attackpath, hooks from internal/hooks, skills from
// internal/skills. This package only assembles, fingerprints, and compares.
package agentenv

import (
	"github.com/aspex-security/aspex/internal/attackpath"
)

// SchemaVersion is the lockfile / BOM schema version. Bump on any change to
// the serialized shape that a reader could misinterpret.
const SchemaVersion = 1

// Environment is the normalized security-relevant state of an agent setup.
// Field order matters for readers of the JSON; slices are always sorted so
// two builds of the same setup serialize identically.
type Environment struct {
	SchemaVersion int           `json:"schema_version"`
	Agents        []Agent       `json:"agents"`
	Servers       []Server      `json:"mcp_servers"`
	Hooks         []Hook        `json:"hooks"`
	Skills        []Skill       `json:"skills"`
	Instructions  []Instruction `json:"instructions"`

	// Derived, security conclusions over the entities above.
	SensitiveResources []Resource               `json:"sensitive_resources"`
	Destinations       []string                 `json:"destinations"`
	AttackPaths        []attackpath.AttackChain `json:"attack_paths"`
	BlastRadius        BlastRadius              `json:"blast_radius"`

	// Static is true when no server was launched: capabilities are inferred
	// from packages and configs. Lower confidence everywhere.
	Static bool `json:"static"`
}

// Agent is a client that runs tools: Claude Code, Cursor, ...
type Agent struct {
	Name   string `json:"name"`
	Client string `json:"client"`
}

// Server is one MCP server with its identity, surface, and capabilities.
type Server struct {
	Name       string   `json:"name"`
	Client     string   `json:"client"`
	Command    string   `json:"command,omitempty"`
	Args       []string `json:"args,omitempty"`
	URL        string   `json:"url,omitempty"`
	ConfigPath string   `json:"config_path,omitempty"` // file the server is configured in
	Package    string   `json:"package,omitempty"`     // best-effort: the npm/pypi identifier in the command line
	Pinned     bool     `json:"pinned"`                // a version is fixed in the command line
	EnvKeys    []string `json:"env_keys,omitempty"`
	Static     bool     `json:"static"`
	Identity   string   `json:"identity"` // fingerprint of command+args+url: what would run

	Tools        []Tool                        `json:"tools"`
	Capabilities []string                      `json:"capabilities"`
	Roots        []string                      `json:"filesystem_roots,omitempty"`
	Scope        string                        `json:"filesystem_scope,omitempty"` // sensitive | project | unknown
	EgressOpen   bool                          `json:"egress_open"`                // network egress without a destination allowlist
	Destinations []string                      `json:"destinations,omitempty"`
	StateWrites  []attackpath.AgentStateTarget `json:"agent_state_writes,omitempty"`

	Fingerprint string `json:"fingerprint"` // identity + every tool: the rug-pull detector
}

// Tool is one MCP tool. Description is kept in full because a description
// change is security-relevant and the reader must be able to show before and
// after; the schema is kept as a hash because it is large and its meaning is
// captured by the capability classification.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	SchemaHash  string `json:"schema_hash,omitempty"`
}

// Hook is an agent lifecycle command.
type Hook struct {
	Event    string `json:"event"`
	Matcher  string `json:"matcher,omitempty"`
	Command  string `json:"command"`
	Source   string `json:"source"`
	Scope    string `json:"scope"`
	Hash     string `json:"hash"`
	Severity string `json:"severity"` // from hooks.Analyze: critical..info
	Judgment string `json:"judgment"` // finding title
}

// Skill is a persistent instruction bundle, possibly with scripts.
type Skill struct {
	Name         string   `json:"name"`
	Path         string   `json:"path"`
	Scope        string   `json:"scope"`
	ContentHash  string   `json:"content_hash"`
	Scripts      []string `json:"scripts,omitempty"`
	Destinations []string `json:"destinations,omitempty"`
	Executes     bool     `json:"executes"`
}

// Instruction is a persistent instruction file the agent loads (CLAUDE.md,
// .cursorrules, ...). Content is hashed, never stored.
type Instruction struct {
	Path  string `json:"path"`
	Kind  string `json:"kind"`  // instructions | memory | mcp-config | hooks
	Scope string `json:"scope"` // user | project
	Hash  string `json:"hash"`
}

// Resource is a sensitive thing some server can reach.
type Resource struct {
	Path   string   `json:"path"`   // ~/.ssh, production database, ...
	Kind   string   `json:"kind"`   // credentials | agent-state | database | browser-profile
	Via    []string `json:"via"`    // server names
	Access string   `json:"access"` // read | write | read-write
}

// BlastRadius is the qualitative answer to "how bad could an instruction the
// agent follows get", with the reasons listed so it is never a bare label.
type BlastRadius struct {
	Level string   `json:"level"` // HIGH | MEDIUM | LOW | NONE
	Why   []Reason `json:"why"`
}

// Reason is one factor in the blast radius, present or absent.
type Reason struct {
	Present bool   `json:"present"`
	Text    string `json:"text"`
}
