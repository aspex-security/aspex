// Package hooks discovers and analyzes agent lifecycle hooks. A hook is a
// shell command an agent runs automatically on an event (before or after a
// tool call, on session stop, on prompt submit). Hooks are code that runs
// without a prompt, on every matching event, and they are exactly the
// persistent state that attack path AP003 and rule MCP200 warn can be written
// by a compromised agent. This package reads what is actually configured and
// judges each command.
//
// Claude Code stores hooks in settings.json under a "hooks" map keyed by event
// name; each entry has matchers whose "hooks" are {type:"command", command}.
package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Hook is one configured lifecycle command.
type Hook struct {
	Client  string `json:"client"`
	Event   string `json:"event"`   // PreToolUse, PostToolUse, Stop, UserPromptSubmit, ...
	Matcher string `json:"matcher"` // tool-name matcher, if any
	Command string `json:"command"`
	Source  string `json:"source"` // file the hook was read from
	Scope   string `json:"scope"`  // "user" (global) | "project"
}

// Finding is a judgment about a hook. Kept independent of the rules package so
// hooks stays a leaf with no dependency on scan internals.
type Finding struct {
	Hook     Hook   `json:"hook"`
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"` // critical | high | medium | low | info
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
}

// Discover reads hooks from the user-global and project settings files.
func Discover(home, cwd string) []Hook {
	var out []Hook
	read := func(path, scope string) {
		out = append(out, parseSettings(path, scope)...)
	}
	read(filepath.Join(home, ".claude", "settings.json"), "user")
	read(filepath.Join(home, ".claude", "settings.local.json"), "user")
	if cwd != "" {
		read(filepath.Join(cwd, ".claude", "settings.json"), "project")
		read(filepath.Join(cwd, ".claude", "settings.local.json"), "project")
	}
	return out
}

// settingsFile is the subset of Claude Code settings.json this package reads.
type settingsFile struct {
	Hooks map[string][]struct {
		Matcher string `json:"matcher"`
		Hooks   []struct {
			Type    string `json:"type"`
			Command string `json:"command"`
		} `json:"hooks"`
	} `json:"hooks"`
}

func parseSettings(path, scope string) []Hook {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return ParseBytes(data, path, scope)
}

// ParseBytes parses settings.json content as if it lived at path. Used to
// read hooks at a git revision without checking it out.
func ParseBytes(data []byte, path, scope string) []Hook {
	var sf settingsFile
	if json.Unmarshal(data, &sf) != nil {
		return nil
	}
	var out []Hook
	for event, matchers := range sf.Hooks {
		for _, m := range matchers {
			for _, h := range m.Hooks {
				if h.Type != "command" || h.Command == "" {
					continue
				}
				out = append(out, Hook{
					Client: "claude-code", Event: event, Matcher: m.Matcher,
					Command: h.Command, Source: path, Scope: scope,
				})
			}
		}
	}
	return out
}

var (
	reCurlPipeShell = regexp.MustCompile(`(?i)(curl|wget)\b[^|]*\|\s*(sh|bash|zsh)\b`)
	reBase64Exec    = regexp.MustCompile(`(?i)base64\s+(-d|--decode)\b.*\|\s*(sh|bash|zsh|python)`)
	reReverseShell  = regexp.MustCompile(`(?i)(nc|ncat|netcat)\b.*-e|/dev/tcp/|bash\s+-i`)
	// Network commands only; bare "ssh"/"scp" are omitted because they also
	// appear inside credential paths like ".ssh/" and would misclassify a
	// credential-read hook as a network one.
	reNetwork  = regexp.MustCompile(`(?i)\b(curl|wget|ncat|netcat)\b|\bnc\s+-|https?://`)
	reCredPath = regexp.MustCompile(`(?i)(\.ssh/|\.aws/|\.env\b|id_rsa|credentials|\.npmrc|\.netrc|keychain)`)
)

// Analyze judges each hook. Every hook produces at least an informational
// finding, because a hook is an execution surface worth seeing; dangerous
// command shapes are escalated.
func Analyze(list []Hook) []Finding {
	var out []Finding
	for _, h := range list {
		cmd := h.Command
		switch {
		case reCurlPipeShell.MatchString(cmd) || reBase64Exec.MatchString(cmd):
			out = append(out, mk(h, "HOOK001", "critical", "Hook fetches and executes remote code",
				"The "+h.Event+" hook pipes downloaded content straight into a shell. Anything the remote host serves runs on every "+h.Event+" event.",
				"Remove this hook or replace it with a vetted, version-pinned local script."))
		case reReverseShell.MatchString(cmd):
			out = append(out, mk(h, "HOOK002", "critical", "Hook opens a reverse shell",
				"The "+h.Event+" hook command has the shape of a reverse shell or interactive network shell.",
				"Remove this hook immediately and rotate anything the machine had access to."))
		case reCredPath.MatchString(cmd) && reNetwork.MatchString(cmd):
			out = append(out, mk(h, "HOOK003", "high", "Hook reads credentials and reaches the network",
				"The "+h.Event+" hook references a credential path and a network command; together they are an exfiltration surface that runs automatically.",
				"Remove the credential access or the network call from this hook."))
		case reCredPath.MatchString(cmd):
			out = append(out, mk(h, "HOOK004", "medium", "Hook accesses sensitive paths",
				"The "+h.Event+" hook references credential or secret paths. It runs automatically on every "+h.Event+" event.",
				"Confirm this access is intended; hooks run without a prompt."))
		case reNetwork.MatchString(cmd):
			out = append(out, mk(h, "HOOK005", "medium", "Hook makes network calls",
				"The "+h.Event+" hook reaches the network on every "+h.Event+" event. A hook is a standing outbound channel most users forget is there.",
				"Confirm the destination is trusted and the call is intended."))
		default:
			out = append(out, mk(h, "HOOK000", "info", "Hook runs a command automatically",
				"A "+h.Event+" hook runs `"+truncate(cmd, 80)+"` automatically. Nothing suspicious in the command itself.",
				"Review periodically; a compromised agent that can write settings.json could change this."))
		}
	}
	return out
}

func mk(h Hook, id, sev, title, detail, fix string) Finding {
	return Finding{Hook: h, RuleID: id, Severity: sev, Title: title, Detail: detail, Fix: fix}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
