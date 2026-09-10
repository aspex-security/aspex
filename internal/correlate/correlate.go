// Package correlate joins what aspex-scan knows a server CAN do with what
// aspex-trace saw it actually DO. A server with a critical static finding
// that was never invoked is a latent risk; the same server invoked 300 times
// last week, twelve of them touching credential files, is the thing to fix
// first. Static risk x observed behavior is the prioritization signal
// neither tool has on its own.
package correlate

import (
	"sort"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/trace"
)

// Activity summarizes observed runtime behavior for one server.
type Activity struct {
	Server   string    `json:"server"`
	Calls    int       `json:"calls"`       // tools/call events
	Tools    []string  `json:"tools"`       // distinct tools invoked, sorted
	Flagged  int       `json:"flagged"`     // events that tripped a trace rule
	MaxSev   string    `json:"maxSeverity"` // highest trace-rule severity seen, "" if none
	LastSeen time.Time `json:"lastSeen"`
	Clients  []string  `json:"clients"`

	maxSev rules.Severity
	tools  map[string]struct{}
	clis   map[string]struct{}
}

// Summarize aggregates events per server name. It runs the trace rule engine
// so flagged counts reflect the same detections `aspex-trace` would report.
func Summarize(events []logparse.Event) map[string]*Activity {
	out := map[string]*Activity{}
	get := func(name string) *Activity {
		a, ok := out[name]
		if !ok {
			a = &Activity{Server: name, tools: map[string]struct{}{}, clis: map[string]struct{}{}}
			out[name] = a
		}
		return a
	}

	for _, ev := range events {
		if ev.Server == "" {
			continue
		}
		a := get(ev.Server)
		a.clis[ev.Client] = struct{}{}
		if ev.Timestamp.After(a.LastSeen) {
			a.LastSeen = ev.Timestamp
		}
		if ev.Event == logparse.EventToolsCall {
			a.Calls++
			if ev.Tool != "" {
				a.tools[ev.Tool] = struct{}{}
			}
		}
	}

	for _, fe := range trace.AnalyzeEvents(events) {
		if fe.Event.Server == "" {
			continue
		}
		a := get(fe.Event.Server)
		a.Flagged++
		for _, f := range fe.Findings {
			if f.Severity > a.maxSev {
				a.maxSev = f.Severity
			}
		}
	}

	for _, a := range out {
		for t := range a.tools {
			a.Tools = append(a.Tools, t)
		}
		sort.Strings(a.Tools)
		for c := range a.clis {
			a.Clients = append(a.Clients, c)
		}
		sort.Strings(a.Clients)
		if a.maxSev > 0 {
			a.MaxSev = a.maxSev.String()
		}
	}
	return out
}

// Normalize makes server names from configs and from client logs comparable.
// Logs label the same server inconsistently across clients: "plugin_slack_slack",
// "claude_ai_ClickUp", "Claude_Browser". Lowercase, unify separators, and drop
// the wrapper prefixes clients add.
func Normalize(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = strings.NewReplacer("_", "-", " ", "-", ".", "-").Replace(s)
	for _, p := range []string{"plugin-", "claude-ai-", "mcp-", "server-"} {
		s = strings.TrimPrefix(s, p)
	}
	return strings.Trim(s, "-")
}

// Match finds the observed activity for a configured server. Exact normalized
// match first; otherwise the config name must appear as a whole token in the
// log name (so "slack" matches "plugin_slack_slack" but not "slacker").
func Match(activity map[string]*Activity, serverName string) *Activity {
	want := Normalize(serverName)
	if want == "" {
		return nil
	}
	var best *Activity
	for logName, a := range activity {
		got := Normalize(logName)
		if got == want {
			return a
		}
		for _, tok := range strings.Split(got, "-") {
			if tok == want && (best == nil || a.Calls > best.Calls) {
				best = a
			}
		}
	}
	return best
}

// IsClientBuiltin reports whether a log "server" is really the client's own
// built-in tool surface (Claude Code's Bash/Read/Edit are logged under the
// client name). Those are not MCP servers and never appear in a config.
func IsClientBuiltin(logName string) bool {
	n := Normalize(logName)
	for _, c := range logparse.SupportedClients {
		if n == Normalize(c) {
			return true
		}
	}
	return false
}

// Priority ranks a server for remediation: static severity weighted by
// observed use. Higher is more urgent. Zero means "no static findings".
//
//	unused server with critical finding      -> 4 (latent)
//	used server with critical finding        -> 8
//	used + trace-flagged + critical finding  -> 12
func Priority(staticMax rules.Severity, a *Activity) int {
	if staticMax == 0 {
		return 0
	}
	p := int(staticMax)
	if a != nil && a.Calls > 0 {
		p *= 2
		if a.Flagged > 0 {
			p += int(staticMax)
		}
	}
	return p
}
