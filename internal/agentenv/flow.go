package agentenv

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Data-flow reasoning: follow the data. A forward query starts at a resource
// and lists every sink it could reach; a reverse query starts at a
// destination and lists every sensitive resource that could reach it. Both
// walk the same graph as attack paths: readers, the agent context, sinks.
// Flows are POTENTIAL unless runtime evidence marks a hop OBSERVED; Aspex
// never claims data moved.

// FlowStatus labels a hop or flow.
const (
	FlowPotential = "POTENTIAL" // the capabilities allow it
	FlowReachable = "REACHABLE" // the resource is within a reader's scope
	FlowObserved  = "OBSERVED"  // the trace shows this hop was exercised (server/tool called)
)

// FlowSource is where data starts.
type FlowSource struct {
	Resource    string `json:"resource"`    // ~/.aws/credentials, database via postgres, project files
	Sensitivity string `json:"sensitivity"` // high | medium | low
	Reader      string `json:"reader"`      // server.tool
	Status      string `json:"status"`      // REACHABLE | OBSERVED
}

// FlowSink is where data could go.
type FlowSink struct {
	Via         string `json:"via"`  // server.tool
	Kind        string `json:"kind"` // network | channel | exec | persistence | memory | database
	Destination string `json:"destination"`
	Status      string `json:"status"` // POTENTIAL | OBSERVED
}

// FlowAnswer is a forward or reverse flow result.
type FlowAnswer struct {
	Direction string       `json:"direction"` // forward | reverse
	Subject   string       `json:"subject"`   // the resource or destination asked about
	Sources   []FlowSource `json:"sources"`
	Sinks     []FlowSink   `json:"sinks"`
	Summary   string       `json:"summary"`
	Evidence  []Condition  `json:"evidence"`
	NotProven []string     `json:"not_proven"`
}

// Observed is optional runtime evidence: server names (and server.tool) that
// were actually invoked in the trace window. Used only to mark hops OBSERVED.
type Observed map[string]bool

var reFlowForward = regexp.MustCompile(`(?i)\b(where (could|can|does|would)|where (might|may))\b.*\b(data|content|contents|files?|secrets?|keys?)\b.*\bfrom\b\s+(.+?)\s*(go|end up|flow|reach|leak)?\??$`)
var reFlowReverse = regexp.MustCompile(`(?i)\b(what|which)\b.*\b(data|files?|secrets?|information|content)\b.*\b(reach|flow to|end up in|be sent to|go to|leak to)\b\s+(.+?)\??$`)

// ParseFlow recognizes forward ("where could data from ~/.aws go?") and
// reverse ("what sensitive data could reach Slack?") flow questions.
func ParseFlow(q string) (direction, subject string, ok bool) {
	if m := reFlowForward.FindStringSubmatch(q); m != nil {
		return "forward", strings.Trim(m[5], " ?\"'`"), true
	}
	if m := reFlowReverse.FindStringSubmatch(q); m != nil {
		return "reverse", strings.Trim(m[4], " ?\"'`"), true
	}
	return "", "", false
}

// sinksOf lists every way data in the agent context can leave or persist.
func sinksOf(env Environment, obs Observed) []FlowSink {
	var out []FlowSink
	for _, s := range env.Servers {
		caps := capSet(s)
		// OBSERVED means this tool (or, when no tool list exists, this server)
		// was invoked in the window. A server-level match must not mark a sink
		// observed when a different tool of the same server was what ran.
		status := func(tool string) string {
			if tool != "" && len(s.Tools) > 0 {
				if obs[s.Name+"."+tool] {
					return FlowObserved
				}
				return FlowPotential
			}
			if obs[s.Name] {
				return FlowObserved
			}
			return FlowPotential
		}
		switch {
		case s.EgressOpen:
			t := toolFor(s, "net")
			out = append(out, FlowSink{Via: hop(s.Name, t, "network"), Kind: "network", Destination: "any network destination", Status: status(t)})
		case caps["network-send"]:
			t := toolFor(s, "net")
			out = append(out, FlowSink{Via: hop(s.Name, t, "network"), Kind: "network", Destination: "allowlisted destinations", Status: status(t)})
		}
		if caps["external-send"] || caps["email-send"] {
			t := toolFor(s, "send")
			dest := strings.Join(s.Destinations, ", ")
			if dest == "" {
				dest = "an external service"
			}
			out = append(out, FlowSink{Via: hop(s.Name, t, "channel"), Kind: "channel", Destination: dest, Status: status(t)})
		}
		if caps["shell-exec"] {
			t := toolFor(s, "exec")
			out = append(out, FlowSink{Via: hop(s.Name, t, "shell-exec"), Kind: "exec", Destination: "any process on this machine (and from there, anywhere)", Status: status(t)})
		}
		if len(s.StateWrites) > 0 {
			t := toolFor(s, "write")
			out = append(out, FlowSink{Via: hop(s.Name, t, "file-write"), Kind: "persistence", Destination: "agent config, hooks, instructions (survives the session)", Status: status(t)})
		}
		if caps["memory-write"] {
			out = append(out, FlowSink{Via: hop(s.Name, toolFor(s, "memory"), "memory-write"), Kind: "memory", Destination: "the agent's persistent memory", Status: status("")})
		}
		if caps["db-write"] {
			t := toolFor(s, "query")
			out = append(out, FlowSink{Via: hop(s.Name, t, "db-write"), Kind: "database", Destination: "database via " + s.Name, Status: status(t)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return kindRank(out[i].Kind) < kindRank(out[j].Kind)
		}
		return out[i].Via < out[j].Via
	})
	return out
}

func kindRank(k string) int {
	switch k {
	case "network":
		return 0
	case "channel":
		return 1
	case "exec":
		return 2
	case "persistence":
		return 3
	case "memory":
		return 4
	}
	return 5
}

// sourcesOf lists sensitive resources readable through the servers, with a
// sensitivity grade. Matching the asked resource is done by resolveResource.
func sourcesOf(env Environment, obs Observed) []FlowSource {
	var out []FlowSource
	for _, s := range env.Servers {
		caps := capSet(s)
		st := func(tool string) string {
			if tool != "" && len(s.Tools) > 0 {
				if obs[s.Name+"."+tool] {
					return FlowObserved
				}
				return FlowReachable
			}
			if obs[s.Name] {
				return FlowObserved
			}
			return FlowReachable
		}
		if caps["file-read"] {
			t := toolFor(s, "read")
			switch s.Scope {
			case "sensitive", "unknown":
				for _, r := range []string{"~/.aws/credentials", "~/.ssh/*", "~/.gnupg/*", "~/.kube/config", "~/.docker/config.json", "~/.netrc, ~/.npmrc"} {
					out = append(out, FlowSource{Resource: r, Sensitivity: "high", Reader: hop(s.Name, t, "file-read"), Status: st(t)})
				}
				out = append(out, FlowSource{Resource: "browser profiles (cookies, saved logins)", Sensitivity: "high", Reader: hop(s.Name, t, "file-read"), Status: st(t)})
				out = append(out, FlowSource{Resource: "~/Documents/*, ~/Desktop/*, ~/Downloads/*", Sensitivity: "medium", Reader: hop(s.Name, t, "file-read"), Status: st(t)})
				out = append(out, FlowSource{Resource: "agent config and instruction files", Sensitivity: "medium", Reader: hop(s.Name, t, "file-read"), Status: st(t)})
			case "project":
				out = append(out, FlowSource{Resource: "project files under " + firstRoot(s) + " (source, .env, keys committed by mistake)", Sensitivity: "medium", Reader: hop(s.Name, t, "file-read"), Status: st(t)})
			}
		}
		if caps["credential-read"] || caps["env-read"] {
			out = append(out, FlowSource{Resource: "environment variables and secret stores", Sensitivity: "high", Reader: hop(s.Name, toolFor(s, "env"), "env-read"), Status: st("")})
		}
		if caps["shell-exec"] {
			out = append(out, FlowSource{Resource: "anything the user can read (via a shell)", Sensitivity: "high", Reader: hop(s.Name, toolFor(s, "exec"), "shell-exec"), Status: st("")})
		}
		if caps["data-read"] && isDatabase(s) {
			out = append(out, FlowSource{Resource: "database via " + s.Name, Sensitivity: "high", Reader: hop(s.Name, toolFor(s, "query"), "data-read"), Status: st("")})
		}
		if caps["browser"] {
			out = append(out, FlowSource{Resource: "browser session content (logged-in pages)", Sensitivity: "high", Reader: hop(s.Name, toolFor(s, "browser"), "browser"), Status: st("")})
		}
	}
	return out
}

// Forward answers "where could data from <resource> go?".
func Forward(env Environment, resource string, obs Observed) FlowAnswer {
	a := FlowAnswer{Direction: "forward", Subject: resource}
	want := strings.ToLower(resource)
	for _, src := range sourcesOf(env, obs) {
		if resourceMatches(src.Resource, want) {
			a.Sources = append(a.Sources, src)
		}
	}
	if len(a.Sources) == 0 {
		a.Summary = "No configured server can read " + resource + "; nothing to follow."
		a.Evidence = []Condition{{Met: false, Text: "a server can read " + resource}}
		return a
	}
	a.Sinks = sinksOf(env, obs)
	a.Evidence = append(a.Evidence, Condition{Met: true, Text: "a server can read " + resource, Evidence: a.Sources[0].Reader})
	if len(a.Sinks) == 0 {
		a.Summary = resource + " can be read into the agent's context, but no server can send data out, run commands, or persist it. It stays on this machine."
		a.Evidence = append(a.Evidence, Condition{Met: false, Text: "a sink exists (network, channel, shell, persistence)"})
		return a
	}
	a.Summary = fmt.Sprintf("%s can reach %d sink(s) through the agent's context.", resource, len(a.Sinks))
	a.Evidence = append(a.Evidence, Condition{Met: true, Text: fmt.Sprintf("%d sink(s) exist", len(a.Sinks)), Evidence: a.Sinks[0].Via})
	a.NotProven = []string{"no runtime evidence that this data was read or sent; POTENTIAL means the capabilities allow it, OBSERVED means the server or tool was invoked in the trace window, not that this data moved"}
	return a
}

// Reverse answers "what sensitive data could reach <destination>?".
func Reverse(env Environment, destination string, obs Observed) FlowAnswer {
	a := FlowAnswer{Direction: "reverse", Subject: destination}
	want := strings.ToLower(destination)
	for _, sk := range sinksOf(env, obs) {
		if strings.Contains(strings.ToLower(sk.Via), want) || strings.Contains(strings.ToLower(sk.Destination), want) ||
			(want == "the internet" || want == "internet" || want == "external network" || want == "outside") && sk.Kind == "network" {
			a.Sinks = append(a.Sinks, sk)
		}
	}
	if len(a.Sinks) == 0 {
		a.Summary = "No configured server sends data to " + destination + "."
		a.Evidence = []Condition{{Met: false, Text: "a sink reaching " + destination}}
		return a
	}
	a.Sources = dedupeSources(sourcesOf(env, obs))
	sort.SliceStable(a.Sources, func(i, j int) bool { return sensRank(a.Sources[i].Sensitivity) > sensRank(a.Sources[j].Sensitivity) })
	a.Evidence = append(a.Evidence, Condition{Met: true, Text: "a sink reaches " + destination, Evidence: a.Sinks[0].Via})
	if len(a.Sources) == 0 {
		a.Summary = destination + " is reachable, but no server reads anything sensitive; only what the user types could get there."
		a.Evidence = append(a.Evidence, Condition{Met: false, Text: "a server reads sensitive resources"})
		return a
	}
	a.Summary = fmt.Sprintf("%d sensitive resource class(es) could reach %s via the agent's context.", len(a.Sources), destination)
	a.Evidence = append(a.Evidence, Condition{Met: true, Text: "servers read sensitive resources", Evidence: a.Sources[0].Reader})
	a.NotProven = []string{"no runtime evidence that any of this data was sent to " + destination}
	return a
}

func resourceMatches(resource, want string) bool {
	r := strings.ToLower(resource)
	if strings.Contains(r, want) {
		return true
	}
	// Semantic aliases.
	aliases := map[string][]string{
		"aws": {"~/.aws"}, "credentials": {"~/.aws", "environment variables", "~/.ssh", "browser profiles"}, "ssh": {"~/.ssh"}, "ssh keys": {"~/.ssh"},
		"secrets": {"environment variables", "~/.aws", "~/.ssh"}, "env": {"environment variables"}, "environment": {"environment variables"},
		"database": {"database"}, "production": {"database"}, "documents": {"~/documents"}, "browser": {"browser"}, "cookies": {"browser profiles"},
		"kube": {"~/.kube"}, "kubeconfig": {"~/.kube"}, "gpg": {"~/.gnupg"}, "project": {"project files"}, "source": {"project files"}, "repo": {"project files"},
		"home": {"~/"}, "~": {"~/"},
	}
	for k, vs := range aliases {
		if strings.Contains(want, k) {
			for _, v := range vs {
				if strings.Contains(r, v) {
					return true
				}
			}
		}
	}
	return false
}

func sensRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	}
	return 1
}

// dedupeSources merges rows for the same resource, joining the readers, so a
// reverse answer lists each resource once ("via filesystem, desktop-commander").
func dedupeSources(in []FlowSource) []FlowSource {
	idx := map[string]int{}
	var out []FlowSource
	for _, s := range in {
		if i, ok := idx[s.Resource]; ok {
			if !strings.Contains(out[i].Reader, s.Reader) {
				out[i].Reader += ", " + s.Reader
			}
			if s.Status == FlowObserved {
				out[i].Status = FlowObserved
			}
			continue
		}
		idx[s.Resource] = len(out)
		out = append(out, s)
	}
	return out
}
