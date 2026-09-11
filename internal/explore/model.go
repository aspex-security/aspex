// Package explore builds the dataset behind `aspex explore`: a local,
// loopback-only session explorer. Think DevTools for an agent session: a
// timeline of what happened, provenance chains from ingested content to
// suspicious calls, the capability graph, and per-finding detail that keeps
// OBSERVED, INFERRED and POSSIBLE apart.
//
// Everything here is computed from data the other packages already produce
// (trace events and rules, kill chains, provenance, the environment). The
// package adds no detection of its own.
package explore

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/killchain"
	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/provenance"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/trace"
)

// Dataset is everything the UI needs, serialized once.
type Dataset struct {
	Generated  time.Time                `json:"generated"`
	Window     string                   `json:"window"`
	Summary    Summary                  `json:"summary"`
	Sessions   []Session                `json:"sessions"`
	Timeline   []Entry                  `json:"timeline"`
	Provenance []Chain                  `json:"provenance"`
	KillChains []KillChain              `json:"killchains"`
	Graph      Graph                    `json:"graph"`
	Findings   []Finding                `json:"findings"`
	Blast      agentenv.BlastRadius     `json:"blast_radius"`
	DataFlows  []FlowView               `json:"data_flows"`
	Paths      []attackpath.AttackChain `json:"attack_paths"`
	// Controls: for each attack path (keyed id|servers), the concrete changes
	// that break it, from the shared remediation engine.
	Controls map[string][]string `json:"controls"`
}

// Summary is the header numbers.
type Summary struct {
	Events   int `json:"events"`
	Sessions int `json:"sessions"`
	Flagged  int `json:"flagged"`
	Servers  int `json:"servers"`
	Chains   int `json:"killchains"`
	Attribs  int `json:"provenance_links"`
}

// Session is one agent conversation.
type Session struct {
	ID      string    `json:"id"`
	Client  string    `json:"client"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Events  int       `json:"events"`
	Flagged int       `json:"flagged"`
	Servers []string  `json:"servers"`
}

// Entry is one timeline row.
type Entry struct {
	ID       int       `json:"id"`
	TS       time.Time `json:"ts"`
	Session  string    `json:"session"`
	Client   string    `json:"client"`
	Kind     string    `json:"kind"` // TOOL | CONTENT | NETWORK | ERROR | RESOURCE
	Server   string    `json:"server"`
	Tool     string    `json:"tool"`
	Detail   string    `json:"detail"` // path, url, or first argument
	Severity string    `json:"severity,omitempty"`
	Rules    []string  `json:"rules,omitempty"`
}

// Chain is a provenance link rendered as labeled evidence.
type Chain struct {
	Source     Entry      `json:"source"`
	Target     Entry      `json:"target"`
	Delta      string     `json:"delta"`
	Apart      int        `json:"events_apart"`
	Confidence string     `json:"confidence"`
	Evidence   []Evidence `json:"evidence"`
}

// Evidence is one labeled statement.
type Evidence struct {
	Level string `json:"level"` // OBSERVED | INFERRED | POSSIBLE | NOT OBSERVED
	Text  string `json:"text"`
}

// KillChain mirrors killchain.Chain for the UI.
type KillChain struct {
	Name     string     `json:"name"`
	Severity string     `json:"severity"`
	Start    time.Time  `json:"start"`
	Steps    []string   `json:"steps"`
	Evidence []Evidence `json:"evidence"`
	Tactic   string     `json:"tactic"`
}

// Graph is the capability graph: sources -> agent -> servers -> resources.
type Graph struct {
	Nodes []GNode `json:"nodes"`
	Edges []GEdge `json:"edges"`
}

type GNode struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Kind     string `json:"kind"` // source | agent | server | resource | destination
	Meta     string `json:"meta,omitempty"`
	Boundary string `json:"boundary"`           // EXTERNAL CONTENT | AGENT CONTEXT | LOCAL MACHINE | EXTERNAL NETWORK | PERSISTENT STATE | DATABASE
	Persists bool   `json:"persists,omitempty"` // a write here survives the session
}

type GEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Label    string `json:"label,omitempty"`
	Severity string `json:"severity,omitempty"` // set when part of an attack path
	Observed bool   `json:"observed"`           // the edge was exercised in the trace window
	Persists bool   `json:"persists,omitempty"` // crosses the session boundary
}

// FlowView is the data-flow tab: for a sensitive resource, the readers and
// the sinks it could reach, each hop labeled REACHABLE / POTENTIAL / OBSERVED.
type FlowView struct {
	Resource string                `json:"resource"`
	Sources  []agentenv.FlowSource `json:"sources"`
	Sinks    []agentenv.FlowSink   `json:"sinks"`
	Summary  string                `json:"summary"`
}

// Finding is one flagged event with its explanation.
type Finding struct {
	EntryID  int        `json:"entry_id"`
	RuleID   string     `json:"rule_id"`
	Name     string     `json:"name"`
	Severity string     `json:"severity"`
	Detail   string     `json:"detail"`
	Fix      string     `json:"fix"`
	Mapping  string     `json:"mapping"`
	Evidence []Evidence `json:"evidence"`
	Server   string     `json:"server"`
	Tool     string     `json:"tool"`
	TS       time.Time  `json:"ts"`
}

// Inputs are the already-computed analyses.
type Inputs struct {
	Events  []logparse.Event
	Flagged []trace.FlaggedEvent
	Chains  []killchain.Chain
	Prov    provenance.Report
	Env     agentenv.Environment
	Window  time.Duration
}

// Build assembles the dataset.
func Build(in Inputs) Dataset {
	sorted := make([]logparse.Event, len(in.Events))
	copy(sorted, in.Events)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })

	flaggedBy := map[string][]rules.Finding{}
	for _, fe := range in.Flagged {
		flaggedBy[key(fe.Event)] = append(flaggedBy[key(fe.Event)], fe.Findings...)
	}

	ds := Dataset{Generated: time.Now(), Window: humanWindow(in.Window), Blast: in.Env.BlastRadius}
	idOf := map[string]int{}
	sessions := map[string]*Session{}
	observedEdge := map[string]bool{}
	for i, ev := range sorted {
		e := entryOf(i, ev)
		if fs := flaggedBy[key(ev)]; len(fs) > 0 {
			var worst rules.Severity
			for _, f := range fs {
				e.Rules = append(e.Rules, f.RuleID)
				if f.Severity > worst {
					worst = f.Severity
				}
				ds.Findings = append(ds.Findings, Finding{
					EntryID: i, RuleID: f.RuleID, Name: f.Name, Severity: strings.ToLower(worstName(f.Severity)),
					Detail: f.Detail, Fix: f.Fix, Mapping: f.Mapping, Server: ev.Server, Tool: ev.Tool, TS: ev.Timestamp,
					Evidence: findingEvidence(ev, f),
				})
			}
			e.Severity = strings.ToLower(worstName(worst))
		}
		ds.Timeline = append(ds.Timeline, e)
		idOf[key(ev)] = i
		sid := sessionID(ev)
		s, ok := sessions[sid]
		if !ok {
			s = &Session{ID: sid, Client: ev.Client, Start: ev.Timestamp}
			sessions[sid] = s
		}
		s.End = ev.Timestamp
		s.Events++
		if e.Severity != "" {
			s.Flagged++
		}
		if ev.Server != "" && !contains(s.Servers, ev.Server) {
			s.Servers = append(s.Servers, ev.Server)
		}
		if ev.Server != "" {
			observedEdge["agent->"+ev.Server] = true
			if ev.Tool != "" {
				observedEdge["agent->"+ev.Server+"."+ev.Tool] = true
			}
		}
	}
	for _, s := range sessions {
		sort.Strings(s.Servers)
		ds.Sessions = append(ds.Sessions, *s)
	}
	sort.Slice(ds.Sessions, func(i, j int) bool { return ds.Sessions[i].Start.After(ds.Sessions[j].Start) })

	for _, a := range in.Prov.Attributions {
		src := entryOf(idOf[key(a.IngestionEvent)], a.IngestionEvent)
		dst := entryOf(idOf[key(a.SuspiciousEvent)], a.SuspiciousEvent)
		ds.Provenance = append(ds.Provenance, Chain{
			Source: src, Target: dst, Delta: a.Delta.Truncate(time.Second).String(), Apart: a.EventsApart, Confidence: a.Confidence,
			Evidence: provenanceEvidence(a, src, dst),
		})
	}
	for _, c := range in.Chains {
		kc := KillChain{Name: c.Name, Severity: c.Severity, Start: c.WindowStart, Tactic: c.MITRETactic + " (" + c.MITRERef + ")"}
		for _, s := range c.Steps {
			kc.Steps = append(kc.Steps, s.Timestamp.Format("15:04:05")+"  "+s.Server+"."+s.Tool+"  "+s.Detail)
		}
		for _, e := range c.Evidence {
			kc.Evidence = append(kc.Evidence, Evidence{Level: e.Level, Text: e.Text})
		}
		ds.KillChains = append(ds.KillChains, kc)
	}
	ds.Graph = buildGraph(in.Env, observedEdge)
	ds.Paths = in.Env.AttackPaths
	ds.Controls = map[string][]string{}
	for _, p := range in.Env.AttackPaths {
		for _, ctl := range agentenv.ControlsFor(in.Env, p, "") {
			ds.Controls[p.ID+"|"+strings.Join(p.Servers, ",")] = append(ds.Controls[p.ID+"|"+strings.Join(p.Servers, ",")], ctl.Text)
		}
	}
	// Data-flow views for the resources people ask about; hops are OBSERVED
	// when the server was invoked in the window, never "data moved".
	obs := agentenv.Observed{}
	for k := range observedEdge {
		obs[strings.TrimPrefix(k, "agent->")] = true
	}
	for _, res := range []string{"~/.aws/credentials", "~/.ssh", "environment variables", "database", "browser session", "project files"} {
		fa := agentenv.Forward(in.Env, res, obs)
		if len(fa.Sources) == 0 {
			continue
		}
		ds.DataFlows = append(ds.DataFlows, FlowView{Resource: res, Sources: fa.Sources, Sinks: fa.Sinks, Summary: fa.Summary})
	}
	if ds.DataFlows == nil {
		ds.DataFlows = []FlowView{}
	}
	if ds.Paths == nil {
		ds.Paths = []attackpath.AttackChain{}
	}
	ds.Summary = Summary{Events: len(sorted), Sessions: len(ds.Sessions), Flagged: len(ds.Findings), Servers: len(in.Env.Servers), Chains: len(ds.KillChains), Attribs: len(ds.Provenance)}
	if ds.Timeline == nil {
		ds.Timeline = []Entry{}
	}
	if ds.Sessions == nil {
		ds.Sessions = []Session{}
	}
	if ds.Provenance == nil {
		ds.Provenance = []Chain{}
	}
	if ds.KillChains == nil {
		ds.KillChains = []KillChain{}
	}
	if ds.Findings == nil {
		ds.Findings = []Finding{}
	}
	return ds
}

func key(ev logparse.Event) string {
	return ev.Timestamp.Format(time.RFC3339Nano) + "/" + ev.Tool + "/" + ev.Server
}

func sessionID(ev logparse.Event) string {
	if ev.Session != "" {
		return ev.Client + "/" + shortID(ev.Session)
	}
	return ev.Client + "/" + ev.Timestamp.Format("2006-01-02")
}

func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func entryOf(id int, ev logparse.Event) Entry {
	e := Entry{ID: id, TS: ev.Timestamp, Session: sessionID(ev), Client: ev.Client, Server: ev.Server, Tool: ev.Tool, Kind: "TOOL"}
	switch ev.Event {
	case logparse.EventError:
		e.Kind = "ERROR"
	case logparse.EventResourceRead:
		e.Kind = "RESOURCE"
	}
	if ok, kind := provenance.IngestionKind(ev.Tool); ok {
		if kind == "web_fetch" || kind == "browser_load" {
			e.Kind = "NETWORK"
		} else {
			e.Kind = "CONTENT"
		}
	} else if isNetworkTool(ev.Tool) {
		e.Kind = "NETWORK"
	}
	e.Detail = detailOf(ev)
	return e
}

func isNetworkTool(tool string) bool {
	l := strings.ToLower(tool)
	for _, t := range []string{"fetch", "http", "request", "curl", "navigate", "download", "send_message", "create_issue", "post", "upload"} {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}

// detailOf picks the most telling argument: a path or URL if present, else
// the first short argument. Content-bearing arguments are never shown whole.
func detailOf(ev logparse.Event) string {
	for _, k := range []string{"path", "file_path", "url", "uri", "command", "query", "title"} {
		if v, ok := ev.Args[k]; ok && v != "" {
			return truncate(v, 120)
		}
	}
	var keys []string
	for k := range ev.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(ev.Args[k]) < 80 && !strings.ContainsAny(ev.Args[k], "\n") {
			return k + "=" + ev.Args[k]
		}
	}
	return ""
}

func findingEvidence(ev logparse.Event, f rules.Finding) []Evidence {
	out := []Evidence{{Level: "OBSERVED", Text: fmt.Sprintf("%s %s.%s was called", ev.Timestamp.Format("15:04:05"), ev.Server, ev.Tool)}}
	if d := detailOf(ev); d != "" {
		out = append(out, Evidence{Level: "OBSERVED", Text: "argument: " + d})
	}
	out = append(out, Evidence{Level: "INFERRED", Text: f.Name + ": " + f.Detail})
	out = append(out, Evidence{Level: "NOT OBSERVED", Text: "whether the call served a user request or an injected instruction; the log records the call, not its motive"})
	return out
}

func provenanceEvidence(a provenance.Attribution, src, dst Entry) []Evidence {
	out := []Evidence{
		{Level: "OBSERVED", Text: fmt.Sprintf("%s %s.%s brought content in (%s: %s)", src.TS.Format("15:04:05"), src.Server, src.Tool, a.IngestionKind, truncate(a.IngestionSource, 80))},
		{Level: "OBSERVED", Text: fmt.Sprintf("%s %s.%s was called %s later, %d event(s) apart", dst.TS.Format("15:04:05"), dst.Server, dst.Tool, a.Delta.Truncate(time.Second), a.EventsApart)},
		{Level: "INFERRED", Text: fmt.Sprintf("the ingested content may have influenced the call (confidence %s, from timing and proximity only)", a.Confidence)},
	}
	for _, f := range a.Findings {
		if f.Severity >= rules.SeverityHigh {
			out = append(out, Evidence{Level: "OBSERVED", Text: f.RuleID + " " + f.Name + ": " + f.Detail})
			break
		}
	}
	out = append(out, Evidence{Level: "NOT OBSERVED", Text: "the content itself is not in the log; Aspex cannot show it contained an instruction"})
	return out
}

// buildGraph lays out sources -> agent -> servers -> resources/destinations.
// Attack-path edges carry severity; edges exercised in the trace window are
// marked observed. Small by construction: one node per server, per sensitive
// resource kind, per destination.
func buildGraph(env agentenv.Environment, observed map[string]bool) Graph {
	g := Graph{}
	add := func(n GNode) {
		for _, x := range g.Nodes {
			if x.ID == n.ID {
				return
			}
		}
		g.Nodes = append(g.Nodes, n)
	}
	add(GNode{ID: "src:external", Label: "External content", Kind: "source", Meta: "prompts, documents, web pages, tool results", Boundary: "EXTERNAL CONTENT"})
	add(GNode{ID: "agent", Label: "Agent", Kind: "agent", Boundary: "AGENT CONTEXT"})
	g.Edges = append(g.Edges, GEdge{From: "src:external", To: "agent", Observed: true})
	pathSev := map[string]string{} // server -> worst path severity
	for _, p := range env.AttackPaths {
		for _, s := range p.Servers {
			if sevRank(p.Severity) > sevRank(pathSev[s]) {
				pathSev[s] = p.Severity
			}
		}
	}
	for _, s := range env.Servers {
		id := "srv:" + s.Name
		add(GNode{ID: id, Label: s.Name, Kind: "server", Meta: strings.Join(s.Capabilities, ", "), Boundary: "AGENT CONTEXT"})
		g.Edges = append(g.Edges, GEdge{From: "agent", To: id, Observed: observed["agent->"+s.Name], Severity: pathSev[s.Name]})
		for _, d := range s.Destinations {
			did := "dst:" + d
			add(GNode{ID: did, Label: d, Kind: "destination", Boundary: "EXTERNAL NETWORK"})
			g.Edges = append(g.Edges, GEdge{From: id, To: did, Label: "sends", Severity: pathSev[s.Name]})
		}
	}
	// Credential directories collapse into one node: nine boxes for ~/.ssh,
	// ~/.aws, ~/.gnupg ... say nothing more than one box that lists them.
	var credPaths []string
	for _, r := range env.SensitiveResources {
		if r.Kind == "credentials" {
			credPaths = append(credPaths, r.Path)
		}
	}
	for _, r := range env.SensitiveResources {
		rid := "res:" + r.Kind + ":" + r.Path
		label := r.Path
		boundary := "LOCAL MACHINE"
		persists := false
		switch r.Kind {
		case "agent-state":
			rid = "res:agent-state"
			label = "agent config, hooks, instructions"
			boundary = "PERSISTENT STATE"
			persists = true
		case "credentials":
			rid = "res:credentials"
			label = "credentials: " + strings.Join(firstN(credPaths, 3), ", ")
			if len(credPaths) > 3 {
				label += fmt.Sprintf(" +%d", len(credPaths)-3)
			}
		case "database":
			boundary = "DATABASE"
		}
		add(GNode{ID: rid, Label: label, Kind: "resource", Meta: r.Kind, Boundary: boundary, Persists: persists})
		for _, via := range r.Via {
			g.Edges = append(g.Edges, GEdge{From: "srv:" + via, To: rid, Label: r.Access, Severity: pathSev[via], Persists: persists && strings.Contains(r.Access, "write")})
		}
	}
	// Dedupe edges.
	seen := map[string]bool{}
	var edges []GEdge
	for _, e := range g.Edges {
		k := e.From + ">" + e.To + ">" + e.Label
		if !seen[k] {
			seen[k] = true
			edges = append(edges, e)
		}
	}
	g.Edges = edges
	if g.Nodes == nil {
		g.Nodes = []GNode{}
	}
	if g.Edges == nil {
		g.Edges = []GEdge{}
	}
	return g
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func worstName(s rules.Severity) string { return s.String() }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func humanWindow(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	return d.String()
}

func firstN(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}
