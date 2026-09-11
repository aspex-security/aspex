// Package aspexmcp exposes Aspex's analysis to an AI agent as a read-only MCP
// server over stdio. A coding agent can ask "what would adding this server do
// to my attack surface?" before it edits .mcp.json. Nothing here writes,
// executes, or changes Aspex configuration; every tool is a pure function of
// the current environment (or of JSON the caller supplies).
package aspexmcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/inspect"
)

// Loader returns the current environment. Injected so tests never touch the
// machine and the CLI can honor --no-exec / --clients.
type Loader func(ctx context.Context) agentenv.Environment

// InputsLoader returns the inspected inputs so simulation can rebuild
// before/after through the same pipeline. Optional; without it the
// simulation tools report unavailability.
type InputsLoader func(ctx context.Context) agentenv.Inputs

// Server is a minimal MCP server (initialize, tools/list, tools/call).
type Server struct {
	load    Loader
	version string
	home    string
	// cached environment for the life of the process; scans are expensive
	// and the agent typically asks several questions in a row.
	env    *agentenv.Environment
	logger io.Writer
	loadIn InputsLoader
	inputs *agentenv.Inputs
}

// WithInputs enables the simulation-backed tools.
func (s *Server) WithInputs(l InputsLoader) *Server {
	s.loadIn = l
	return s
}

// New creates a server.
func New(load Loader, version string, logger io.Writer) *Server {
	home, _ := os.UserHomeDir()
	return &Server{load: load, version: version, home: home, logger: logger}
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Tool describes one exposed tool.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

func schema(props map[string]string, required ...string) json.RawMessage {
	p := map[string]interface{}{}
	for k, desc := range props {
		p[k] = map[string]string{"type": "string", "description": desc}
	}
	m := map[string]interface{}{"type": "object", "properties": p}
	if len(required) > 0 {
		m["required"] = required
	}
	b, _ := json.Marshal(m)
	return b
}

// Tools is the fixed, read-only tool list.
var Tools = []Tool{
	{"aspex_scan", "Summarize the local agent environment: agents, MCP servers with capabilities, hooks, skills, blast radius (with reasons), attack path counts. Read-only.", schema(nil)},
	{"aspex_get_capabilities", "List every configured MCP server with its classified capabilities, filesystem scope, egress, and the agent-state files it can write.", schema(nil)},
	{"aspex_get_attack_paths", "List cross-server attack paths (compositions of capabilities) with severity, confidence, evidence, impact and remediation.", schema(nil)},
	{"aspex_explain", "Answer a security question about this environment deterministically from the capability graph, e.g. 'Can external content reach my AWS credentials?'. Returns YES / NO COMPLETE PATH with conditions and what is not proven.", schema(map[string]string{"question": "The question in plain English"}, "question")},
	{"aspex_verify", "Compare the current environment with a lockfile (default .aspex.lock in the working directory) and report security-classified drift.", schema(map[string]string{"lockfile": "Path to the lockfile (optional)"})},
	{"aspex_security_impact", "Before you change agent configuration: pass the proposed .mcp.json content (and optionally the proposed .claude/settings.json) and get the security impact versus the current environment: new capabilities, new attack paths, blast radius before and after.", schema(map[string]string{"mcp_json": "Proposed .mcp.json content (Claude Code / Cursor mcpServers format)", "settings_json": "Proposed .claude/settings.json content with hooks (optional)"}, "mcp_json")},
	{"aspex_simulate_change", "Counterfactual: what would removing or restricting something do? Pass one or more changes as 'remove-server=NAME', 'restrict-filesystem=[SERVER=]ROOT', 'deny-network=[SERVER|*]', 'remove-tool=SERVER.TOOL', 'remove-hook=EVENT', 'remove-skill=NAME' (comma-separated). Returns blast radius before/after, attack paths removed/added, capability deltas. Nothing is modified.", schema(map[string]string{"changes": "Comma-separated change specs"}, "changes")},
	{"aspex_explain_path", "Explain a finding id (AP001-AP006): what it is, why Aspex reports it in this environment with OBSERVED CONFIGURATION / INFERRED / NOT OBSERVED evidence, and the concrete controls that break it, each simulated.", schema(map[string]string{"id": "Attack path id, e.g. AP003"}, "id")},
	{"aspex_data_flow", "Follow the data. direction 'forward' with a resource ('~/.aws/credentials', 'ssh keys', 'database') lists every sink it could reach; direction 'reverse' with a destination ('Slack', 'github', 'the internet') lists the sensitive resources that could reach it. Flows are POTENTIAL unless the trace shows the tool was invoked; Aspex never claims data moved.", schema(map[string]string{"direction": "forward | reverse", "subject": "resource or destination"}, "direction", "subject")},
}

// Serve reads JSON-RPC messages line by line from r and writes responses to w.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	enc := json.NewEncoder(w)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req rpcReq
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			enc.Encode(rpcResp{JSONRPC: "2.0", Error: &rpcError{-32700, "parse error"}})
			continue
		}
		if req.ID == nil { // notification
			continue
		}
		resp := s.handle(ctx, req)
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

// Handle processes one request (exported for tests).
func (s *Server) Handle(ctx context.Context, req []byte) []byte {
	var r rpcReq
	if err := json.Unmarshal(req, &r); err != nil {
		b, _ := json.Marshal(rpcResp{JSONRPC: "2.0", Error: &rpcError{-32700, "parse error"}})
		return b
	}
	b, _ := json.Marshal(s.handle(ctx, r))
	return b
}

func (s *Server) handle(ctx context.Context, req rpcReq) rpcResp {
	resp := rpcResp{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo":      map[string]string{"name": "aspex", "version": s.version},
			"instructions":    "Aspex is a read-only local security debugger for AI agents. Call aspex_security_impact before editing .mcp.json, hooks, or skills; call aspex_explain to check whether a capability composition exists. Nothing here changes the machine.",
		}
	case "ping":
		resp.Result = map[string]interface{}{}
	case "tools/list":
		resp.Result = map[string]interface{}{"tools": Tools}
	case "tools/call":
		var p struct {
			Name string          `json:"name"`
			Args json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &rpcError{-32602, "invalid params"}
			return resp
		}
		out, err := s.call(ctx, p.Name, p.Args)
		if err != nil {
			resp.Result = map[string]interface{}{"content": []map[string]string{{"type": "text", "text": "error: " + err.Error()}}, "isError": true}
			return resp
		}
		resp.Result = map[string]interface{}{"content": []map[string]string{{"type": "text", "text": out}}}
	default:
		resp.Error = &rpcError{-32601, "method not found: " + req.Method}
	}
	return resp
}

func (s *Server) environment(ctx context.Context) agentenv.Environment {
	if s.env == nil {
		if s.loadIn != nil {
			in := s.loadIn(ctx)
			s.inputs = &in
			e := agentenv.Build(in.Servers, in.Options)
			s.env = &e
		} else {
			e := s.load(ctx)
			s.env = &e
		}
	}
	return *s.env
}

func pretty(v interface{}) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return string(b), err
}

func (s *Server) call(ctx context.Context, name string, args json.RawMessage) (string, error) {
	var a map[string]string
	if len(args) > 0 {
		json.Unmarshal(args, &a)
	}
	env := s.environment(ctx)
	switch name {
	case "aspex_scan":
		type srv struct {
			Name, Client string
			Capabilities []string
			Scope        string `json:",omitempty"`
			Tools        int
		}
		var servers []srv
		for _, x := range env.Servers {
			servers = append(servers, srv{x.Name, x.Client, x.Capabilities, x.Scope, len(x.Tools)})
		}
		counts := map[string]int{}
		for _, p := range env.AttackPaths {
			counts[p.Severity]++
		}
		return pretty(map[string]interface{}{
			"agents": env.Agents, "servers": servers, "hooks": len(env.Hooks), "skills": len(env.Skills),
			"blast_radius": env.BlastRadius, "attack_paths": counts, "static": env.Static,
			"note": "Capabilities are what the servers can do; attack paths are compositions an instruction could walk. Nothing here says anything happened.",
		})
	case "aspex_get_capabilities":
		return pretty(env.Servers)
	case "aspex_get_attack_paths":
		return pretty(env.AttackPaths)
	case "aspex_explain":
		q := a["question"]
		if q == "" {
			return "", fmt.Errorf("question is required")
		}
		ans, ok := agentenv.Explain(env, q)
		if !ok {
			return pretty(map[string]interface{}{"understood": false, "supported_questions": agentenv.SupportedQuestions})
		}
		return pretty(ans)
	case "aspex_verify":
		p := a["lockfile"]
		if p == "" {
			p = agentenv.LockFileName
		}
		if !strings.HasSuffix(p, ".lock") && !strings.HasSuffix(p, ".json") {
			return "", fmt.Errorf("lockfile must be a .lock or .json file")
		}
		locked, err := agentenv.ReadLock(p)
		if err != nil {
			return "", err
		}
		d := agentenv.Compare(locked, env)
		return pretty(map[string]interface{}{"drift": !d.Empty(), "worst": d.Worst(), "result": d})
	case "aspex_security_impact":
		return s.securityImpact(ctx, env, a["mcp_json"], a["settings_json"])
	case "aspex_simulate_change":
		if s.inputs == nil {
			return "", fmt.Errorf("simulation inputs unavailable in this server mode")
		}
		var changes []agentenv.HypotheticalChange
		for _, spec := range strings.Split(a["changes"], ",") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			k, v, _ := strings.Cut(spec, "=")
			ch, err := agentenv.ParseChange(agentenv.ChangeKind(k), v)
			if err != nil {
				return "", err
			}
			changes = append(changes, ch)
		}
		if len(changes) == 0 {
			return "", fmt.Errorf("no changes given")
		}
		sim := agentenv.Simulate(*s.inputs, changes)
		return pretty(map[string]interface{}{
			"changes": sim.Changes, "unmatched": sim.Unmatched,
			"blast_radius_before": sim.Before.BlastRadius.Level, "blast_radius_after": sim.After.BlastRadius.Level,
			"attack_paths_before": len(sim.Before.AttackPaths), "attack_paths_after": len(sim.After.AttackPaths),
			"attack_paths_removed": sim.Drift.PathsRemoved, "attack_paths_added": sim.Drift.PathsAdded,
			"capability_changes": sim.Capabilities, "note": "No configuration was modified.",
		})
	case "aspex_explain_path":
		fe, ok := agentenv.ExplainFinding(env, a["id"], "")
		if !ok {
			return "", fmt.Errorf("unknown path id %q (AP001-AP006)", a["id"])
		}
		if fe.Present && s.inputs != nil {
			for i := range fe.Instances {
				fe.Controls = agentenv.Evaluate(*s.inputs, fe.Instances[i], fe.Controls)
			}
		}
		return pretty(fe)
	case "aspex_data_flow":
		switch a["direction"] {
		case "forward":
			return pretty(agentenv.Forward(env, a["subject"], nil))
		case "reverse":
			return pretty(agentenv.Reverse(env, a["subject"], nil))
		}
		return "", fmt.Errorf("direction must be forward or reverse")
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

// securityImpact builds a hypothetical environment: the current one with the
// proposed project config in place of the current project config, analyzed
// statically (the proposal is never launched), and diffs it.
func (s *Server) securityImpact(ctx context.Context, current agentenv.Environment, mcpJSON, settingsJSON string) (string, error) {
	if strings.TrimSpace(mcpJSON) == "" {
		return "", fmt.Errorf("mcp_json is required")
	}
	cwd, _ := os.Getwd()
	entries, err := discover.ParseConfigBytes(discover.ClientClaudeCode, filepath.Join(cwd, ".mcp.json"), []byte(mcpJSON))
	if err != nil {
		return "", fmt.Errorf("mcp_json: %w", err)
	}
	// Keep every current server that is not project-scoped Claude Code (those
	// are what the proposal replaces), add the proposal's servers.
	var keep []*inspect.Server
	for _, srv := range current.Servers {
		if srv.ConfigPath == filepath.Join(cwd, ".mcp.json") {
			continue // the proposal replaces this file
		}
		keep = append(keep, &inspect.Server{Entry: discover.ServerEntry{Name: srv.Name, Client: srv.Client, Command: srv.Command, Args: srv.Args, URL: srv.URL, EnvKeys: srv.EnvKeys, ConfigPath: srv.ConfigPath}, StaticOnly: true})
	}
	proposed := inspect.InspectAll(ctx, entries, inspect.Options{NoExec: true}, nil)
	all := append(keep, proposed...)
	local := &agentenv.LocalState{}
	if strings.TrimSpace(settingsJSON) != "" {
		local.Hooks = hooksFromSettings(settingsJSON)
	}
	opts := agentenv.Options{Home: s.home, Cwd: cwd, Local: local}
	after := agentenv.Build(all, opts)
	// Compare against the current environment rebuilt with the same static
	// treatment, so tool-list differences do not masquerade as drift.
	var cur []*inspect.Server
	for _, srv := range current.Servers {
		cur = append(cur, &inspect.Server{Entry: discover.ServerEntry{Name: srv.Name, Client: srv.Client, Command: srv.Command, Args: srv.Args, URL: srv.URL, EnvKeys: srv.EnvKeys, ConfigPath: srv.ConfigPath}, StaticOnly: true})
	}
	before := agentenv.Build(cur, agentenv.Options{Home: s.home, Cwd: cwd, Local: &agentenv.LocalState{}})
	d := agentenv.Compare(before, after)
	verdict := "no new risk"
	switch {
	case len(d.PathsAdded) > 0 && worstSeverity(d.PathsAdded) == "critical":
		verdict = "introduces a CRITICAL attack path"
	case len(d.PathsAdded) > 0:
		verdict = "introduces a " + strings.ToUpper(worstSeverity(d.PathsAdded)) + " attack path"
	case d.Worst() == agentenv.ClassSuspicious:
		verdict = "contains suspicious content"
	case d.Worst() == agentenv.ClassSecurityRelevant:
		verdict = "adds security-relevant capability"
	}
	return pretty(map[string]interface{}{
		"verdict": verdict, "blast_radius_before": d.BlastBefore.Level, "blast_radius_after": d.BlastAfter.Level,
		"changes": d.SecurityRelevant(), "attack_paths_added": d.PathsAdded, "attack_paths_removed": d.PathsRemoved,
		"note": "Static analysis of the proposal; nothing was launched. Existing user-level servers are included so compositions with them are visible.",
	})
}

func worstSeverity(cs []attackpath.AttackChain) string {
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	w := ""
	for _, c := range cs {
		if rank[c.Severity] > rank[w] {
			w = c.Severity
		}
	}
	return w
}
