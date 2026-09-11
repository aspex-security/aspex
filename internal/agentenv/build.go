package agentenv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/hooks"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/skills"
)

// Options controls Build. Zero values mean "this machine".
type Options struct {
	Home string // home directory; defaults to the current user's
	Cwd  string // project directory; "" disables project-scoped discovery
	// SkipLocalState disables hooks/skills/instruction discovery from disk.
	// Set when building an environment from configs that live elsewhere
	// (a git revision, a corpus scenario) so the machine's own state does not
	// leak into a comparison.
	SkipLocalState bool
	// Local, when non-nil, supplies hooks/skills/instructions directly instead
	// of discovering them (a git revision, a corpus scenario). Implies
	// SkipLocalState for discovery.
	Local *LocalState
}

// LocalState is pre-discovered hooks, skills and instruction files.
type LocalState struct {
	Hooks        []hooks.Hook
	Skills       []skills.Skill
	Instructions []Instruction
}

// Build assembles the environment from inspected servers plus the local
// hooks, skills and instruction files. It is pure with respect to its inputs
// and the filesystem paths it reads; two calls over the same state produce
// byte-identical JSON.
func Build(servers []*inspect.Server, opts Options) Environment {
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	env := Environment{SchemaVersion: SchemaVersion, Static: true}

	caps, chains := attackpath.AnalyzeWithOptions(servers, attackpath.Options{Home: home})
	capByName := map[string]attackpath.ServerCapabilities{}
	for _, c := range caps {
		capByName[c.Client+"\x00"+c.ServerName] = c
	}

	agents := map[string]bool{}
	for _, srv := range servers {
		if !srv.StaticOnly && len(srv.Tools) > 0 {
			env.Static = false
		}
		agents[srv.Entry.Client] = true
		env.Servers = append(env.Servers, buildServer(srv, capByName[srv.Entry.Client+"\x00"+srv.Entry.Name]))
	}
	for a := range agents {
		env.Agents = append(env.Agents, Agent{Name: agentDisplayName(a), Client: a})
	}

	if opts.Local != nil {
		attachLocal(&env, hooks.Analyze(opts.Local.Hooks), opts.Local.Skills, opts.Local.Instructions)
	} else if !opts.SkipLocalState {
		for _, f := range hooks.Analyze(hooks.Discover(home, opts.Cwd)) {
			env.Hooks = append(env.Hooks, Hook{
				Event: f.Hook.Event, Matcher: f.Hook.Matcher, Command: f.Hook.Command,
				Source: f.Hook.Source, Scope: f.Hook.Scope, Hash: shortHash([]byte(f.Hook.Command)),
				Severity: f.Severity, Judgment: f.Title,
			})
		}
		for _, sk := range skills.Discover(home, opts.Cwd) {
			env.Skills = append(env.Skills, Skill{
				Name: sk.Name, Path: sk.Path, Scope: sk.Scope, ContentHash: sk.ContentHash,
				Scripts: sk.Scripts, Destinations: sk.Destinations, Executes: sk.Executes,
			})
		}
		env.Instructions = discoverInstructions(home, opts.Cwd)
		if len(env.Hooks) > 0 || len(env.Skills) > 0 {
			agents["claude-code"] = true
			if !hasAgent(env.Agents, "claude-code") {
				env.Agents = append(env.Agents, Agent{Name: agentDisplayName("claude-code"), Client: "claude-code"})
			}
		}
	}

	env.AttackPaths = chains
	env.SensitiveResources = deriveResources(env.Servers, home)
	env.Destinations = deriveDestinations(env)
	env.BlastRadius = deriveBlastRadius(env)
	sortEnv(&env)
	return env
}

func attachLocal(env *Environment, hf []hooks.Finding, sks []skills.Skill, ins []Instruction) {
	for _, f := range hf {
		env.Hooks = append(env.Hooks, Hook{
			Event: f.Hook.Event, Matcher: f.Hook.Matcher, Command: f.Hook.Command,
			Source: f.Hook.Source, Scope: f.Hook.Scope, Hash: shortHash([]byte(f.Hook.Command)),
			Severity: f.Severity, Judgment: f.Title,
		})
	}
	for _, sk := range sks {
		env.Skills = append(env.Skills, Skill{
			Name: sk.Name, Path: sk.Path, Scope: sk.Scope, ContentHash: sk.ContentHash,
			Scripts: sk.Scripts, Destinations: sk.Destinations, Executes: sk.Executes,
		})
	}
	env.Instructions = append(env.Instructions, ins...)
	if (len(env.Hooks) > 0 || len(env.Skills) > 0) && !hasAgent(env.Agents, "claude-code") {
		env.Agents = append(env.Agents, Agent{Name: agentDisplayName("claude-code"), Client: "claude-code"})
	}
}

func hasAgent(list []Agent, client string) bool {
	for _, a := range list {
		if a.Client == client {
			return true
		}
	}
	return false
}

func agentDisplayName(client string) string {
	switch client {
	case "claude":
		return "Claude Desktop"
	case "claude-code":
		return "Claude Code"
	case "cursor":
		return "Cursor"
	case "windsurf":
		return "Windsurf"
	case "vscode":
		return "VS Code"
	case "cline":
		return "Cline"
	case "roo-cline":
		return "Roo Code"
	case "continue":
		return "Continue"
	case "zed":
		return "Zed"
	}
	return client
}

var pinnedRe = regexp.MustCompile(`@\d+\.\d+|==\d|@v?\d+\.\d+\.\d+`)

// pkgScopedRe is tried first so a wrapper binary named like "onyx-mcp-gw"
// does not shadow the real "@scope/server-x" it launches.
var pkgScopedRe = regexp.MustCompile(`@[a-z0-9-]+/[a-z0-9._-]+`)
var pkgRe = regexp.MustCompile(`\b[a-z0-9][a-z0-9._-]*(?:-mcp|mcp-[a-z0-9._-]+|server-[a-z0-9._-]+)[a-z0-9._-]*`)

func buildServer(srv *inspect.Server, sc attackpath.ServerCapabilities) Server {
	e := srv.Entry
	s := Server{
		Name: e.Name, Client: e.Client, Command: e.Command, Args: append([]string(nil), e.Args...),
		URL: e.URL, ConfigPath: e.ConfigPath, EnvKeys: sortedCopy(e.EnvKeys), Static: sc.Static || len(srv.Tools) == 0,
	}
	cmdline := strings.ToLower(e.Command + " " + strings.Join(e.Args, " "))
	if m := pkgScopedRe.FindString(cmdline); m != "" {
		s.Package = m
	} else if m := pkgRe.FindString(cmdline); m != "" {
		s.Package = m
	}
	s.Pinned = pinnedRe.MatchString(cmdline)
	s.Identity = shortHash([]byte(e.Command + "\x00" + strings.Join(e.Args, "\x00") + "\x00" + e.URL))

	for _, t := range srv.Tools {
		tool := Tool{Name: t.Name, Description: t.Description}
		if len(t.InputSchema) > 0 {
			tool.SchemaHash = shortHash(canonicalJSON(t.InputSchema))
		}
		s.Tools = append(s.Tools, tool)
	}
	sort.Slice(s.Tools, func(i, j int) bool { return s.Tools[i].Name < s.Tools[j].Name })

	for _, c := range attackpath.AllCapabilities {
		if sc.Has(c) {
			s.Capabilities = append(s.Capabilities, c.String())
		}
	}
	s.Roots = sortedCopy(sc.Roots)
	if sc.Has(attackpath.CapReadFile) || sc.Has(attackpath.CapWriteFile) {
		s.Scope = sc.Scope.String()
	}
	s.EgressOpen = sc.Has(attackpath.CapNetworkSend) && !sc.EgressConstrained
	s.Destinations = serverDestinations(cmdline, sc)
	s.StateWrites = append([]attackpath.AgentStateTarget(nil), sc.StateWrites...)
	sort.Slice(s.StateWrites, func(i, j int) bool { return s.StateWrites[i].Path < s.StateWrites[j].Path })

	// Fingerprint: identity plus the full tool surface. A changed description
	// or schema changes the fingerprint; that is the rug-pull signal.
	h := sha256.New()
	h.Write([]byte(s.Identity))
	for _, t := range s.Tools {
		h.Write([]byte(t.Name + "\x00" + t.Description + "\x00" + t.SchemaHash + "\x00"))
	}
	s.Fingerprint = hex.EncodeToString(h.Sum(nil))[:16]
	return s
}

// knownDestinations maps package tokens to the destination a channel server
// reaches. Only services whose destination is fixed by the package appear;
// open egress is represented separately.
var knownDestinations = []struct {
	token string
	host  string
}{
	{"github", "github.com"}, {"gitlab", "gitlab.com"}, {"slack", "slack.com"},
	{"brave", "api.search.brave.com"}, {"notion", "api.notion.com"}, {"linear", "api.linear.app"},
	{"jira", "atlassian.net"}, {"sentry", "sentry.io"}, {"stripe", "api.stripe.com"},
	{"sendgrid", "api.sendgrid.com"}, {"twilio", "api.twilio.com"}, {"clickup", "api.clickup.com"},
}

func serverDestinations(cmdline string, sc attackpath.ServerCapabilities) []string {
	var out []string
	if sc.Has(attackpath.CapNetworkSend) || sc.Has(attackpath.CapBrowser) {
		if sc.EgressConstrained {
			out = append(out, "allowlisted destinations")
		} else {
			out = append(out, "arbitrary https")
		}
	}
	if sc.Has(attackpath.CapExternalSend) || sc.Has(attackpath.CapUntrustedIngress) || sc.Has(attackpath.CapEmailSend) {
		for _, kd := range knownDestinations {
			if strings.Contains(cmdline, kd.token) {
				out = append(out, kd.host)
			}
		}
		if sc.Has(attackpath.CapEmailSend) {
			out = append(out, "email recipients")
		}
	}
	return uniqSorted(out)
}

// instructionFiles are the persistent files an agent loads. Hashed so a
// verify/diff can say "your instructions changed" without storing content.
func discoverInstructions(home, cwd string) []Instruction {
	type cand struct{ path, kind, scope string }
	cands := []cand{
		{filepath.Join(home, ".claude", "CLAUDE.md"), "instructions", "user"},
		{filepath.Join(home, ".claude.json"), "mcp-config", "user"},
		{filepath.Join(home, ".claude", "settings.json"), "hooks", "user"},
		{filepath.Join(home, ".cursor", "mcp.json"), "mcp-config", "user"},
		{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "mcp-config", "user"},
		{filepath.Join(home, ".codeium", "windsurf", "memories", "global_rules.md"), "instructions", "user"},
	}
	if cwd != "" {
		cands = append(cands,
			cand{filepath.Join(cwd, "CLAUDE.md"), "instructions", "project"},
			cand{filepath.Join(cwd, ".claude", "CLAUDE.md"), "instructions", "project"},
			cand{filepath.Join(cwd, ".cursorrules"), "instructions", "project"},
			cand{filepath.Join(cwd, ".mcp.json"), "mcp-config", "project"},
			cand{filepath.Join(cwd, ".claude", "settings.json"), "hooks", "project"},
			cand{filepath.Join(cwd, ".vscode", "mcp.json"), "mcp-config", "project"},
			cand{filepath.Join(cwd, "AGENTS.md"), "instructions", "project"},
			cand{filepath.Join(cwd, ".windsurfrules"), "instructions", "project"},
		)
		// Rule directories: Cursor (.cursor/rules/*.mdc) and Windsurf
		// (.windsurf/rules/*). Each file is its own instruction, so a change
		// to one rule is attributed to that rule.
		for _, dir := range []string{filepath.Join(cwd, ".cursor", "rules"), filepath.Join(cwd, ".windsurf", "rules")} {
			for _, f := range ruleFiles(dir) {
				cands = append(cands, cand{f, "instructions", "project"})
			}
		}
	}
	var out []Instruction
	for _, c := range cands {
		data, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		out = append(out, Instruction{Path: c.path, Kind: c.kind, Scope: c.scope, Hash: shortHash(data)})
	}
	return out
}

// ruleFiles lists instruction rule files under dir (one level), sorted.
func ruleFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".mdc" || ext == ".md" || ext == "" || ext == ".txt" {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

var credentialDirs = []string{".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gcloud", ".azure", ".netrc", ".npmrc"}

func deriveResources(servers []Server, home string) []Resource {
	byPath := map[string]*Resource{}
	add := func(path, kind, via, access string) {
		r, ok := byPath[path]
		if !ok {
			r = &Resource{Path: path, Kind: kind, Access: access}
			byPath[path] = r
		}
		r.Via = append(r.Via, via)
		if r.Access != access && (access == "read-write" || r.Access == "read-write" || (r.Access == "read" && access == "write") || (r.Access == "write" && access == "read")) {
			r.Access = "read-write"
		}
	}
	for _, s := range servers {
		caps := map[string]bool{}
		for _, c := range s.Capabilities {
			caps[c] = true
		}
		access := ""
		switch {
		case caps["file-read"] && caps["file-write"]:
			access = "read-write"
		case caps["file-read"]:
			access = "read"
		case caps["file-write"]:
			access = "write"
		}
		if access != "" && (s.Scope == "sensitive" || s.Scope == "unknown") {
			for _, d := range credentialDirs {
				add("~/"+d, "credentials", s.Name, access)
			}
			add("browser profiles", "browser-profile", s.Name, access)
		}
		if caps["credential-read"] || caps["env-read"] {
			add("environment variables and secret stores", "credentials", s.Name, "read")
		}
		for _, t := range s.StateWrites {
			add(shortenHome(t.Path, home), "agent-state", s.Name, "write")
		}
		if caps["data-read"] && (caps["db-write"] || strings.Contains(strings.ToLower(s.Package+s.Command+strings.Join(s.Args, " ")), "postgres") || strings.Contains(strings.ToLower(s.Package), "sql")) {
			acc := "read"
			if caps["db-write"] {
				acc = "read-write"
			}
			add("database via "+s.Name, "database", s.Name, acc)
		}
	}
	var out []Resource
	for _, r := range byPath {
		r.Via = uniqSorted(r.Via)
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func deriveDestinations(env Environment) []string {
	var out []string
	for _, s := range env.Servers {
		out = append(out, s.Destinations...)
	}
	for _, sk := range env.Skills {
		out = append(out, sk.Destinations...)
	}
	return uniqSorted(out)
}

// deriveBlastRadius states how far an instruction the agent follows could
// reach. Every reason is listed, present or not, so the level is auditable.
func deriveBlastRadius(env Environment) BlastRadius {
	var credRead, sensitiveRead, openEgress, channel, exec, persistExec, persistInstr, dbWrite, ingress bool
	for _, s := range env.Servers {
		caps := map[string]bool{}
		for _, c := range s.Capabilities {
			caps[c] = true
		}
		if caps["credential-read"] || caps["env-read"] {
			credRead = true
		}
		if caps["file-read"] && (s.Scope == "sensitive" || s.Scope == "unknown") {
			sensitiveRead = true
		}
		if s.EgressOpen {
			openEgress = true
		}
		if caps["external-send"] || caps["email-send"] || (caps["network-send"] && !s.EgressOpen) {
			channel = true
		}
		if caps["shell-exec"] {
			exec = true
		}
		if caps["untrusted-ingress"] || caps["browser"] {
			ingress = true
		}
		if caps["db-write"] {
			dbWrite = true
		}
		for _, t := range s.StateWrites {
			if t.Executes {
				persistExec = true
			} else {
				persistInstr = true
			}
		}
	}
	for _, h := range env.Hooks {
		if h.Severity == "critical" || h.Severity == "high" {
			exec = true
		}
	}
	worst := ""
	for _, p := range env.AttackPaths {
		if sevRank(p.Severity) > sevRank(worst) {
			worst = p.Severity
		}
	}

	level := "LOW"
	switch {
	case worst == "critical", exec && openEgress, (credRead || sensitiveRead) && openEgress, persistExec && ingress:
		level = "HIGH"
	case worst == "high", exec, openEgress, credRead || sensitiveRead, persistExec, dbWrite, channel && (sensitiveRead || credRead):
		level = "MEDIUM"
	}
	if len(env.Servers) == 0 && len(env.Hooks) == 0 && len(env.Skills) == 0 {
		level = "NONE"
	}
	return BlastRadius{Level: level, Why: []Reason{
		{credRead || sensitiveRead, "reads credentials or sensitive files"},
		{openEgress, "arbitrary external network egress"},
		{channel && !openEgress, "sends data to an external service (fixed destination)"},
		{exec, "command execution"},
		{persistExec, "can rewrite agent config or hooks that run at next start"},
		{persistInstr, "can rewrite agent instructions or memory"},
		{dbWrite, "destructive database capability"},
		{ingress, "external content enters the agent's context"},
	}}
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

func sortEnv(env *Environment) {
	sort.Slice(env.Agents, func(i, j int) bool { return env.Agents[i].Client < env.Agents[j].Client })
	sort.Slice(env.Servers, func(i, j int) bool {
		if env.Servers[i].Client != env.Servers[j].Client {
			return env.Servers[i].Client < env.Servers[j].Client
		}
		return env.Servers[i].Name < env.Servers[j].Name
	})
	sort.Slice(env.Hooks, func(i, j int) bool {
		a, b := env.Hooks[i], env.Hooks[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Event != b.Event {
			return a.Event < b.Event
		}
		return a.Command < b.Command
	})
	sort.Slice(env.Skills, func(i, j int) bool { return env.Skills[i].Path < env.Skills[j].Path })
	sort.Slice(env.Instructions, func(i, j int) bool { return env.Instructions[i].Path < env.Instructions[j].Path })
	sort.Slice(env.AttackPaths, func(i, j int) bool {
		a, b := env.AttackPaths[i], env.AttackPaths[j]
		if sevRank(a.Severity) != sevRank(b.Severity) {
			return sevRank(a.Severity) > sevRank(b.Severity)
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return strings.Join(a.Servers, ",") < strings.Join(b.Servers, ",")
	})
	// Never nil slices: a lockfile must read the same whether empty or absent.
	if env.Agents == nil {
		env.Agents = []Agent{}
	}
	if env.Servers == nil {
		env.Servers = []Server{}
	}
	if env.Hooks == nil {
		env.Hooks = []Hook{}
	}
	if env.Skills == nil {
		env.Skills = []Skill{}
	}
	if env.Instructions == nil {
		env.Instructions = []Instruction{}
	}
	if env.SensitiveResources == nil {
		env.SensitiveResources = []Resource{}
	}
	if env.Destinations == nil {
		env.Destinations = []string{}
	}
	if env.AttackPaths == nil {
		env.AttackPaths = []attackpath.AttackChain{}
	}
	for i := range env.Servers {
		if env.Servers[i].Tools == nil {
			env.Servers[i].Tools = []Tool{}
		}
		if env.Servers[i].Capabilities == nil {
			env.Servers[i].Capabilities = []string{}
		}
	}
}

// ---- helpers ---------------------------------------------------------------

func shortHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

// canonicalJSON re-encodes JSON with sorted keys so semantically equal schemas
// hash equally regardless of key order or whitespace.
func canonicalJSON(raw []byte) []byte {
	var v interface{}
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	out, err := json.Marshal(v) // encoding/json sorts map keys
	if err != nil {
		return raw
	}
	return out
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func uniqSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func shortenHome(p, home string) string {
	if home != "" && strings.HasPrefix(p, home) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

// Server returns the server with the given client and name, or nil.
func (e *Environment) Server(client, name string) *Server {
	for i := range e.Servers {
		if e.Servers[i].Client == client && e.Servers[i].Name == name {
			return &e.Servers[i]
		}
	}
	return nil
}

// HasCapability reports whether any server has the named capability.
func (e *Environment) HasCapability(cap string) []string {
	var via []string
	for _, s := range e.Servers {
		for _, c := range s.Capabilities {
			if c == cap {
				via = append(via, s.Name)
			}
		}
	}
	return via
}
