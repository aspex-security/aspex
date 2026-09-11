// Package attackpath finds dangerous compositions of otherwise legitimate
// capabilities across the MCP servers an agent can reach.
//
// A developer already knows that a filesystem server can read files and that a
// fetch server can reach the internet. What the two together mean is a path
// from ~/.ssh/id_rsa to an arbitrary external destination that any injected
// instruction can walk. Naming that composition, with the evidence for each
// half, is the whole job of this package.
//
// Three concepts are kept apart on purpose:
//
//   - a Capability is something a server can do (read files under /Users/x);
//   - an Evidence item records how we know it (the tool, the allowed root);
//   - an AttackChain is a security conclusion drawn from a composition of
//     capabilities, with a severity that reflects the composition and a
//     confidence that reflects the quality of the evidence.
//
// Capabilities come from live tool lists when a server was launched, and from
// a small table of well-known packages when it was not (static scans and the
// snapshot). Static inference is reported at medium confidence.
package attackpath

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/mcpclient"
)

// Capability is one thing a server can do. Bits so a server's set is cheap to test.
type Capability uint32

const (
	CapNone Capability = 0
	// CapReadFile: reads local files. Scope decides how dangerous: see FileScope.
	CapReadFile Capability = 1 << iota
	// CapWriteFile: creates or modifies local files. Scope decides what it can reach.
	CapWriteFile
	// CapShellExec: runs commands or code on this machine.
	CapShellExec
	// CapNetworkSend: can reach arbitrary network destinations (HTTP, browser).
	CapNetworkSend
	// CapCredentialRead: tools that explicitly read secrets, tokens, keys, or keychains.
	CapCredentialRead
	// CapPersistence: writes reach startup or agent-state locations (see AgentStateWrite).
	CapPersistence
	// CapPackageInstall: installs packages.
	CapPackageInstall
	// CapReadEnv: reads process environment variables.
	CapReadEnv
	// CapDatabaseWrite: writes to a database.
	CapDatabaseWrite
	// CapEmailSend: sends email.
	CapEmailSend
	// CapExternalSend: posts to an authenticated external channel (Slack, GitHub, webhooks).
	CapExternalSend
	// CapUntrustedIngress: brings external content into the agent's context (web fetch, browse, search).
	CapUntrustedIngress
	// CapBrowser: drives a browser, usually with the user's authenticated sessions.
	CapBrowser
	// CapDataRead: reads remote data that may be sensitive (repositories, databases, documents).
	CapDataRead
	// CapMemoryWrite: writes to a persistent memory store the agent reads back in later sessions.
	CapMemoryWrite
)

// AllCapabilities lists every capability in display order.
var AllCapabilities = []Capability{
	CapReadFile, CapWriteFile, CapShellExec, CapNetworkSend, CapCredentialRead,
	CapPersistence, CapPackageInstall, CapReadEnv, CapDatabaseWrite, CapEmailSend,
	CapExternalSend, CapUntrustedIngress, CapBrowser, CapDataRead, CapMemoryWrite,
}

// String returns the short label used in output and JSON.
func (c Capability) String() string {
	switch c {
	case CapReadFile:
		return "file-read"
	case CapWriteFile:
		return "file-write"
	case CapShellExec:
		return "shell-exec"
	case CapNetworkSend:
		return "network-send"
	case CapCredentialRead:
		return "credential-read"
	case CapPersistence:
		return "persistence-write"
	case CapPackageInstall:
		return "package-install"
	case CapReadEnv:
		return "env-read"
	case CapDatabaseWrite:
		return "db-write"
	case CapEmailSend:
		return "email-send"
	case CapExternalSend:
		return "external-send"
	case CapUntrustedIngress:
		return "untrusted-ingress"
	case CapBrowser:
		return "browser"
	case CapDataRead:
		return "data-read"
	case CapMemoryWrite:
		return "memory-write"
	}
	return "unknown"
}

// FileScope classifies what a filesystem-capable server can reach.
type FileScope int

const (
	// ScopeUnknown: the server reads or writes files but no allowed roots could be determined.
	ScopeUnknown FileScope = iota
	// ScopeProject: roots are ordinary directories (source trees, documents).
	ScopeProject
	// ScopeSensitive: a root is the home directory, the filesystem root, or a
	// directory that holds credentials (~/.ssh, ~/.aws, ...).
	ScopeSensitive
)

func (s FileScope) String() string {
	switch s {
	case ScopeProject:
		return "project"
	case ScopeSensitive:
		return "sensitive"
	}
	return "unknown"
}

// Evidence is one concrete observation that supports a capability.
type Evidence struct {
	Server string `json:"server"`
	Tool   string `json:"tool,omitempty"`   // tool name, or "" for config-derived evidence
	Detail string `json:"detail"`           // what was seen: "allowed root /Users/x (home directory)"
	Source string `json:"source,omitempty"` // "tool" | "config" | "package"
}

// AgentStateTarget is a file the agent trusts in future sessions that a
// writable root can reach.
type AgentStateTarget struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`     // "mcp-config" | "hooks" | "instructions" | "memory" | "shell-startup"
	Executes bool   `json:"executes"` // writing it yields code execution at the next session start
	// Global is true for user/home-level state that affects every project and
	// every session (e.g. ~/.claude.json). Project-local state (a repo's own
	// .mcp.json) is a smaller blast radius: you already opened that repo.
	Global bool `json:"global,omitempty"`
}

// ServerCapabilities is everything the analyzer concluded about one server.
type ServerCapabilities struct {
	ServerName string
	Client     string
	Caps       Capability
	CapTools   map[Capability][]string   // capability -> contributing tool names (kept for compatibility)
	Evidence   map[Capability][]Evidence // capability -> how we know
	Static     bool                      // capabilities inferred from the package, not a live tool list

	// Filesystem details, meaningful when CapReadFile or CapWriteFile is set.
	Roots       []string // allowed roots, expanded; empty when unknown
	Scope       FileScope
	StateWrites []AgentStateTarget // agent-state files a writable root reaches

	// EgressConstrained is true when the network tool's schema or description
	// declares a destination allowlist.
	EgressConstrained bool
}

// Has reports whether the server has capability c.
func (sc *ServerCapabilities) Has(c Capability) bool { return sc.Caps&c != 0 }

func (sc *ServerCapabilities) add(c Capability, ev Evidence) {
	sc.Caps |= c
	if sc.CapTools == nil {
		sc.CapTools = map[Capability][]string{}
	}
	if sc.Evidence == nil {
		sc.Evidence = map[Capability][]Evidence{}
	}
	if ev.Tool != "" {
		sc.CapTools[c] = appendUniq(sc.CapTools[c], ev.Tool)
	}
	ev.Server = sc.ServerName
	for _, e := range sc.Evidence[c] {
		if e == ev {
			return
		}
	}
	sc.Evidence[c] = append(sc.Evidence[c], ev)
}

// AttackChain is a security conclusion: a composition of capabilities that an
// injected or malicious instruction could walk. Severity reflects what the
// composition reaches; Confidence reflects how directly we observed each half.
type AttackChain struct {
	ID          string     `json:"id"`       // stable identifier, e.g. AP001
	Name        string     `json:"name"`     // "Potential credential exfiltration path"
	Severity    string     `json:"severity"` // critical | high | medium | low
	Confidence  string     `json:"confidence"`
	Description string     `json:"description"` // one sentence, no drama
	MITRETactic string     `json:"mitre_tactic"`
	MITRERef    string     `json:"mitre_ref"`
	Servers     []string   `json:"servers"`
	Steps       []string   `json:"steps"` // the path, one hop per line
	Evidence    []Evidence `json:"evidence"`
	Impact      string     `json:"impact"`
	Remediation string     `json:"remediation"`
}

// Options tunes analysis; zero value is fine for production use.
type Options struct {
	// Home overrides the home directory used to classify roots. Tests set it.
	Home string
}

// Analyze detects capabilities and attack chains across all inspected servers.
func Analyze(servers []*inspect.Server) ([]ServerCapabilities, []AttackChain) {
	return AnalyzeWithOptions(servers, Options{})
}

// AnalyzeWithOptions is Analyze with an explicit home directory.
func AnalyzeWithOptions(servers []*inspect.Server, opts Options) ([]ServerCapabilities, []AttackChain) {
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	caps := make([]ServerCapabilities, 0, len(servers))
	for _, srv := range servers {
		caps = append(caps, detectCapabilities(srv, home))
	}
	return caps, detectChains(caps)
}

// DetectServer returns the capabilities of a single server, including its
// filesystem scope and the agent-state files a writable root reaches. Exported
// so per-server scan rules can reason about writable agent state without
// duplicating the scope logic.
func DetectServer(srv *inspect.Server, opts Options) ServerCapabilities {
	home := opts.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return detectCapabilities(srv, home)
}

// ---------------------------------------------------------------------------
// Capability detection
// ---------------------------------------------------------------------------

// knownPackage describes a well-known MCP server whose capabilities are fixed,
// so a static scan (no tool list) can still reason about it.
type knownPackage struct {
	match       []string // substrings matched against the command line
	caps        []Capability
	filesystem  bool // roots are the path arguments
	description string
}

var knownPackages = []knownPackage{
	{match: []string{"server-filesystem", "mcp-server-filesystem"}, caps: []Capability{CapReadFile, CapWriteFile}, filesystem: true, description: "official filesystem server"},
	{match: []string{"mcp-server-fetch", "server-fetch"}, caps: []Capability{CapNetworkSend, CapUntrustedIngress}, description: "official fetch server"},
	{match: []string{"server-puppeteer", "playwright", "server-browser", "browser-mcp", "browsermcp"}, caps: []Capability{CapBrowser, CapNetworkSend, CapUntrustedIngress}, description: "browser automation server"},
	{match: []string{"server-github", "github-mcp"}, caps: []Capability{CapDataRead, CapExternalSend, CapUntrustedIngress}, description: "GitHub server"},
	{match: []string{"server-gitlab"}, caps: []Capability{CapDataRead, CapExternalSend, CapUntrustedIngress}, description: "GitLab server"},
	{match: []string{"server-slack", "mcp.slack.com"}, caps: []Capability{CapDataRead, CapExternalSend}, description: "Slack server"},
	{match: []string{"server-brave-search", "brave-search"}, caps: []Capability{CapUntrustedIngress}, description: "web search server"},
	{match: []string{"server-memory"}, caps: []Capability{CapMemoryWrite}, description: "memory server"},
	{match: []string{"server-postgres", "server-sqlite", "mysql-mcp", "mongodb-mcp"}, caps: []Capability{CapDataRead, CapDatabaseWrite}, description: "database server"},
	{match: []string{"desktop-commander", "server-shell", "shell-mcp", "server-terminal"}, caps: []Capability{CapShellExec, CapReadFile, CapWriteFile}, description: "shell and filesystem server"},
	{match: []string{"server-everything"}, caps: []Capability{}, description: "demo server"},
}

func detectCapabilities(srv *inspect.Server, home string) ServerCapabilities {
	sc := ServerCapabilities{
		ServerName: srv.Entry.Name,
		Client:     srv.Entry.Client,
		CapTools:   map[Capability][]string{},
		Evidence:   map[Capability][]Evidence{},
	}
	cmdline := strings.ToLower(srv.Entry.Command + " " + strings.Join(srv.Entry.Args, " ") + " " + srv.Entry.URL)

	// Filesystem roots come from the config regardless of whether tools were listed.
	roots := pathArgs(srv.Entry.Args, home)
	isFilesystemPkg := false
	for _, kp := range knownPackages {
		if kp.filesystem && matchesAny(cmdline, kp.match) {
			isFilesystemPkg = true
		}
	}

	if len(srv.Tools) == 0 {
		// Static: infer from the package.
		for _, kp := range knownPackages {
			if !matchesAny(cmdline, kp.match) {
				continue
			}
			sc.Static = true
			for _, c := range kp.caps {
				sc.add(c, Evidence{Detail: kp.description + " (" + firstMatch(cmdline, kp.match) + ")", Source: "package"})
			}
		}
	} else {
		for i := range srv.Tools {
			classifyTool(&sc, &srv.Tools[i], isFilesystemPkg || len(roots) > 0)
		}
	}

	// Scope applies to any server that reads or writes local files.
	if sc.Has(CapReadFile) || sc.Has(CapWriteFile) {
		sc.Roots = roots
		sc.Scope = classifyRoots(roots, home)
		for _, r := range roots {
			ev := Evidence{Detail: "allowed root " + describeRoot(r, home), Source: "config"}
			if sc.Has(CapReadFile) {
				sc.add(CapReadFile, ev)
			}
			if sc.Has(CapWriteFile) {
				sc.add(CapWriteFile, ev)
			}
		}
		if len(roots) == 0 {
			ev := Evidence{Detail: "allowed roots not declared in config; scope unknown", Source: "config"}
			if sc.Has(CapReadFile) {
				sc.add(CapReadFile, ev)
			} else {
				sc.add(CapWriteFile, ev)
			}
		}
		if sc.Has(CapWriteFile) {
			sc.StateWrites = agentStateTargets(roots, sc.Scope, home)
			if len(sc.StateWrites) > 0 {
				for _, t := range sc.StateWrites {
					sc.add(CapPersistence, Evidence{Detail: "can write " + t.Path + " (" + t.Kind + ")", Source: "config"})
				}
			}
		}
	}
	// A browser is an egress and an ingress by nature; say so once per server
	// rather than once per click/type/screenshot tool.
	if sc.Has(CapBrowser) {
		sc.add(CapNetworkSend, Evidence{Detail: "browser session can reach any destination", Source: "tool"})
		sc.add(CapUntrustedIngress, Evidence{Detail: "web content entering the browser enters the agent's context", Source: "tool"})
	}
	// Shell execution reaches every agent-state file the user can write.
	if sc.Has(CapShellExec) && len(sc.StateWrites) == 0 {
		sc.StateWrites = agentStateTargets([]string{home}, ScopeSensitive, home)
	}
	return sc
}

// classifyTool assigns capabilities from one tool's name, description and schema.
// Names are matched as whole tokens so "user_profile" does not become persistence
// and "reply" does not become a REPL.
func classifyTool(sc *ServerCapabilities, t *inspectTool, localFS bool) {
	name := strings.ToLower(t.Name)
	desc := strings.ToLower(t.Description)
	schema := strings.ToLower(string(t.InputSchema))
	ev := func(detail string) Evidence { return Evidence{Tool: t.Name, Detail: detail, Source: "tool"} }

	hasParam := func(names ...string) bool {
		for _, n := range names {
			if strings.Contains(schema, `"`+n+`"`) {
				return true
			}
		}
		return false
	}

	// Reads.
	if anyToken(name, "read_file", "read_multiple_files", "read_text_file", "read_media_file", "get_file_info", "list_directory", "directory_tree", "search_files", "cat", "view_file", "open_file") ||
		(anyToken(name, "read", "get", "list") && hasParam("path", "paths", "file", "directory")) {
		if localFS {
			sc.add(CapReadFile, ev("reads files by path"))
		} else {
			sc.add(CapDataRead, ev("reads data by path"))
		}
	}
	if anyToken(name, "get_file_contents", "search_code", "search_repositories", "list_commits", "get_issue", "list_issues", "query", "read_query", "execute_sql", "list_tables", "describe_table", "get_channel_history", "get_users", "read_graph", "search_nodes", "open_nodes") {
		sc.add(CapDataRead, ev("reads remote data"))
	}

	// Writes.
	if anyToken(name, "write_file", "edit_file", "create_file", "create_directory", "move_file", "delete_file", "append_file", "patch_file", "apply_diff", "insert_content", "write_to_file") ||
		(anyToken(name, "write", "create", "edit", "modify", "update", "delete", "move") && hasParam("path", "file", "destination")) {
		if localFS {
			sc.add(CapWriteFile, ev("writes files by path"))
		}
	}
	if anyToken(name, "create_entities", "create_relations", "add_observations", "store_memory", "save_memory", "remember", "memory_write", "update_memory") || strings.Contains(name, "memory") && anyToken(name, "add", "create", "store", "save", "update") {
		sc.add(CapMemoryWrite, ev("writes persistent memory"))
	}

	// Execution.
	if anyToken(name, "execute_command", "run_command", "shell", "bash", "sh", "exec", "execute", "terminal", "run_shell", "shell_exec", "start_process", "spawn_process", "run_code", "execute_code", "eval_code", "eval", "run_python", "run_javascript", "code_interpreter", "repl", "sandbox_exec") ||
		hasParam("command", "shell_command", "cmd") {
		sc.add(CapShellExec, ev("executes commands or code"))
	}

	// Network egress and ingress.
	urlParam := hasParam("url", "uri", "endpoint", "href")
	if anyToken(name, "fetch", "http_get", "http_post", "http_put", "http_request", "web_fetch", "fetch_url", "get_url", "download", "navigate", "goto", "browse", "curl", "webhook", "call_api", "send_request", "make_request", "web_request", "network_request") || urlParam {
		sc.add(CapNetworkSend, ev("reaches network destinations"+paramNote(urlParam)))
		if hasParam("alloweddomains", "allowlist", "allow_list", "whitelist") || strings.Contains(desc, "only allowed domain") || strings.Contains(desc, "allowlisted") {
			sc.EgressConstrained = true
		}
	}
	if anyToken(name, "fetch", "web_fetch", "fetch_url", "get_url", "browse", "navigate", "goto", "search", "web_search", "get_page", "get_page_text", "read_page", "scrape", "crawl") || strings.HasPrefix(name, "brave_") {
		sc.add(CapUntrustedIngress, ev("brings external content into the agent's context"))
	}
	if anyToken(name, "navigate", "click", "screenshot", "type", "fill", "select_option", "hover", "evaluate", "get_page", "get_page_text", "read_page", "find", "tabs_context", "browser_batch") || strings.HasPrefix(name, "browser_") || strings.HasPrefix(name, "puppeteer_") || strings.HasPrefix(name, "playwright_") {
		sc.add(CapBrowser, ev("drives a browser session"))
	}

	// External channels: authenticated destinations an agent can post data to.
	if anyToken(name, "post_message", "send_message", "reply_to_thread", "send_dm", "create_issue", "create_pull_request", "create_or_update_file", "push_files", "add_issue_comment", "upload_file", "upload", "send_webhook", "post_data", "create_page", "create_comment") {
		sc.add(CapExternalSend, ev("posts data to an external, authenticated destination"))
	}
	if anyToken(name, "send_email", "email_send", "smtp_send", "mail_send", "sendmail", "compose_email", "reply_email", "send_mail") {
		sc.add(CapEmailSend, ev("sends email"))
		sc.add(CapExternalSend, ev("sends email"))
	}

	// Secrets and environment.
	if anyToken(name, "get_env", "read_env", "getenv", "list_env", "show_env", "env_vars", "environment_variables", "print_env") || hasParam("env_var", "variable_name") && anyToken(name, "get", "read") {
		sc.add(CapReadEnv, ev("reads environment variables"))
	}
	if anyToken(name, "get_secret", "read_secret", "fetch_secret", "get_token", "get_api_key", "get_password", "get_credential", "get_credentials", "read_keychain", "keychain", "read_ssh_key", "get_ssh_key", "list_secrets") ||
		strings.Contains(desc, "private key") || strings.Contains(desc, "credentials file") || strings.Contains(desc, "api key") && anyToken(name, "get", "read", "fetch") {
		sc.add(CapCredentialRead, ev("reads credentials or secrets"))
	}

	// Persistence via explicit startup-location tools.
	if anyToken(name, "crontab", "cron", "add_cron", "schedule_task", "launchagent", "systemd", "registry_run", "startup_item", "autorun") {
		sc.add(CapPersistence, ev("writes startup or scheduler locations"))
	}
	if anyToken(name, "npm_install", "pip_install", "brew_install", "apt_install", "install_package", "add_dependency", "install") {
		sc.add(CapPackageInstall, ev("installs packages"))
	}
	if anyToken(name, "insert_record", "update_record", "delete_record", "write_query", "execute_sql", "run_sql", "sql_execute") {
		sc.add(CapDatabaseWrite, ev("writes to a database"))
	}
}

type inspectTool = mcpclient.Tool

func paramNote(urlParam bool) string {
	if urlParam {
		return " (takes a URL parameter)"
	}
	return ""
}

// anyToken reports whether name equals, or contains as a whole `_`/`-`-delimited
// token sequence, any of the candidates.
func anyToken(name string, candidates ...string) bool {
	tokens := splitTokens(name)
	joined := "_" + strings.Join(tokens, "_") + "_"
	for _, c := range candidates {
		if name == c || strings.Contains(joined, "_"+c+"_") {
			return true
		}
	}
	return false
}

func splitTokens(s string) []string {
	f := func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }
	return strings.FieldsFunc(strings.ToLower(s), f)
}

func matchesAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func firstMatch(s string, subs []string) string {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return sub
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Filesystem scope
// ---------------------------------------------------------------------------

// pathArgs returns arguments that look like directories or files, with ~ expanded.
func pathArgs(args []string, home string) []string {
	var out []string
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		if a == "~" || strings.HasPrefix(a, "~/") {
			out = append(out, filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(a, "~"), "/")))
			continue
		}
		if filepath.IsAbs(a) || strings.HasPrefix(a, "/") {
			// Skip things that are clearly not roots: URLs never start with '/', package
			// names never do either, so an absolute path argument is a root candidate.
			if strings.Contains(a, "://") {
				continue
			}
			out = append(out, filepath.Clean(a))
		}
	}
	return out
}

// sensitiveDirs are home-relative directories that hold credentials or session material.
var sensitiveDirs = []string{".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config/gcloud", ".azure", ".config/gh", ".netrc", ".npmrc", ".pypirc", "Library/Keychains", ".password-store", ".mozilla", "Library/Application Support/Google/Chrome"}

func classifyRoots(roots []string, home string) FileScope {
	if len(roots) == 0 {
		return ScopeUnknown
	}
	scope := ScopeProject
	for _, r := range roots {
		if rootIsSensitive(r, home) {
			return ScopeSensitive
		}
	}
	return scope
}

func rootIsSensitive(root, home string) bool {
	root = filepath.Clean(root)
	if root == "/" || root == filepath.Clean(home) || root == "/Users" || root == "/home" || root == "/root" {
		return true
	}
	// An ancestor of home (e.g. /Users) reaches everything under it.
	if isAncestor(root, home) {
		return true
	}
	for _, d := range sensitiveDirs {
		full := filepath.Join(home, d)
		if root == full || isAncestor(root, full) {
			return true
		}
	}
	return false
}

func isAncestor(dir, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, "..")
}

func describeRoot(root, home string) string {
	switch {
	case root == "/":
		return "/ (entire filesystem)"
	case root == filepath.Clean(home):
		return root + " (home directory: includes ~/.ssh, ~/.aws, browser profiles)"
	case isAncestor(root, home):
		return root + " (contains the home directory)"
	}
	for _, d := range sensitiveDirs {
		if root == filepath.Join(home, d) {
			return root + " (credential store)"
		}
	}
	return root
}

// agentStateTargets lists agent-state files the given roots can reach.
// Home-level targets are listed when a root covers them; project-level targets
// are listed for every project root, since their presence cannot be known
// without reading the directory.
func agentStateTargets(roots []string, scope FileScope, home string) []AgentStateTarget {
	homeTargets := []AgentStateTarget{
		{Path: filepath.Join(home, ".claude.json"), Kind: "mcp-config", Executes: true},
		{Path: filepath.Join(home, ".claude", "settings.json"), Kind: "hooks", Executes: true},
		{Path: filepath.Join(home, ".claude", "CLAUDE.md"), Kind: "instructions"},
		{Path: filepath.Join(home, ".claude", "projects"), Kind: "memory"},
		{Path: filepath.Join(home, ".cursor", "mcp.json"), Kind: "mcp-config", Executes: true},
		{Path: filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), Kind: "mcp-config", Executes: true},
		{Path: filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), Kind: "mcp-config", Executes: true},
		{Path: filepath.Join(home, ".zshrc"), Kind: "shell-startup", Executes: true},
		{Path: filepath.Join(home, ".bashrc"), Kind: "shell-startup", Executes: true},
	}
	projectTargets := []AgentStateTarget{
		{Path: ".mcp.json", Kind: "mcp-config", Executes: true},
		{Path: ".claude/settings.json", Kind: "hooks", Executes: true},
		{Path: "CLAUDE.md", Kind: "instructions"},
		{Path: ".cursorrules", Kind: "instructions"},
		{Path: ".cursor/rules", Kind: "instructions"},
		{Path: ".vscode/mcp.json", Kind: "mcp-config", Executes: true},
	}
	var out []AgentStateTarget
	seen := map[string]bool{}
	add := func(t AgentStateTarget) {
		if !seen[t.Path] {
			seen[t.Path] = true
			out = append(out, t)
		}
	}
	for _, r := range roots {
		for _, t := range homeTargets {
			if r == filepath.Clean(t.Path) || isAncestor(r, t.Path) {
				t.Global = true
				add(t)
			}
		}
		if !rootIsSensitive(r, home) {
			for _, t := range projectTargets {
				add(AgentStateTarget{Path: filepath.Join(r, t.Path), Kind: t.Kind, Executes: t.Executes})
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Chains
// ---------------------------------------------------------------------------

// egress describes how a server can move data out.
type egress struct {
	sc    *ServerCapabilities
	class string // "open" | "constrained" | "channel"
	tools []string
	cap   Capability
}

func egressOf(sc *ServerCapabilities) []egress {
	var out []egress
	if sc.Has(CapNetworkSend) {
		class := "open"
		if sc.EgressConstrained {
			class = "constrained"
		}
		out = append(out, egress{sc: sc, class: class, tools: sc.CapTools[CapNetworkSend], cap: CapNetworkSend})
	}
	if sc.Has(CapExternalSend) && !sc.Has(CapNetworkSend) {
		out = append(out, egress{sc: sc, class: "channel", tools: sc.CapTools[CapExternalSend], cap: CapExternalSend})
	}
	return out
}

// reader describes how a server can obtain sensitive data.
type reader struct {
	sc    *ServerCapabilities
	class string // "credential" | "sensitive" | "project" | "unknown" | "data"
	cap   Capability
}

func readersOf(sc *ServerCapabilities) []reader {
	var out []reader
	if sc.Has(CapCredentialRead) {
		out = append(out, reader{sc: sc, class: "credential", cap: CapCredentialRead})
	}
	if sc.Has(CapReadFile) {
		class := map[FileScope]string{ScopeSensitive: "sensitive", ScopeProject: "project", ScopeUnknown: "unknown"}[sc.Scope]
		out = append(out, reader{sc: sc, class: class, cap: CapReadFile})
	}
	if sc.Has(CapReadEnv) {
		out = append(out, reader{sc: sc, class: "env", cap: CapReadEnv})
	}
	if sc.Has(CapDataRead) && !sc.Has(CapReadFile) {
		out = append(out, reader{sc: sc, class: "data", cap: CapDataRead})
	}
	return out
}

func detectChains(caps []ServerCapabilities) []AttackChain {
	var chains []AttackChain
	seen := map[string]bool{}
	add := func(ch AttackChain) {
		key := ch.ID + "|" + strings.Join(ch.Servers, ",")
		if seen[key] {
			return
		}
		seen[key] = true
		chains = append(chains, ch)
	}

	var egresses []egress
	var readers []reader
	var ingress, execs, stateWriters, memoryWriters []*ServerCapabilities
	for i := range caps {
		sc := &caps[i]
		egresses = append(egresses, egressOf(sc)...)
		readers = append(readers, readersOf(sc)...)
		if sc.Has(CapUntrustedIngress) {
			ingress = append(ingress, sc)
		}
		if sc.Has(CapShellExec) {
			execs = append(execs, sc)
		}
		if sc.Has(CapWriteFile) && len(sc.StateWrites) > 0 {
			stateWriters = append(stateWriters, sc)
		}
		if sc.Has(CapMemoryWrite) {
			memoryWriters = append(memoryWriters, sc)
		}
	}

	// AP001 / AP002: sensitive data or credentials leave through a network capability.
	for _, r := range readers {
		for _, e := range egresses {
			if r.class == "data" {
				continue // remote data through remote channels is the tool's purpose
			}
			sev, conf, ok := exfilSeverity(r, e)
			if !ok {
				continue
			}
			id, name, what := "AP001", "Potential sensitive data exfiltration path", "files"
			if r.class == "credential" || r.class == "env" {
				id, name, what = "AP002", "Potential credential exfiltration path", "credentials"
			}
			if r.class == "sensitive" {
				what = "credential files such as ~/.ssh and ~/.aws"
			}
			if r.class == "project" {
				what = "project files, including any .env or key files in the tree"
			}
			steps := []string{
				"instruction from a prompt, document, or tool result",
				hop(r.sc, r.cap) + " reads " + what,
				"contents enter the agent's context",
				hop(e.sc, e.cap) + " sends them to " + egressDestination(e),
			}
			add(AttackChain{
				ID: id, Name: name, Severity: sev, Confidence: conf,
				Description: r.sc.ServerName + " can read " + what + " and " + e.sc.ServerName + " can send data to " + egressDestination(e) + ". Together they form a path an injected instruction could walk.",
				MITRETactic: "Exfiltration", MITRERef: "TA0010",
				Servers:     dedup(r.sc.ServerName, e.sc.ServerName),
				Steps:       steps,
				Evidence:    append(copyEv(r.sc.Evidence[r.cap]), e.sc.Evidence[e.cap]...),
				Impact:      "An instruction the agent processes could combine these two capabilities to expose " + what + " outside this machine. Nothing here proves it has happened; the path exists.",
				Remediation: remediateExfil(r, e),
			})
		}
	}

	// AP003: untrusted content -> writable agent state -> future sessions.
	for _, w := range stateWriters {
		exec := false
		for _, t := range w.StateWrites {
			exec = exec || t.Executes
		}
		// A writable agent-state file is a risky configuration on its own; it becomes
		// a path only when something can bring external content into the context.
		// Configuration risk is the job of scan rules, not of this package.
		hasIngress := len(ingress) > 0
		if !hasIngress {
			continue
		}
		sev, conf := "high", confidenceFor(w)
		if exec {
			sev = "critical"
		}
		var targets []string
		for _, t := range w.StateWrites {
			label := t.Path + " (" + t.Kind
			if t.Executes {
				label += ", runs code at next session start"
			}
			targets = append(targets, label+")")
		}
		servers := []string{w.ServerName}
		var evidence []Evidence
		evidence = append(evidence, w.Evidence[CapWriteFile]...)
		evidence = append(evidence, w.Evidence[CapPersistence]...)
		steps := []string{}
		if hasIngress {
			steps = append(steps, ingress[0].ServerName+" brings external content into the agent's context")
			servers = dedup(w.ServerName, ingress[0].ServerName)
			evidence = append(evidence, ingress[0].Evidence[CapUntrustedIngress]...)
		} else {
			steps = append(steps, "instruction from a prompt or document")
		}
		steps = append(steps,
			hop(w, CapWriteFile)+" modifies "+targets[0],
			"current session ends",
			"next session loads the modified state and trusts it",
		)
		add(AttackChain{
			ID: "AP003", Name: "Potential persistent agent compromise path", Severity: sev, Confidence: conf,
			Description: w.ServerName + " can write files the agent trusts in future sessions: " + strings.Join(shorten(targets, 3), "; ") + ".",
			MITRETactic: "Persistence", MITRERef: "TA0003",
			Servers: servers, Steps: steps, Evidence: evidence,
			Impact:      "A modification made in one session would shape every later session. " + execImpact(exec),
			Remediation: "Scope " + w.ServerName + " to a directory that holds no agent configuration, instruction files, or hooks; keep a copy of those files under version control so changes are visible.",
		})
	}

	// AP004: untrusted content -> persistent memory.
	if len(ingress) > 0 {
		for _, m := range memoryWriters {
			add(AttackChain{
				ID: "AP004", Name: "Potential memory poisoning path", Severity: "medium", Confidence: confidenceFor(m),
				Description: ingress[0].ServerName + " brings external content into the context and " + m.ServerName + " persists what the agent decides to remember.",
				MITRETactic: "Persistence", MITRERef: "TA0003",
				Servers: dedup(ingress[0].ServerName, m.ServerName),
				Steps: []string{
					ingress[0].ServerName + " returns external content",
					"content instructs the agent to remember something",
					hop(m, CapMemoryWrite) + " persists it",
					"later sessions read it back as trusted memory",
				},
				Evidence:    append(copyEv(ingress[0].Evidence[CapUntrustedIngress]), m.Evidence[CapMemoryWrite]...),
				Impact:      "Memory written under the influence of external content is read back later as if it were the user's own. This is possible, not observed.",
				Remediation: "Review the memory store periodically and treat stored instructions with the same suspicion as retrieved documents.",
			})
		}
	}

	// AP005: command execution reachable with open egress -> remote control path.
	for _, x := range execs {
		for _, e := range egresses {
			if e.class == "channel" {
				continue
			}
			sev := "critical"
			if e.class == "constrained" {
				sev = "high"
			}
			add(AttackChain{
				ID: "AP005", Name: "Potential remote control path", Severity: sev, Confidence: strongest(confidenceFor(x), confidenceFor(e.sc)),
				Description: x.ServerName + " can execute commands and " + e.sc.ServerName + " can reach " + egressDestination(e) + ", which is enough for a reverse shell or beacon if an instruction asks for one.",
				MITRETactic: "Command and Control", MITRERef: "TA0011",
				Servers: dedup(x.ServerName, e.sc.ServerName),
				Steps: []string{
					"instruction from a prompt, document, or tool result",
					hop(x, CapShellExec) + " runs an arbitrary command",
					hop(e.sc, e.cap) + " provides a channel to " + egressDestination(e),
				},
				Evidence:    append(copyEv(x.Evidence[CapShellExec]), e.sc.Evidence[e.cap]...),
				Impact:      "Command execution plus an outbound channel is the shape of remote control over this machine. The path exists; whether it is used depends on what the agent is asked.",
				Remediation: "Remove command execution from the agent's reach or run it in a sandbox without network access; constrain " + e.sc.ServerName + " to known destinations.",
			})
		}
	}

	// AP006: untrusted content -> command execution, for environments with no
	// open egress. When open egress exists, AP005 already reports every exec
	// server and AP006 would only restate it.
	openEgress := false
	for _, e := range egresses {
		if e.class != "channel" {
			openEgress = true
		}
	}
	if len(ingress) > 0 && !openEgress {
		for _, x := range execs {
			add(AttackChain{
				ID: "AP006", Name: "Potential untrusted content to command execution path", Severity: "high", Confidence: confidenceFor(x),
				Description: ingress[0].ServerName + " brings external content into the context and " + x.ServerName + " executes commands; content that contains instructions can become commands.",
				MITRETactic: "Execution", MITRERef: "TA0002",
				Servers: dedup(ingress[0].ServerName, x.ServerName),
				Steps: []string{
					ingress[0].ServerName + " returns external content",
					"content contains instructions the model follows",
					hop(x, CapShellExec) + " runs the resulting command",
				},
				Evidence:    append(copyEv(ingress[0].Evidence[CapUntrustedIngress]), x.Evidence[CapShellExec]...),
				Impact:      "Any web page, document, or tool result the agent reads is a possible source of commands that run on this machine.",
				Remediation: "Require confirmation for command execution, or restrict it to an allowlist of commands; keep browsing and execution in separate sessions where possible.",
			})
		}
	}

	sort.SliceStable(chains, func(i, j int) bool {
		si, sj := severityRank(chains[i].Severity), severityRank(chains[j].Severity)
		if si != sj {
			return si > sj
		}
		if chains[i].ID != chains[j].ID {
			return chains[i].ID < chains[j].ID
		}
		return strings.Join(chains[i].Servers, ",") < strings.Join(chains[j].Servers, ",")
	})
	return chains
}

// exfilSeverity maps (what can be read, how it can leave) to severity and confidence.
//
//	credential/sensitive + open        -> critical
//	credential/sensitive + channel     -> high
//	credential/sensitive + constrained -> medium
//	project + open                     -> high
//	project + channel                  -> medium
//	project + constrained              -> low
//	unknown scope is treated as sensitive at medium confidence
//	env + open -> high, env + channel -> medium, env + constrained -> low
func exfilSeverity(r reader, e egress) (sev, conf string, ok bool) {
	conf = strongest(confidenceFor(r.sc), confidenceFor(e.sc))
	class := r.class
	if class == "unknown" {
		class = "sensitive"
		conf = "medium"
	}
	table := map[string]map[string]string{
		"credential": {"open": "critical", "channel": "high", "constrained": "medium"},
		"sensitive":  {"open": "critical", "channel": "high", "constrained": "medium"},
		"project":    {"open": "high", "channel": "medium", "constrained": "low"},
		"env":        {"open": "high", "channel": "medium", "constrained": "low"},
	}
	row, ok := table[class]
	if !ok {
		return "", "", false
	}
	sev, ok = row[e.class]
	return sev, conf, ok
}

// confidenceFor is high when capabilities come from a live tool list and the
// evidence is explicit, medium when inferred from a package name.
func confidenceFor(sc *ServerCapabilities) string {
	if sc.Static {
		return "medium"
	}
	return "high"
}

func strongest(a, b string) string {
	if a == "medium" || b == "medium" {
		return "medium"
	}
	return "high"
}

func egressDestination(e egress) string {
	switch e.class {
	case "constrained":
		return "an allowlisted set of destinations"
	case "channel":
		return "an external service the agent is authenticated to"
	}
	return "any network destination"
}

func remediateExfil(r reader, e egress) string {
	var parts []string
	switch r.class {
	case "sensitive", "unknown":
		parts = append(parts, "scope "+r.sc.ServerName+" to specific project directories instead of "+firstOr(r.sc.Roots, "an undeclared root"))
	case "project":
		parts = append(parts, "keep secrets out of the directories "+r.sc.ServerName+" can read (use a secret manager rather than .env files)")
	case "credential":
		parts = append(parts, "remove or gate the credential-reading tools on "+r.sc.ServerName)
	case "env":
		parts = append(parts, "avoid exposing environment-reading tools on "+r.sc.ServerName+" while secrets live in the environment")
	}
	if e.class == "open" {
		parts = append(parts, "constrain "+e.sc.ServerName+" to an allowlist of destinations")
	}
	return strings.Join(parts, "; ") + ". Either change alone removes the path."
}

func execImpact(exec bool) string {
	if exec {
		return "Because the writable state includes MCP configuration or hooks, a modification can start arbitrary code at the next session without any further instruction."
	}
	return "Modified instructions would be followed in future sessions as if the user had written them."
}

func severityRank(s string) int {
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

func dedup(names ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func appendUniq(s []string, v string) []string {
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}

func copyEv(e []Evidence) []Evidence { return append([]Evidence(nil), e...) }

// hop names one step of a path: "server.tool" when a tool is known, otherwise
// "server (capability)" so static inference never invents a tool name.
func hop(sc *ServerCapabilities, c Capability) string {
	if tools := sc.CapTools[c]; len(tools) > 0 {
		return sc.ServerName + "." + tools[0]
	}
	return sc.ServerName + " (" + c.String() + ")"
}

func firstOr(s []string, fallback string) string {
	if len(s) == 0 {
		return fallback
	}
	return s[0]
}

func shorten(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), "and "+itoa(len(s)-n)+" more")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
