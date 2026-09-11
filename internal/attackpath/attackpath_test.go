package attackpath_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/mcpclient"
)

const home = "/Users/dev"

var opts = attackpath.Options{Home: home}

// tool builds a tool whose schema declares the given string parameters.
func tool(name string, params ...string) mcpclient.Tool {
	props := map[string]any{}
	for _, p := range params {
		props[p] = map[string]string{"type": "string"}
	}
	schema, _ := json.Marshal(map[string]any{"type": "object", "properties": props})
	return mcpclient.Tool{Name: name, Description: name + " tool", InputSchema: schema}
}

func server(name string, args []string, tools ...mcpclient.Tool) *inspect.Server {
	return &inspect.Server{Entry: discover.ServerEntry{Name: name, Client: "claude", Command: "npx", Args: args}, Tools: tools}
}

// Common fixtures.
var (
	fsHome            = server("filesystem", []string{"-y", "@modelcontextprotocol/server-filesystem", "~"}, tool("read_file", "path"), tool("write_file", "path", "content"), tool("list_directory", "path"))
	fsProject         = server("filesystem", []string{"-y", "@modelcontextprotocol/server-filesystem", "/Users/dev/projects/app"}, tool("read_file", "path"), tool("write_file", "path", "content"))
	fsReadOnlyProject = server("docs", []string{"-y", "@modelcontextprotocol/server-filesystem", "/Users/dev/docs"}, tool("read_file", "path"))
	fetch             = server("fetch", []string{"mcp-server-fetch"}, tool("fetch", "url", "max_length"))
	fetchAllow        = &inspect.Server{
		Entry: discover.ServerEntry{Name: "fetch-internal", Client: "claude", Command: "uvx", Args: []string{"internal-fetch"}},
		Tools: []mcpclient.Tool{{Name: "fetch", Description: "Fetch only allowed domains", InputSchema: json.RawMessage(`{"type":"object","properties":{"url":{"type":"string"},"allowedDomains":{"type":"array"}}}`)}},
	}
	slack   = server("slack", []string{"-y", "@modelcontextprotocol/server-slack"}, tool("slack_post_message", "channel_id", "text"), tool("slack_list_channels"), tool("slack_reply_to_thread", "channel_id", "thread_ts", "text"))
	shell   = server("shell", []string{"-y", "shell-mcp"}, tool("execute_command", "command"))
	search  = server("brave", []string{"-y", "@modelcontextprotocol/server-brave-search"}, tool("brave_web_search", "query"))
	memory  = server("memory", []string{"-y", "@modelcontextprotocol/server-memory"}, tool("create_entities", "entities"), tool("read_graph"))
	github  = server("github", []string{"-y", "@modelcontextprotocol/server-github"}, tool("get_file_contents", "owner", "repo", "path"), tool("create_issue", "owner", "repo", "title"), tool("search_repositories", "query"))
	profile = server("crm", []string{"-y", "crm-mcp"}, tool("user_profile", "id"), tool("get_user_profile", "id"))
)

func chainsFor(t *testing.T, servers ...*inspect.Server) []attackpath.AttackChain {
	t.Helper()
	_, chains := attackpath.AnalyzeWithOptions(servers, opts)
	return chains
}

func findChain(chains []attackpath.AttackChain, id string) *attackpath.AttackChain {
	for i := range chains {
		if chains[i].ID == id {
			return &chains[i]
		}
	}
	return nil
}

func ids(chains []attackpath.AttackChain) []string {
	var out []string
	for _, c := range chains {
		out = append(out, c.ID+"/"+c.Severity)
	}
	return out
}

func evidenceMentions(c *attackpath.AttackChain, sub string) bool {
	for _, e := range c.Evidence {
		if strings.Contains(e.Detail, sub) || strings.Contains(e.Tool, sub) {
			return true
		}
	}
	return false
}

// ---- Exfiltration compositions -------------------------------------------

func TestHomeScopedReadPlusOpenEgressIsCriticalWithEvidence(t *testing.T) {
	chains := chainsFor(t, fsHome, fetch)
	c := findChain(chains, "AP001")
	if c == nil {
		t.Fatalf("expected AP001, got %v", ids(chains))
	}
	if c.Severity != "critical" || c.Confidence != "high" {
		t.Errorf("severity/confidence = %s/%s, want critical/high", c.Severity, c.Confidence)
	}
	if !evidenceMentions(c, "home directory") {
		t.Errorf("evidence must name the allowed root as the home directory: %+v", c.Evidence)
	}
	if !evidenceMentions(c, "read_file") || !evidenceMentions(c, "fetch") {
		t.Errorf("evidence must name both tools: %+v", c.Evidence)
	}
	if len(c.Steps) < 3 || !strings.Contains(strings.Join(c.Steps, " "), "filesystem.read_file") {
		t.Errorf("steps should show the path hop by hop: %v", c.Steps)
	}
	if c.Remediation == "" || c.Impact == "" {
		t.Error("important findings carry impact and remediation")
	}
	if strings.Contains(c.Impact, "has happened") && !strings.Contains(c.Impact, "Nothing here proves") {
		t.Error("impact must not claim the exfiltration occurred")
	}
}

func TestProjectScopedReadPlusOpenEgressIsHighNotCritical(t *testing.T) {
	c := findChain(chainsFor(t, fsProject, fetch), "AP001")
	if c == nil {
		t.Fatal("expected AP001 for project scope + open egress")
	}
	if c.Severity != "high" {
		t.Errorf("project-scoped read should be high, got %s", c.Severity)
	}
	if !strings.Contains(c.Description, ".env") {
		t.Errorf("project scope should explain the .env concern: %s", c.Description)
	}
}

func TestChannelEgressLowersSeverity(t *testing.T) {
	if c := findChain(chainsFor(t, fsHome, slack), "AP001"); c == nil || c.Severity != "high" {
		t.Errorf("home read + authenticated channel should be high, got %+v", c)
	}
	if c := findChain(chainsFor(t, fsProject, slack), "AP001"); c == nil || c.Severity != "medium" {
		t.Errorf("project read + authenticated channel should be medium, got %+v", c)
	}
}

func TestConstrainedEgressLowersSeverity(t *testing.T) {
	c := findChain(chainsFor(t, fsHome, fetchAllow), "AP001")
	if c == nil || c.Severity != "medium" {
		t.Fatalf("home read + allowlisted egress should be medium, got %+v", c)
	}
	if !strings.Contains(strings.Join(c.Steps, " "), "allowlisted") {
		t.Errorf("steps should say the destination set is allowlisted: %v", c.Steps)
	}
}

func TestSingleCapabilityIsNotAPath(t *testing.T) {
	for name, srv := range map[string]*inspect.Server{"fetch alone": fetch, "filesystem alone": fsHome, "shell alone": shell, "search alone": search} {
		if chains := chainsFor(t, srv); len(chains) != 0 {
			t.Errorf("%s: a capability is not a composition, got %v", name, ids(chains))
		}
	}
}

func TestRemoteDataReadIsNotExfiltrationSource(t *testing.T) {
	// GitHub reads repository content and can post issues; moving repo data to
	// GitHub is the tool's purpose, not a local exfiltration path.
	chains := chainsFor(t, github, fetch)
	if c := findChain(chains, "AP001"); c != nil {
		t.Errorf("remote data read must not be treated as a local file read: %+v", c)
	}
}

// ---- Persistence compositions ----------------------------------------------

func TestUntrustedIngressPlusWritableAgentConfigIsCritical(t *testing.T) {
	c := findChain(chainsFor(t, fsHome, fetch), "AP003")
	if c == nil {
		t.Fatal("expected AP003 persistence path")
	}
	if c.Severity != "critical" {
		t.Errorf("writable MCP config/hooks + external content should be critical, got %s", c.Severity)
	}
	joined := strings.Join(c.Steps, " ") + c.Description
	if !strings.Contains(joined, ".claude.json") && !strings.Contains(joined, "settings.json") {
		t.Errorf("should name a concrete agent-state file: %s", joined)
	}
	if !strings.Contains(c.Impact, "next session") {
		t.Errorf("impact should explain the session boundary: %s", c.Impact)
	}
}

func TestProjectScopedWritePlusIngressReachesProjectMCPConfig(t *testing.T) {
	c := findChain(chainsFor(t, fsProject, search), "AP003")
	if c == nil {
		t.Fatal("expected AP003 for project write + web search")
	}
	if !strings.Contains(c.Description, ".mcp.json") && !strings.Contains(strings.Join(c.Steps, " "), ".mcp.json") {
		t.Errorf("project root should list .mcp.json as a writable, executable target: %s", c.Description)
	}
}

func TestReadOnlyProjectServerHasNoPersistencePath(t *testing.T) {
	if c := findChain(chainsFor(t, fsReadOnlyProject, fetch), "AP003"); c != nil {
		t.Errorf("a server without write tools cannot persist: %+v", c)
	}
}

func TestWritableStateWithoutIngressIsConfigurationNotPath(t *testing.T) {
	// A server that can rewrite .mcp.json is a risky configuration, which is a
	// scan rule's job. Without a source of external content it is not a path.
	if c := findChain(chainsFor(t, fsProject), "AP003"); c != nil {
		t.Errorf("no ingress means no composition, got %+v", c)
	}
}

func TestMemoryPoisoningNeedsIngress(t *testing.T) {
	if c := findChain(chainsFor(t, memory), "AP004"); c != nil {
		t.Error("memory alone is not a path")
	}
	c := findChain(chainsFor(t, memory, search), "AP004")
	if c == nil || c.Severity != "medium" {
		t.Errorf("memory + web search should be a medium poisoning path, got %+v", c)
	}
	if !strings.Contains(c.Impact, "possible, not observed") {
		t.Errorf("must not present possibility as observation: %s", c.Impact)
	}
}

// ---- Execution compositions -----------------------------------------------

func TestExecPlusOpenEgressIsCritical(t *testing.T) {
	c := findChain(chainsFor(t, shell, fetch), "AP005")
	if c == nil || c.Severity != "critical" {
		t.Fatalf("exec + open egress should be a critical remote control path, got %+v", c)
	}
	if findChain(chainsFor(t, shell, fetch), "AP006") != nil {
		t.Error("AP006 is redundant when AP005 covers the same exec server")
	}
}

func TestIngressPlusExecWithoutEgressIsHigh(t *testing.T) {
	c := findChain(chainsFor(t, shell, search), "AP006")
	if c == nil || c.Severity != "high" {
		t.Errorf("web search + exec should be a high path, got %+v", c)
	}
}

// ---- Precision -------------------------------------------------------------

func TestTokenMatchingAvoidsSubstringFalsePositives(t *testing.T) {
	caps, chains := attackpath.AnalyzeWithOptions([]*inspect.Server{profile, slack}, opts)
	for _, sc := range caps {
		if sc.Has(attackpath.CapPersistence) {
			t.Errorf("%s: 'profile' must not be read as a shell profile", sc.ServerName)
		}
		if sc.Has(attackpath.CapShellExec) {
			t.Errorf("%s: 'reply' must not be read as a REPL", sc.ServerName)
		}
	}
	if len(chains) != 0 {
		t.Errorf("no compositions expected, got %v", ids(chains))
	}
}

func TestGitHubPullRequestToolsAreAChannelNotOpenEgress(t *testing.T) {
	// Regression: "create_pull_request" tokenizes to pull + request; a bare
	// "request" token used to make GitHub look like an arbitrary HTTP client.
	// Posting to GitHub is an authenticated channel, one severity step lower.
	gh := server("github", []string{"-y", "@modelcontextprotocol/server-github"},
		tool("create_pull_request", "owner", "repo", "title", "head", "base"),
		tool("get_pull_request", "owner", "repo", "pull_number"),
		tool("merge_pull_request", "owner", "repo", "pull_number"))
	caps, chains := attackpath.AnalyzeWithOptions([]*inspect.Server{fsHome, gh}, opts)
	for _, sc := range caps {
		if sc.ServerName == "github" && sc.Has(attackpath.CapNetworkSend) {
			t.Errorf("GitHub PR tools must not be classified as open network egress: %+v", sc.CapTools)
		}
	}
	c := findChain(chains, "AP001")
	if c == nil || c.Severity != "high" {
		t.Errorf("home read + GitHub channel should be high, got %+v", c)
	}
}

func TestBrowserEgressEvidenceIsStatedOnce(t *testing.T) {
	browser := server("playwright", []string{"-y", "@playwright/mcp"},
		tool("browser_navigate", "url"), tool("browser_click", "ref"), tool("browser_type", "ref", "text"), tool("browser_screenshot"), tool("browser_close"))
	caps, _ := attackpath.AnalyzeWithOptions([]*inspect.Server{browser}, opts)
	sc := caps[0]
	if !sc.Has(attackpath.CapBrowser) || !sc.Has(attackpath.CapNetworkSend) || !sc.Has(attackpath.CapUntrustedIngress) {
		t.Fatalf("browser server should be browser + egress + ingress: %v", sc.Caps)
	}
	// navigate carries a URL parameter (one tool evidence) plus one server-level statement.
	if n := len(sc.Evidence[attackpath.CapNetworkSend]); n > 3 {
		t.Errorf("egress evidence should not repeat per browser tool, got %d items: %+v", n, sc.Evidence[attackpath.CapNetworkSend])
	}
}

func TestStaticInferenceFromKnownPackages(t *testing.T) {
	static := []*inspect.Server{
		{Entry: discover.ServerEntry{Name: "filesystem", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "~"}}, StaticOnly: true},
		{Entry: discover.ServerEntry{Name: "fetch", Command: "uvx", Args: []string{"mcp-server-fetch"}}, StaticOnly: true},
	}
	caps, chains := attackpath.AnalyzeWithOptions(static, opts)
	for _, sc := range caps {
		if !sc.Static {
			t.Errorf("%s should be marked as statically inferred", sc.ServerName)
		}
	}
	c := findChain(chains, "AP001")
	if c == nil {
		t.Fatalf("static scan should still find the exfiltration path, got %v", ids(chains))
	}
	if c.Confidence != "medium" {
		t.Errorf("inferred capabilities must not claim high confidence, got %s", c.Confidence)
	}
	if !evidenceMentions(c, "home directory") {
		t.Errorf("roots from config still provide scope evidence in static mode: %+v", c.Evidence)
	}
}

func TestUnknownPackageWithoutToolsHasNoCapabilities(t *testing.T) {
	unknown := &inspect.Server{Entry: discover.ServerEntry{Name: "mystery", Command: "npx", Args: []string{"-y", "some-random-mcp"}}, StaticOnly: true}
	caps, chains := attackpath.AnalyzeWithOptions([]*inspect.Server{unknown, fetch}, opts)
	if caps[0].Caps != attackpath.CapNone || len(chains) != 0 {
		t.Errorf("no evidence, no capabilities, no paths: caps=%v chains=%v", caps[0].Caps, ids(chains))
	}
}

func TestChainsAreDeterministicAndDeduplicated(t *testing.T) {
	a := chainsFor(t, fsHome, fetch, shell, slack)
	b := chainsFor(t, fsHome, fetch, shell, slack)
	if strings.Join(ids(a), ",") != strings.Join(ids(b), ",") {
		t.Errorf("order differs between runs: %v vs %v", ids(a), ids(b))
	}
	seen := map[string]bool{}
	for _, c := range a {
		key := c.ID + strings.Join(c.Servers, ",")
		if seen[key] {
			t.Errorf("duplicate chain %s", key)
		}
		seen[key] = true
	}
	// Critical first.
	for i := 1; i < len(a); i++ {
		if a[i-1].Severity == "high" && a[i].Severity == "critical" {
			t.Errorf("chains not sorted by severity: %v", ids(a))
		}
	}
}

func TestScopeClassification(t *testing.T) {
	cases := map[string]attackpath.FileScope{
		"~":                    attackpath.ScopeSensitive,
		"/":                    attackpath.ScopeSensitive,
		"/Users":               attackpath.ScopeSensitive,
		"/Users/dev/.ssh":      attackpath.ScopeSensitive,
		"/Users/dev/.config":   attackpath.ScopeSensitive, // contains gcloud, gh
		"/Users/dev/projects":  attackpath.ScopeProject,
		"/tmp":                 attackpath.ScopeProject,
		"/Users/dev/Documents": attackpath.ScopeProject,
	}
	for root, want := range cases {
		srv := server("fs", []string{"-y", "@modelcontextprotocol/server-filesystem", root}, tool("read_file", "path"))
		caps, _ := attackpath.AnalyzeWithOptions([]*inspect.Server{srv}, opts)
		if caps[0].Scope != want {
			t.Errorf("root %q: scope = %s, want %s", root, caps[0].Scope, want)
		}
	}
}
