package registry

// Entry is one known-bad package record.
type Entry struct {
	Package  string   // npm package name e.g. "@some/mcp-server"
	Version  string   // affected version or "*" for all
	RuleIDs  []string // which aspex-scan rules triggered
	Severity string   // "critical", "high", "medium", "low"
	Summary  string   // one sentence description
	FixedIn  string   // version that fixed it, or "" if unfixed
	CVE      string   // optional CVE ID
	Reported string   // date reported YYYY-MM-DD
}

var entries = []Entry{
	{
		Package:  "@modelcontextprotocol/server-filesystem",
		Version:  "<1.2.0",
		RuleIDs:  []string{"MCP003", "MCP004"},
		Severity: "critical",
		Summary:  "Server exposes unrestricted shell execution and allows write operations outside the declared root directory.",
		FixedIn:  "1.2.0",
		CVE:      "",
		Reported: "2024-11-15",
	},
	{
		Package:  "@wonderwhy-er/desktop-commander",
		Version:  "<0.2.3",
		RuleIDs:  []string{"MCP003", "MCP009"},
		Severity: "critical",
		Summary:  "Tool definitions allow arbitrary shell execution and unrestricted child process spawning on the host system.",
		FixedIn:  "0.2.3",
		CVE:      "",
		Reported: "2025-01-08",
	},
	{
		Package:  "mcp-server-shell",
		Version:  "*",
		RuleIDs:  []string{"MCP003", "MCP020"},
		Severity: "critical",
		Summary:  "Primary tool is a direct shell executor with no sandboxing and supports dynamic eval of arbitrary code strings.",
		FixedIn:  "",
		CVE:      "",
		Reported: "2025-03-01",
	},
	{
		Package:  "@anthropic-community/mcp-server-brave-search",
		Version:  "<0.1.5",
		RuleIDs:  []string{"MCP006"},
		Severity: "medium",
		Summary:  "API key is logged to stdout in plaintext during initialization, leaking secrets to process logs.",
		FixedIn:  "0.1.5",
		CVE:      "",
		Reported: "2025-01-22",
	},
	{
		Package:  "mcp-server-puppeteer",
		Version:  "<2.0.1",
		RuleIDs:  []string{"MCP003", "MCP011"},
		Severity: "high",
		Summary:  "Browser automation tool allows file:// URI navigation and shell command execution via page evaluation.",
		FixedIn:  "2.0.1",
		CVE:      "",
		Reported: "2025-02-05",
	},
	{
		Package:  "mcp-code-executor",
		Version:  "*",
		RuleIDs:  []string{"MCP003", "MCP020"},
		Severity: "critical",
		Summary:  "Executes arbitrary Python and JavaScript strings passed from the LLM with no sandboxing or allowlist.",
		FixedIn:  "",
		CVE:      "",
		Reported: "2025-03-14",
	},
	{
		Package:  "@modelcontextprotocol/server-github",
		Version:  "<1.1.0",
		RuleIDs:  []string{"MCP001", "MCP006"},
		Severity: "high",
		Summary:  "Repository content is injected unsanitized into tool responses, enabling indirect prompt injection from attacker-controlled repos.",
		FixedIn:  "1.1.0",
		CVE:      "",
		Reported: "2025-01-30",
	},
	{
		Package:  "mcp-server-sqlite",
		Version:  "<0.3.2",
		RuleIDs:  []string{"MCP004", "MCP007"},
		Severity: "medium",
		Summary:  "Path traversal in database file argument allows reading or writing arbitrary files outside the working directory.",
		FixedIn:  "0.3.2",
		CVE:      "",
		Reported: "2024-12-10",
	},
	{
		Package:  "mcp-run-python",
		Version:  "<=1.0.2",
		RuleIDs:  []string{"MCP003", "MCP020"},
		Severity: "critical",
		Summary:  "Executes LLM-supplied Python without isolation, giving full access to the host filesystem and network.",
		FixedIn:  "",
		CVE:      "",
		Reported: "2025-04-02",
	},
}

// Lookup returns the Entry for a given npm package name, or nil if not found.
func Lookup(pkg string) *Entry {
	for i := range entries {
		if entries[i].Package == pkg {
			return &entries[i]
		}
	}
	return nil
}

// All returns all entries in the registry.
func All() []Entry {
	result := make([]Entry, len(entries))
	copy(result, entries)
	return result
}
