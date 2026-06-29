// Package rules implements the aspex-scan risk rule catalog.
// Framework mappings:
//   OWASP LLM Top 10 2025: LLM01-LLM10 (https://owasp.org/www-project-top-10-for-large-language-model-applications/)
//   MITRE ATLAS: AML.Txxx (https://atlas.mitre.org/)
//   CWE: CWE-N (https://cwe.mitre.org/)
package rules

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/mcpclient"
)

// Severity levels.
type Severity int

const (
	SeverityInfo     Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

// Finding is a single rule match.
type Finding struct {
	RuleID   string
	Name     string
	Severity Severity
	Detail   string
	Fix      string
	// Comma-separated framework references, e.g. "OWASP LLM01, ATLAS AML.T0051, CWE-77"
	Mapping string
}

// Advisory holds educational context for a rule finding, surfaced when --explain is passed.
type Advisory struct {
	Why        string // why this is a risk (1–2 sentences)
	Exploit    string // how an attacker would realistically exploit it (concrete scenario)
	Impact     string // what the worst-case impact is
	Confidence string // "high" | "medium" | "low" — how sure we are this is truly malicious
}

// EvalServer runs all applicable rules against a server and returns any findings.
func EvalServer(srv *inspect.Server) []Finding {
	var f []Finding

	// Server-level rules.
	f = append(f, checkMCP001StaticDescription(srv)...)
	f = append(f, checkMCP006SecretsInEnv(srv)...)
	f = append(f, checkMCP007UnpinnedSource(srv)...)
	f = append(f, checkMCP010UnauthRemote(srv)...)
	f = append(f, checkMCP021PlaintextHTTP(srv)...)
	f = append(f, checkMCP023CloudMetadataEndpoint(srv)...)

	// Tool-set-level rules (need access to all tools at once).
	f = append(f, checkMCP025OverlappingToolNames(srv)...)
	f = append(f, checkMCP026ExcessiveToolCount(srv)...)

	// Per-tool rules.
	for i := range srv.Tools {
		f = append(f, evalTool(&srv.Tools[i])...)
		f = append(f, EvalToolCatalog(&srv.Tools[i])...)
	}

	// Per-resource catalog rules.
	for i := range srv.Resources {
		f = append(f, EvalResourceCatalog(&srv.Resources[i])...)
	}

	// Per-prompt catalog rules.
	for i := range srv.Prompts {
		f = append(f, EvalPromptCatalog(&srv.Prompts[i])...)
	}

	return f
}

func evalTool(t *mcpclient.Tool) []Finding {
	var f []Finding
	f = append(f, checkMCP001PromptInjection(t)...)
	f = append(f, checkMCP002DeceptiveToolName(t)...)
	f = append(f, checkMCP003ShellExec(t)...)
	f = append(f, checkMCP004ArbitraryFileWrite(t)...)
	f = append(f, checkMCP005UnrestrictedNetwork(t)...)
	f = append(f, checkMCP008PersistenceMechanism(t)...)
	f = append(f, checkMCP009ProcessSpawn(t)...)
	f = append(f, checkMCP011EnvVarAccess(t)...)
	f = append(f, checkMCP012ClipboardAccess(t)...)
	f = append(f, checkMCP013ScreenCapture(t)...)
	f = append(f, checkMCP014BrowserOrKeychainAccess(t)...)
	f = append(f, checkMCP015DatabaseBulkExport(t)...)
	f = append(f, checkMCP016InternalNetworkAccess(t)...)
	f = append(f, checkMCP017VersionControlCICDAccess(t)...)
	f = append(f, checkMCP018SuspiciouslyLongDescription(t)...)
	f = append(f, checkMCP019NoInputSchema(t)...)
	f = append(f, checkMCP020ArbitraryCodeExecution(t)...)
	f = append(f, checkMCP022PackageManifestAccess(t)...)
	f = append(f, checkMCP024SystemInfoGathering(t)...)
	return f
}

// ---- MCP001 (static): Prompt injection in config metadata.description -----------

func checkMCP001StaticDescription(srv *inspect.Server) []Finding {
	desc := srv.Entry.Description
	if desc == "" {
		return nil
	}
	for _, pat := range injectionPhrasePatterns {
		if pat.MatchString(desc) {
			return []Finding{{
				RuleID:   "MCP001",
				Name:     "Prompt injection in server config description",
				Severity: SeverityHigh,
				Detail:   "Server metadata.description matches prompt-injection pattern: " + pat.String(),
				Fix:      "Remove the malicious description from the MCP config. Do not trust this server.",
				Mapping:  "OWASP LLM01, ATLAS AML.T0051, CWE-77",
			}}
		}
	}
	return nil
}

// ---- MCP001: Prompt injection in tool description --------------------------------
// OWASP LLM01 | ATLAS AML.T0051 | CWE-77

var injectionPhrasePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context|rules?)`),
	regexp.MustCompile(`(?i)disregard\s+(your|all|any|previous|prior)`),
	regexp.MustCompile(`(?i)you\s+(are|must|should|will|shall)\s+(now\s+)?(act|behave|respond)\s+as`),
	regexp.MustCompile(`(?i)(new|updated|revised)\s+(role|persona|instructions?|directives?)`),
	regexp.MustCompile(`(?i)system\s*prompt`),
	regexp.MustCompile(`(?i)\bDAN\b`),
	regexp.MustCompile(`(?i)jailbreak`),
	regexp.MustCompile(`(?i)override\s+(your|all|any)\s+(safety|content|instructions?)`),
	regexp.MustCompile(`(?i)pretend\s+(you\s+are|to\s+be)\s+an?\s+(AI|LLM|model|assistant)`),
	regexp.MustCompile(`(?i)your\s+(true|real|actual)\s+(purpose|goal|objective)\s+is`),
	regexp.MustCompile(`(?i)do\s+not\s+(tell|inform|mention|disclose)\s+(the\s+)?(user|human)`),
	regexp.MustCompile(`(?i)without\s+(the\s+)?(user|human)\s+(knowing|awareness|consent)`),
}

func checkMCP001PromptInjection(t *mcpclient.Tool) []Finding {
	desc := t.Description
	for _, pat := range injectionPhrasePatterns {
		if pat.MatchString(desc) {
			return []Finding{{
				RuleID:   "MCP001",
				Name:     "Prompt injection in tool description",
				Severity: SeverityHigh,
				Detail:   "Tool description matches prompt-injection pattern: " + pat.String(),
				Fix:      "Remove or rewrite the tool description. Do not trust this server.",
				Mapping:  "OWASP LLM01, ATLAS AML.T0051, CWE-77",
			}}
		}
	}
	if containsHiddenUnicode(desc) {
		return []Finding{{
			RuleID:   "MCP001",
			Name:     "Prompt injection via hidden Unicode",
			Severity: SeverityHigh,
			Detail:   "Tool description contains hidden Unicode control characters (possible invisible instruction smuggling).",
			Fix:      "Remove this server. Hidden Unicode in a tool description is a strong indicator of malicious intent.",
			Mapping:  "OWASP LLM01, ATLAS AML.T0051, CWE-116",
		}}
	}
	return nil
}

func containsHiddenUnicode(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r) {
			if r != '​' { // zero-width space can appear in legitimate Markdown; skip
				return true
			}
		}
	}
	return false
}

// ---- MCP002: Deceptive tool name / homoglyph attack ----------------------------
// OWASP LLM01 | ATLAS AML.T0051 | CWE-116

// homoglyphMap maps confusable Unicode chars to their ASCII equivalent.
var homoglyphMap = map[rune]rune{
	'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'r', 'с': 'c', 'х': 'x', // Cyrillic
	'ɑ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ꜰ': 'f', 'ɢ': 'g',
	'ʜ': 'h', 'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n',
	'ᴏ': 'o', 'ᴘ': 'p', 'ǫ': 'q', 'ʀ': 'r', 'ꜱ': 's', 'ᴛ': 't', 'ᴜ': 'u',
	'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z',
}

func normalizeHomoglyphs(s string) string {
	var b strings.Builder
	for _, r := range s {
		if mapped, ok := homoglyphMap[r]; ok {
			b.WriteRune(mapped)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func checkMCP002DeceptiveToolName(t *mcpclient.Tool) []Finding {
	normalized := normalizeHomoglyphs(t.Name)
	if normalized != t.Name {
		return []Finding{{
			RuleID:   "MCP002",
			Name:     "Deceptive tool name (homoglyph attack)",
			Severity: SeverityHigh,
			Detail:   "Tool name '" + t.Name + "' contains non-ASCII characters that visually resemble ASCII. Normalized: '" + normalized + "'.",
			Fix:      "Remove this server immediately. Homoglyph substitution in tool names is a strong indicator of malicious intent.",
			Mapping:  "OWASP LLM01, ATLAS AML.T0051, CWE-116",
		}}
	}
	// Also flag tool names that shadow common trusted tool names with slight variations.
	suspicious := []string{"read__file", "write__file", "run__command", "exec__shell", "fetch__url"}
	lower := strings.ToLower(t.Name)
	for _, s := range suspicious {
		if lower == s {
			return []Finding{{
				RuleID:   "MCP002",
				Name:     "Deceptive tool name (shadow of trusted tool)",
				Severity: SeverityMedium,
				Detail:   "Tool name '" + t.Name + "' appears designed to shadow a well-known tool name with a subtle variation.",
				Fix:      "Verify this server is from a trusted source.",
				Mapping:  "OWASP LLM01, ATLAS AML.T0051",
			}}
		}
	}
	return nil
}

// ---- MCP003: Dangerous capability: shell/exec ----------------------------------
// OWASP LLM06, OWASP LLM08 | ATLAS AML.T0043 | CWE-78

var shellToolNames = []string{
	"run_command", "execute_command", "shell", "exec", "bash", "sh", "zsh", "fish",
	"run_script", "execute_script", "system", "eval", "invoke_command",
	"terminal", "cmd", "powershell", "command_execution",
}

var shellSchemaKeywords = []string{
	`"command"`, `"script"`, `"shell_command"`, `"cmd"`, `"bash_cmd"`,
}

func checkMCP003ShellExec(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	for _, n := range shellToolNames {
		if nameLower == n || strings.HasSuffix(nameLower, "_"+n) || strings.HasPrefix(nameLower, n+"_") {
			return []Finding{{
				RuleID:   "MCP003",
				Name:     "Dangerous capability: shell/exec",
				Severity: SeverityCritical,
				Detail:   "Tool '" + t.Name + "' exposes shell or command execution.",
				Fix:      "Remove this tool grant or restrict to an explicit allow-list of safe commands.",
				Mapping:  "OWASP LLM06, OWASP LLM08, ATLAS AML.T0043, CWE-78",
			}}
		}
	}
	schema := string(t.InputSchema)
	descLower := strings.ToLower(t.Description)
	for _, kw := range shellSchemaKeywords {
		if strings.Contains(schema, kw) &&
			(strings.Contains(descLower, "execut") || strings.Contains(descLower, "run") || strings.Contains(descLower, "shell")) {
			return []Finding{{
				RuleID:   "MCP003",
				Name:     "Dangerous capability: shell/exec (schema pattern)",
				Severity: SeverityCritical,
				Detail:   "Tool '" + t.Name + "' schema implies command execution via key: " + kw + ".",
				Fix:      "Remove this tool grant or restrict to an explicit allow-list.",
				Mapping:  "OWASP LLM06, OWASP LLM08, ATLAS AML.T0043, CWE-78",
			}}
		}
	}
	return nil
}

// ---- MCP004: Dangerous capability: arbitrary filesystem write ------------------
// OWASP LLM06 | CWE-732 | CWE-22

var writeToolPrefixes = []string{"write_", "delete_", "remove_", "overwrite_", "move_file", "rename_file", "truncate_"}
var writeSchemaPathKeys = []string{`"path"`, `"file_path"`, `"filepath"`, `"destination"`, `"dest"`, `"target_path"`}

func checkMCP004ArbitraryFileWrite(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	isWriteTool := false
	for _, p := range writeToolPrefixes {
		if strings.HasPrefix(nameLower, p) {
			isWriteTool = true
			break
		}
	}
	if !isWriteTool {
		return nil
	}
	schema := string(t.InputSchema)
	for _, k := range writeSchemaPathKeys {
		if strings.Contains(schema, k) {
			return []Finding{{
				RuleID:   "MCP004",
				Name:     "Dangerous capability: arbitrary filesystem write",
				Severity: SeverityHigh,
				Detail:   "Tool '" + t.Name + "' can write or delete files at arbitrary paths.",
				Fix:      "Restrict path parameters to an allowed directory. Reject absolute paths and path traversal.",
				Mapping:  "OWASP LLM06, CWE-732, CWE-22",
			}}
		}
	}
	return nil
}

// ---- MCP005: Unrestricted network/SSRF -----------------------------------------
// OWASP LLM08 | CWE-918

var networkToolNames = []string{
	"fetch", "http_request", "curl", "get_url", "web_fetch",
	"browse", "request", "http_get", "http_post", "download",
	"open_url", "load_url", "scrape",
}

func checkMCP005UnrestrictedNetwork(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	matched := false
	for _, n := range networkToolNames {
		if nameLower == n || strings.Contains(nameLower, n) {
			matched = true
			break
		}
	}
	if !matched {
		return nil
	}
	schema := string(t.InputSchema)
	hasURLParam := strings.Contains(schema, `"url"`) || strings.Contains(schema, `"uri"`) || strings.Contains(schema, `"endpoint"`)
	hasAllowList := strings.Contains(schema, "allowedDomains") || strings.Contains(schema, "allowList") ||
		strings.Contains(schema, "allowlist") || strings.Contains(schema, "whitelist")
	if hasURLParam && !hasAllowList {
		return []Finding{{
			RuleID:   "MCP005",
			Name:     "Dangerous capability: unrestricted network access (SSRF)",
			Severity: SeverityHigh,
			Detail:   "Tool '" + t.Name + "' accepts an arbitrary URL with no visible allow-list. Risk: SSRF, internal network probing, data exfiltration.",
			Fix:      "Add an allowed-domain list or remove unrestricted fetch capability.",
			Mapping:  "OWASP LLM08, CWE-918",
		}}
	}
	return nil
}

// ---- MCP006: Secrets in config env ---------------------------------------------
// OWASP LLM02 | CWE-312 | CWE-522

var secretKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(AWS_)?ACCESS_KEY`),
	regexp.MustCompile(`(?i)^(AWS_)?SECRET`),
	regexp.MustCompile(`(?i)^AKIA[0-9A-Z]{16}`), // AWS key ID format
	regexp.MustCompile(`(?i)^(GITHUB|GH)_(TOKEN|KEY|PAT|SECRET)`),
	regexp.MustCompile(`(?i)^(GITLAB|BITBUCKET)_(TOKEN|KEY|SECRET)`),
	regexp.MustCompile(`(?i)^(OPENAI|ANTHROPIC|COHERE|MISTRAL|GROQ|GEMINI|HUGGINGFACE)_API_KEY`),
	regexp.MustCompile(`(?i)^(STRIPE|SENDGRID|TWILIO|MAILGUN|RESEND|POSTMARK)_(API_)?KEY`),
	regexp.MustCompile(`(?i)^(SLACK|DISCORD|TELEGRAM)_(BOT_)?TOKEN`),
	regexp.MustCompile(`(?i)^(AZURE|GCP|GOOGLE)_(KEY|SECRET|TOKEN|CREDENTIALS?)`),
	regexp.MustCompile(`(?i)^DATADOG_(API|APP)_KEY`),
	regexp.MustCompile(`(?i)_(API_KEY|SECRET_KEY|PRIVATE_KEY|PASSWORD|PASSWD|PASS|TOKEN|SECRET|CREDENTIAL)$`),
	regexp.MustCompile(`(?i)^(DB|DATABASE)_(PASSWORD|PASS|SECRET)`),
	regexp.MustCompile(`(?i)^JWT_(SECRET|KEY|PRIVATE)`),
	regexp.MustCompile(`(?i)^ENCRYPTION_(KEY|SECRET)`),
	regexp.MustCompile(`(?i)^(RSA|DSA|ECDSA|ED25519)_PRIVATE`),
}

func checkMCP006SecretsInEnv(srv *inspect.Server) []Finding {
	var findings []Finding
	seen := map[string]bool{}
	for _, key := range srv.Entry.EnvKeys {
		for _, pat := range secretKeyPatterns {
			if pat.MatchString(key) && !seen[key] {
				seen[key] = true
				findings = append(findings, Finding{
					RuleID:   "MCP006",
					Name:     "Secrets in config env",
					Severity: SeverityCritical,
					Detail:   "Env key '" + key + "' matches a known secret/credential pattern and is stored in plaintext config.",
					Fix:      "Move secrets to a vault or OS keychain. Set the env var outside the MCP config file.",
					Mapping:  "OWASP LLM02, CWE-312, CWE-522",
				})
			}
		}
	}
	return findings
}

// ---- MCP007: Untrusted/unpinned source -----------------------------------------
// OWASP LLM03 | ATLAS AML.T0010 | CWE-829

func checkMCP007UnpinnedSource(srv *inspect.Server) []Finding {
	cmd := srv.Entry.Command
	args := srv.Entry.Args
	cmdLine := strings.Join(append([]string{cmd}, args...), " ")

	if strings.Contains(cmdLine, "@latest") || strings.Contains(cmdLine, "@next") || strings.Contains(cmdLine, "@beta") {
		return []Finding{{
			RuleID:   "MCP007",
			Name:     "Untrusted/unpinned source (@latest tag)",
			Severity: SeverityMedium,
			Detail:   "Server uses a mutable tag ('@latest', '@next', '@beta') and may silently pull a malicious update.",
			Fix:      "Pin to a specific version (e.g. @1.2.3) and use a lockfile. Verify the package author.",
			Mapping:  "OWASP LLM03, ATLAS AML.T0010, CWE-829",
		}}
	}

	// npx with an unscoped, unversioned package name is also risky.
	if (cmd == "npx" || cmd == "bunx") && len(args) > 0 {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			// Unscoped package with no version pin and no path separator.
			if !strings.Contains(a, "@") && !strings.Contains(a, "/") && !strings.Contains(a, ".") {
				return []Finding{{
					RuleID:   "MCP007",
					Name:     "Untrusted/unpinned source (no version pin)",
					Severity: SeverityMedium,
					Detail:   "Server launched via npx with no version pin on package '" + a + "'.",
					Fix:      "Pin to a specific version and verify the package author on npmjs.com.",
					Mapping:  "OWASP LLM03, ATLAS AML.T0010, CWE-829",
				}}
			}
		}
	}
	return nil
}

// ---- MCP008: Persistence mechanism capability ----------------------------------
// OWASP LLM06 | ATLAS AML.T0048 | CWE-284

var persistenceToolNames = []string{
	"write_crontab", "edit_crontab", "add_cron", "create_cron",
	"write_startup", "add_startup", "install_service", "create_service",
	"register_autorun", "write_launchagent", "write_launchdaemon",
	"write_systemd", "enable_service",
}

var persistencePaths = []string{
	"crontab", "/etc/cron", "/etc/init.d", "/etc/systemd",
	"LaunchAgents", "LaunchDaemons",
	"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
	"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
	".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile",
	"/etc/profile.d", "/etc/environment",
}

func checkMCP008PersistenceMechanism(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	for _, n := range persistenceToolNames {
		if nameLower == n || strings.Contains(nameLower, n) {
			return []Finding{{
				RuleID:   "MCP008",
				Name:     "Dangerous capability: persistence mechanism",
				Severity: SeverityCritical,
				Detail:   "Tool '" + t.Name + "' can install persistence (cron, startup, service, shell rc).",
				Fix:      "Remove this capability. Persistent execution grants should never be delegated to an MCP server.",
				Mapping:  "OWASP LLM06, ATLAS AML.T0048, CWE-284",
			}}
		}
	}
	// Check description for persistence path references.
	descLower := strings.ToLower(t.Description)
	for _, p := range persistencePaths {
		if strings.Contains(descLower, strings.ToLower(p)) {
			return []Finding{{
				RuleID:   "MCP008",
				Name:     "Dangerous capability: persistence mechanism (path in description)",
				Severity: SeverityHigh,
				Detail:   "Tool '" + t.Name + "' description references a persistence/startup path: " + p + ".",
				Fix:      "Verify this tool cannot write to startup or shell init locations.",
				Mapping:  "OWASP LLM06, ATLAS AML.T0048, CWE-284",
			}}
		}
	}
	return nil
}

// ---- MCP009: Process spawn / subprocess creation -------------------------------
// OWASP LLM06 | CWE-78

var processSpawnNames = []string{
	"spawn_process", "create_process", "start_process", "launch_process",
	"fork", "popen", "subprocess", "start_program", "open_application",
	"launch_app", "run_app",
}

func checkMCP009ProcessSpawn(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	for _, n := range processSpawnNames {
		if nameLower == n || strings.Contains(nameLower, n) {
			return []Finding{{
				RuleID:   "MCP009",
				Name:     "Dangerous capability: process spawn",
				Severity: SeverityHigh,
				Detail:   "Tool '" + t.Name + "' can create or spawn new processes.",
				Fix:      "Remove this capability unless strictly necessary and scoped to specific allowed programs.",
				Mapping:  "OWASP LLM06, CWE-78",
			}}
		}
	}
	return nil
}

// ---- MCP010: Unauthenticated remote server -------------------------------------
// OWASP LLM02 | CWE-306

func checkMCP010UnauthRemote(srv *inspect.Server) []Finding {
	if srv.Entry.URL == "" {
		return nil
	}
	for _, k := range srv.Entry.EnvKeys {
		kl := strings.ToLower(k)
		if strings.Contains(kl, "auth") || strings.Contains(kl, "token") ||
			strings.Contains(kl, "key") || strings.Contains(kl, "bearer") ||
			strings.Contains(kl, "secret") {
			return nil
		}
	}
	return []Finding{{
		RuleID:   "MCP010",
		Name:     "Unauthenticated remote server",
		Severity: SeverityMedium,
		Detail:   "Remote MCP server at '" + srv.Entry.URL + "' has no auth token configured.",
		Fix:      "Add authentication headers or restrict access to trusted networks only.",
		Mapping:  "OWASP LLM02, CWE-306",
	}}
}

// ---- MCP011: Environment variable access ---------------------------------------
// OWASP LLM02 | CWE-214 | CWE-526

var envAccessNames = []string{
	"get_env", "read_env", "list_env", "dump_env", "get_environment",
	"read_environment", "env_dump", "getenv", "read_envvar",
}

func checkMCP011EnvVarAccess(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	for _, n := range envAccessNames {
		if nameLower == n || strings.Contains(nameLower, n) {
			return []Finding{{
				RuleID:   "MCP011",
				Name:     "Environment variable access",
				Severity: SeverityHigh,
				Detail:   "Tool '" + t.Name + "' can read environment variables, which typically contain API keys, tokens, and credentials.",
				Fix:      "Remove this tool or restrict it to a specific allow-list of non-sensitive variable names.",
				Mapping:  "OWASP LLM02, CWE-214, CWE-526",
			}}
		}
	}
	// Also check schema for env-reading patterns.
	schema := string(t.InputSchema)
	if strings.Contains(schema, `"env_var"`) || strings.Contains(schema, `"variable_name"`) {
		descLower := strings.ToLower(t.Description)
		if strings.Contains(descLower, "environment") || strings.Contains(descLower, "env var") {
			return []Finding{{
				RuleID:   "MCP011",
				Name:     "Environment variable access (schema pattern)",
				Severity: SeverityMedium,
				Detail:   "Tool '" + t.Name + "' schema accepts an environment variable name parameter.",
				Fix:      "Restrict to a specific allow-list of non-sensitive variable names.",
				Mapping:  "OWASP LLM02, CWE-214, CWE-526",
			}}
		}
	}
	return nil
}

// ---- MCP012: Clipboard access --------------------------------------------------
// OWASP LLM02 | CWE-359

var clipboardToolNames = []string{
	"read_clipboard", "get_clipboard", "clipboard_read", "paste",
	"write_clipboard", "set_clipboard", "clipboard_write", "copy",
	"clipboard", "get_pasteboard",
}

func checkMCP012ClipboardAccess(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	for _, n := range clipboardToolNames {
		if nameLower == n || nameLower == "get_"+n || nameLower == "read_"+n {
			sev := SeverityMedium
			detail := "read clipboard content (potential access to copied passwords, tokens, or sensitive text)"
			if strings.Contains(nameLower, "write") || strings.Contains(nameLower, "set") || nameLower == "copy" {
				sev = SeverityLow
				detail = "write to clipboard"
			}
			return []Finding{{
				RuleID:   "MCP012",
				Name:     "Clipboard access",
				Severity: sev,
				Detail:   "Tool '" + t.Name + "' can " + detail + ".",
				Fix:      "Remove clipboard access unless it is a core feature of the server's stated purpose.",
				Mapping:  "OWASP LLM02, CWE-359",
			}}
		}
	}
	return nil
}

// ---- MCP013: Screen capture / screenshot ---------------------------------------
// OWASP LLM02 | CWE-359

var screenToolNames = []string{
	"screenshot", "capture_screen", "screen_capture", "take_screenshot",
	"record_screen", "screen_record", "capture_display",
}

func checkMCP013ScreenCapture(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	for _, n := range screenToolNames {
		if nameLower == n || strings.Contains(nameLower, n) {
			return []Finding{{
				RuleID:   "MCP013",
				Name:     "Screen capture capability",
				Severity: SeverityHigh,
				Detail:   "Tool '" + t.Name + "' can capture screen contents, which may expose sensitive information visible on screen.",
				Fix:      "Remove this capability unless it is central to the server's stated purpose.",
				Mapping:  "OWASP LLM02, CWE-359",
			}}
		}
	}
	return nil
}

// ---- MCP014: Browser or keychain/credential store access ----------------------
// OWASP LLM02 | CWE-522

var browserAccessNames = []string{
	"get_cookies", "read_cookies", "list_cookies", "export_cookies",
	"get_browser_history", "read_history", "browser_history",
	"get_saved_passwords", "read_passwords", "keychain_get", "keychain_read",
	"get_credentials", "read_credentials", "credential_manager",
	"get_keychain", "read_keychain", "access_keychain",
}

func checkMCP014BrowserOrKeychainAccess(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	for _, n := range browserAccessNames {
		if nameLower == n || strings.Contains(nameLower, n) {
			return []Finding{{
				RuleID:   "MCP014",
				Name:     "Browser or credential store access",
				Severity: SeverityCritical,
				Detail:   "Tool '" + t.Name + "' can access browser cookies, saved passwords, or OS keychain. This is a severe credential exfiltration risk.",
				Fix:      "Remove this server immediately. No legitimate MCP workflow requires reading a browser's saved passwords or OS keychain.",
				Mapping:  "OWASP LLM02, CWE-522, CWE-312",
			}}
		}
	}
	return nil
}

// ---- MCP015: Database bulk export capability -----------------------------------
// OWASP LLM02 | CWE-89

var dbDumpNames = []string{
	"dump_database", "export_database", "db_dump", "backup_database",
	"database_dump", "export_table", "dump_table", "export_all",
}

var rawQueryPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"(raw_?query|sql_query|query_string|statement)"\s*:`),
}

func checkMCP015DatabaseBulkExport(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	for _, n := range dbDumpNames {
		if nameLower == n || strings.Contains(nameLower, n) {
			return []Finding{{
				RuleID:   "MCP015",
				Name:     "Database bulk export capability",
				Severity: SeverityHigh,
				Detail:   "Tool '" + t.Name + "' can export or dump entire database tables.",
				Fix:      "Restrict to parameterized, row-limited queries. Remove bulk export capability.",
				Mapping:  "OWASP LLM02, CWE-89",
			}}
		}
	}
	schema := string(t.InputSchema)
	for _, pat := range rawQueryPatterns {
		if pat.MatchString(schema) {
			return []Finding{{
				RuleID:   "MCP015",
				Name:     "Raw SQL query parameter",
				Severity: SeverityHigh,
				Detail:   "Tool '" + t.Name + "' accepts a raw SQL query string (SQL injection risk and potential for unrestricted data access).",
				Fix:      "Use parameterized queries. Never pass raw SQL from the model to the database.",
				Mapping:  "OWASP LLM02, CWE-89",
			}}
		}
	}
	return nil
}

// ---- MCP016: Internal network / localhost bypass ------------------------------
// OWASP LLM08 | CWE-918

var internalNetworkPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)localhost`),
	regexp.MustCompile(`(?i)127\.0\.0\.`),
	regexp.MustCompile(`(?i)0\.0\.0\.0`),
	regexp.MustCompile(`(?i)::1`),
	regexp.MustCompile(`(?i)192\.168\.`),
	regexp.MustCompile(`(?i)10\.\d+\.\d+\.\d+`),
	regexp.MustCompile(`(?i)172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+`),
}

func checkMCP016InternalNetworkAccess(t *mcpclient.Tool) []Finding {
	descLower := strings.ToLower(t.Description)
	schema := string(t.InputSchema)
	combined := descLower + " " + strings.ToLower(schema)
	for _, pat := range internalNetworkPatterns {
		if pat.MatchString(combined) {
			// Only flag if the tool also accepts a URL/host param (not just a mention).
			if strings.Contains(schema, `"url"`) || strings.Contains(schema, `"host"`) || strings.Contains(schema, `"endpoint"`) {
				return []Finding{{
					RuleID:   "MCP016",
					Name:     "Internal network access",
					Severity: SeverityMedium,
					Detail:   "Tool '" + t.Name + "' description or schema references internal network addresses (SSRF / internal pivot risk).",
					Fix:      "Block requests to private/internal IP ranges. Use an explicit allow-list of external domains.",
					Mapping:  "OWASP LLM08, CWE-918",
				}}
			}
		}
	}
	return nil
}

// ---- MCP017: Version control / CI/CD access ------------------------------------
// OWASP LLM02 | CWE-312

var vcsToolNames = []string{
	"git_push", "git_force_push", "git_reset_hard", "git_clean",
	"delete_branch", "force_merge", "rewrite_history", "git_rebase_force",
}

var cicdPaths = []string{
	".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci",
	".travis.yml", "azure-pipelines.yml", ".drone.yml", "bitbucket-pipelines.yml",
	".git/config", ".git/hooks",
}

func checkMCP017VersionControlCICDAccess(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	for _, n := range vcsToolNames {
		if nameLower == n || strings.Contains(nameLower, n) {
			return []Finding{{
				RuleID:   "MCP017",
				Name:     "Dangerous VCS operation",
				Severity: SeverityHigh,
				Detail:   "Tool '" + t.Name + "' can perform destructive or force-push VCS operations.",
				Fix:      "Remove force/destructive VCS capabilities. All VCS writes should require explicit user confirmation.",
				Mapping:  "OWASP LLM02, OWASP LLM06, CWE-284",
			}}
		}
	}
	// Check for CI/CD config write access.
	schema := strings.ToLower(string(t.InputSchema))
	descLower := strings.ToLower(t.Description)
	for _, p := range cicdPaths {
		lower := strings.ToLower(p)
		if strings.Contains(schema, lower) || strings.Contains(descLower, lower) {
			if strings.HasPrefix(nameLower, "write_") || strings.HasPrefix(nameLower, "edit_") || strings.Contains(nameLower, "modify") {
				return []Finding{{
					RuleID:   "MCP017",
					Name:     "CI/CD pipeline write access",
					Severity: SeverityCritical,
					Detail:   "Tool '" + t.Name + "' can write to CI/CD configuration files (" + p + "). This enables supply chain compromise.",
					Fix:      "Remove write access to CI/CD configs. These must never be writable by an MCP server.",
					Mapping:  "OWASP LLM03, OWASP LLM06, ATLAS AML.T0010, CWE-284",
				}}
			}
		}
	}
	return nil
}

// ---- MCP018: Suspiciously long tool description --------------------------------
// OWASP LLM01 | ATLAS AML.T0051

const maxDescriptionLength = 2000

func checkMCP018SuspiciouslyLongDescription(t *mcpclient.Tool) []Finding {
	if len(t.Description) > maxDescriptionLength {
		return []Finding{{
			RuleID:   "MCP018",
			Name:     "Suspiciously long tool description",
			Severity: SeverityMedium,
			Detail:   "Tool '" + t.Name + "' description is " + itoa(len(t.Description)) + " characters. Unusually long descriptions can be used to smuggle instructions or overflow context.",
			Fix:      "Review the full description manually. Legitimate tool descriptions are rarely over 500 characters.",
			Mapping:  "OWASP LLM01, ATLAS AML.T0051",
		}}
	}
	return nil
}

// ---- MCP019: No input schema (fully unvalidated input) -------------------------
// OWASP LLM06 | CWE-20

func checkMCP019NoInputSchema(t *mcpclient.Tool) []Finding {
	// Only flag tools that take parameters but have no schema.
	if len(t.InputSchema) == 0 || string(t.InputSchema) == "{}" || string(t.InputSchema) == "null" {
		// Only warn for tools that sound like they accept input (not getters with no args).
		nameLower := strings.ToLower(t.Name)
		if strings.Contains(nameLower, "run") || strings.Contains(nameLower, "exec") ||
			strings.Contains(nameLower, "write") || strings.Contains(nameLower, "send") ||
			strings.Contains(nameLower, "post") || strings.Contains(nameLower, "delete") {
			return []Finding{{
				RuleID:   "MCP019",
				Name:     "No input schema defined",
				Severity: SeverityLow,
				Detail:   "Tool '" + t.Name + "' has no input schema. The model will pass unvalidated input directly to the server.",
				Fix:      "Add a JSON Schema to the tool definition to constrain acceptable inputs.",
				Mapping:  "OWASP LLM06, CWE-20",
			}}
		}
	}
	return nil
}

// ---- MCP020: Arbitrary code execution via eval/compile -------------------------
// OWASP LLM06 | CWE-94

var evalToolNames = []string{
	"eval_code", "run_code", "execute_code", "compile_and_run",
	"python_eval", "js_eval", "ruby_eval", "node_eval",
	"run_python", "run_javascript", "run_ruby", "run_go",
	"code_interpreter", "repl", "sandbox_exec",
}

var evalSchemaPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"(code|source_code|program|snippet|expression)"\s*:`),
}

func checkMCP020ArbitraryCodeExecution(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	for _, n := range evalToolNames {
		if nameLower == n || strings.Contains(nameLower, n) {
			return []Finding{{
				RuleID:   "MCP020",
				Name:     "Arbitrary code execution (eval/interpreter)",
				Severity: SeverityCritical,
				Detail:   "Tool '" + t.Name + "' can execute arbitrary code passed as a parameter.",
				Fix:      "Remove this capability or sandbox it strictly (no filesystem, network, or process access). Never allow unsandboxed code eval.",
				Mapping:  "OWASP LLM06, CWE-94, CWE-78",
			}}
		}
	}
	schema := string(t.InputSchema)
	for _, pat := range evalSchemaPatterns {
		if pat.MatchString(schema) {
			descLower := strings.ToLower(t.Description)
			if strings.Contains(descLower, "execut") || strings.Contains(descLower, "run") ||
				strings.Contains(descLower, "eval") || strings.Contains(descLower, "interpret") {
				return []Finding{{
					RuleID:   "MCP020",
					Name:     "Arbitrary code execution (schema pattern)",
					Severity: SeverityCritical,
					Detail:   "Tool '" + t.Name + "' accepts a 'code' or 'program' parameter and description implies execution.",
					Fix:      "Remove this capability or strictly sandbox it.",
					Mapping:  "OWASP LLM06, CWE-94, CWE-78",
				}}
			}
		}
	}
	return nil
}

// ---- MCP021: Plaintext HTTP remote server (no TLS) ----------------------------
// OWASP LLM02 | CWE-319

func checkMCP021PlaintextHTTP(srv *inspect.Server) []Finding {
	if strings.HasPrefix(srv.Entry.URL, "http://") {
		return []Finding{{
			RuleID:   "MCP021",
			Name:     "Remote server using plaintext HTTP (no TLS)",
			Severity: SeverityCritical,
			Detail:   "Remote MCP server at '" + srv.Entry.URL + "' uses unencrypted HTTP. Tool calls and responses are visible on the network.",
			Fix:      "Use HTTPS. Never transmit tool calls or responses over plaintext HTTP.",
			Mapping:  "OWASP LLM02, CWE-319",
		}}
	}
	return nil
}

// ---- MCP022: Package manifest / dependency file access -------------------------
// OWASP LLM03 | CWE-829

var packageManifestPaths = []string{
	"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
	"requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
	"Gemfile", "Gemfile.lock", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
	"composer.json", "composer.lock", "pom.xml", "build.gradle",
}

func checkMCP022PackageManifestAccess(t *mcpclient.Tool) []Finding {
	descLower := strings.ToLower(t.Description)
	schema := strings.ToLower(string(t.InputSchema))
	for _, p := range packageManifestPaths {
		lower := strings.ToLower(p)
		if strings.Contains(descLower, lower) || strings.Contains(schema, lower) {
			if strings.HasPrefix(strings.ToLower(t.Name), "write_") || strings.HasPrefix(strings.ToLower(t.Name), "edit_") {
				return []Finding{{
					RuleID:   "MCP022",
					Name:     "Package manifest write access",
					Severity: SeverityHigh,
					Detail:   "Tool '" + t.Name + "' can write to package manifests (" + p + "). This enables dependency injection and supply chain attacks.",
					Fix:      "Remove write access to dependency manifests.",
					Mapping:  "OWASP LLM03, ATLAS AML.T0010, CWE-829",
				}}
			}
		}
	}
	return nil
}

// ---- MCP023: Cloud metadata endpoint access -----------------------------------
// OWASP LLM08 | CWE-918

var cloudMetadataEndpoints = []string{
	"169.254.169.254",          // AWS/GCP/Azure IMDS
	"metadata.google.internal", // GCP
	"169.254.170.2",            // ECS task metadata
	"fd00:ec2::254",            // AWS IPv6 IMDS
}

func checkMCP023CloudMetadataEndpoint(srv *inspect.Server) []Finding {
	combined := strings.ToLower(srv.Entry.Command + " " + strings.Join(srv.Entry.Args, " ") + " " + srv.Entry.URL)
	for _, ep := range cloudMetadataEndpoints {
		if strings.Contains(combined, ep) {
			return []Finding{{
				RuleID:   "MCP023",
				Name:     "Cloud metadata endpoint in config",
				Severity: SeverityCritical,
				Detail:   "Server config references the cloud metadata endpoint (" + ep + "). This endpoint returns IAM credentials and instance identity documents.",
				Fix:      "Remove this server. No legitimate MCP server should communicate with the cloud metadata service.",
				Mapping:  "OWASP LLM08, CWE-918",
			}}
		}
	}
	return nil
}

// ---- MCP024: System information gathering ------------------------------------
// OWASP LLM02 | CWE-200

var sysInfoToolNames = []string{
	"get_system_info", "list_processes", "ps_aux", "tasklist",
	"get_running_processes", "list_open_ports", "netstat", "ifconfig",
	"get_network_interfaces", "arp_scan", "nmap", "port_scan",
	"get_installed_packages", "list_users", "get_user_list",
	"get_hostname", "get_ip_address", "whoami_detailed",
}

func checkMCP024SystemInfoGathering(t *mcpclient.Tool) []Finding {
	nameLower := strings.ToLower(t.Name)
	for _, n := range sysInfoToolNames {
		if nameLower == n || strings.Contains(nameLower, n) {
			sev := SeverityMedium
			detail := "gather system information (hostname, IPs, users, installed packages)"
			if strings.Contains(n, "scan") || strings.Contains(n, "nmap") || strings.Contains(n, "port") {
				sev = SeverityHigh
				detail = "perform network scanning or port enumeration"
			}
			return []Finding{{
				RuleID:   "MCP024",
				Name:     "System information gathering",
				Severity: sev,
				Detail:   "Tool '" + t.Name + "' can " + detail + ". This information is useful for privilege escalation and lateral movement.",
				Fix:      "Remove or restrict this tool to the minimum information necessary.",
				Mapping:  "OWASP LLM02, CWE-200, ATLAS AML.T0043",
			}}
		}
	}
	return nil
}

// ---- MCP025: Overlapping/shadowed tool names across servers -------------------
// OWASP LLM01 | ATLAS AML.T0051

func checkMCP025OverlappingToolNames(srv *inspect.Server) []Finding {
	seen := map[string]int{}
	for _, t := range srv.Tools {
		seen[strings.ToLower(t.Name)]++
	}
	var findings []Finding
	for name, count := range seen {
		if count > 1 {
			findings = append(findings, Finding{
				RuleID:   "MCP025",
				Name:     "Duplicate tool name within server",
				Severity: SeverityMedium,
				Detail:   "Tool name '" + name + "' appears " + itoa(count) + " times in this server. The model may call the wrong one.",
				Fix:      "Deduplicate tool names within the server.",
				Mapping:  "OWASP LLM01, ATLAS AML.T0051",
			})
		}
	}
	return findings
}

// ---- MCP026: Excessive tool count / large attack surface ----------------------
// OWASP LLM06 | CWE-272

const excessiveToolThreshold = 30

func checkMCP026ExcessiveToolCount(srv *inspect.Server) []Finding {
	if len(srv.Tools) > excessiveToolThreshold {
		return []Finding{{
			RuleID:   "MCP026",
			Name:     "Excessive tool count",
			Severity: SeverityInfo,
			Detail:   "Server exposes " + itoa(len(srv.Tools)) + " tools. Large tool surfaces increase the risk of confused deputy attacks and make auditing harder.",
			Fix:      "Review whether all tools are necessary. Consider splitting into scoped servers.",
			Mapping:  "OWASP LLM06, CWE-272",
		}}
	}
	return nil
}

// ---- helpers -----------------------------------------------------------------

func itoa(n int) string { return strconv.Itoa(n) }
