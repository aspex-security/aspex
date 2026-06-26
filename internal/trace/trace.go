// Package trace applies security analysis rules to the parsed MCP event stream.
// Framework mappings:
//   OWASP LLM Top 10 2025: LLM01-LLM10
//   MITRE ATLAS: AML.Txxx
//   CWE: CWE-N
package trace

import (
	"regexp"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/rules"
)

// FlaggedEvent pairs an event with the trace rule findings it triggered.
type FlaggedEvent struct {
	Event    logparse.Event
	Findings []rules.Finding
}

// SessionState holds per-session running state for stateful rules.
type SessionState struct {
	// serverDataSeen tracks which servers have had data read in this session (for AT015).
	serverDataSeen map[string]bool
	// errorTimes holds timestamps of recent errors (for AT011 burst detection).
	errorTimes []time.Time
	// readCount tracks how many read/list operations have occurred (for AT013).
	readCount int
}

// AnalyzeEvents runs all trace rules against a slice of events and returns flagged events.
// Stateful rules (burst, cross-server flow) operate across the full slice.
func AnalyzeEvents(events []logparse.Event) []FlaggedEvent {
	var flagged []FlaggedEvent
	state := &SessionState{
		serverDataSeen: map[string]bool{},
	}

	for i := range events {
		ev := &events[i]
		var findings []rules.Finding

		// Stateless per-event rules.
		findings = append(findings, checkAT001SensitivePath(ev)...)
		findings = append(findings, checkAT002OutboundNetwork(ev)...)
		findings = append(findings, checkAT003ShellExec(ev)...)
		findings = append(findings, checkAT004HighVolumeDataRead(ev)...)
		findings = append(findings, checkAT005UnusualHourActivity(ev)...)
		findings = append(findings, checkAT006ConfigFileModified(ev)...)
		findings = append(findings, checkAT007CloudMetadataAccess(ev)...)
		findings = append(findings, checkAT008VCSInternalAccess(ev)...)
		findings = append(findings, checkAT009PackageManifestWrite(ev)...)
		findings = append(findings, checkAT010BrowserOrKeychainAccess(ev)...)
		findings = append(findings, checkAT012LateralMovement(ev)...)
		findings = append(findings, checkAT013PersistenceWrite(ev, state)...)
		findings = append(findings, checkAT014ArbitraryCodeExecution(ev)...)
		findings = append(findings, checkAT016EnvVarDump(ev)...)
		findings = append(findings, checkAT017DatabaseDump(ev)...)
		findings = append(findings, checkAT018NetworkScan(ev)...)
		findings = append(findings, checkAT019ClipboardRead(ev)...)
		findings = append(findings, checkAT020ScreenCapture(ev)...)

		// Stateful rules (update state, may produce findings).
		findings = append(findings, checkAT011ErrorBurst(ev, state)...)
		findings = append(findings, checkAT013MassFileEnumeration(ev, state)...)
		findings = append(findings, checkAT015CrossServerDataChain(ev, state)...)

		if len(findings) > 0 {
			flagged = append(flagged, FlaggedEvent{Event: *ev, Findings: findings})
		}
	}
	return flagged
}

// ---- AT001: Sensitive path accessed ------------------------------------------
// OWASP LLM02 | CWE-22 | CWE-312

var sensitivePaths = []string{
	".env", ".env.", "/.ssh/", "/ssh/id_", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
	"known_hosts", "authorized_keys",
	".aws/credentials", ".aws/config",
	"credentials.json", "token.json", "service_account",
	".npmrc", ".pypirc", ".netrc", ".htpasswd", ".pgpass",
	"secrets.yaml", "secrets.yml", "secrets.json",
	"~/.gnupg", "/.gnupg/", ".pgp", "secring.gpg",
	"vault", "1password", "bitwarden",
	"kubeconfig", "/.kube/config",
	".docker/config.json",
	"~/.config/gcloud/", "application_default_credentials.json",
	"~/.azure/", "~/.config/github-copilot",
	"/etc/shadow", "/etc/passwd", "/etc/sudoers",
	"private.key", "private_key.pem", "privkey.pem", "server.key",
	".p12", ".pfx", ".jks", ".keystore",
}

func checkAT001SensitivePath(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall && ev.Event != logparse.EventResourceRead {
		return nil
	}
	for _, arg := range ev.Args {
		lower := strings.ToLower(arg)
		for _, pat := range sensitivePaths {
			if strings.Contains(lower, strings.ToLower(pat)) {
				return []rules.Finding{{
					RuleID:   "AT001",
					Name:     "Sensitive path accessed",
					Severity: rules.SeverityHigh,
					Detail:   "Tool arg references sensitive path: " + arg,
					Fix:      "Review whether this access was intended and authorized.",
					Mapping:  "OWASP LLM02, CWE-22, CWE-312",
				}}
			}
		}
	}
	return nil
}

// ---- AT002: Outbound network call --------------------------------------------
// OWASP LLM08 | CWE-918

var networkToolNames = []string{
	"fetch", "http_request", "curl", "get_url", "web_fetch",
	"browse", "request", "http_get", "http_post", "download",
	"open_url", "load_url", "scrape",
}

func checkAT002OutboundNetwork(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	isNetworkTool := false
	for _, n := range networkToolNames {
		if strings.Contains(toolLower, n) {
			isNetworkTool = true
			break
		}
	}
	if !isNetworkTool {
		return nil
	}
	for _, arg := range ev.Args {
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			return []rules.Finding{{
				RuleID:   "AT002",
				Name:     "Outbound network call",
				Severity: rules.SeverityHigh,
				Detail:   "Tool '" + ev.Tool + "' made an outbound request to: " + arg,
				Fix:      "Verify this network call was expected and authorized. Check destination for known malicious domains.",
				Mapping:  "OWASP LLM08, CWE-918",
			}}
		}
	}
	return nil
}

// ---- AT003: Shell command executed ------------------------------------------
// OWASP LLM06 | CWE-78 | ATLAS AML.T0043

var shellToolNames = []string{
	"run_command", "execute_command", "shell", "exec", "bash", "sh", "zsh",
	"run_script", "execute_script", "system", "eval", "terminal",
	"cmd", "powershell", "command_execution", "invoke_command",
}

func checkAT003ShellExec(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	nameLower := strings.ToLower(ev.Tool)
	for _, n := range shellToolNames {
		if nameLower == n || strings.HasSuffix(nameLower, "_"+n) || strings.HasPrefix(nameLower, n+"_") {
			return []rules.Finding{{
				RuleID:   "AT003",
				Name:     "Shell command executed",
				Severity: rules.SeverityCritical,
				Detail:   "Shell/exec tool '" + ev.Tool + "' was called.",
				Fix:      "Review immediately. Verify this was an explicitly authorized action by the user.",
				Mapping:  "OWASP LLM06, CWE-78, ATLAS AML.T0043",
			}}
		}
	}
	return nil
}

// ---- AT004: High volume data read -------------------------------------------
// OWASP LLM02 | CWE-200

const largeArgThreshold = 10000 // bytes across all args

func checkAT004HighVolumeDataRead(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall && ev.Event != logparse.EventResourceRead {
		return nil
	}
	total := 0
	for _, v := range ev.Args {
		total += len(v)
	}
	if total > largeArgThreshold {
		return []rules.Finding{{
			RuleID:   "AT004",
			Name:     "High volume data in tool args",
			Severity: rules.SeverityMedium,
			Detail:   "Tool call args are unusually large (" + itoa(total) + " bytes). May indicate bulk data being passed to an external tool.",
			Fix:      "Verify no large sensitive payload is being exfiltrated via tool arguments.",
			Mapping:  "OWASP LLM02, CWE-200",
		}}
	}
	return nil
}

// ---- AT005: Unusual hour activity -------------------------------------------
// OWASP LLM06

func checkAT005UnusualHourActivity(ev *logparse.Event) []rules.Finding {
	if ev.Timestamp.IsZero() {
		return nil
	}
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	hour := ev.Timestamp.Local().Hour()
	if hour < 6 || hour >= 23 {
		return []rules.Finding{{
			RuleID:   "AT005",
			Name:     "Agent activity outside business hours",
			Severity: rules.SeverityLow,
			Detail:   "Tool call by " + ev.Client + "/" + ev.Server + " at " + ev.Timestamp.Local().Format("15:04 MST") + " (outside 06:00-23:00 local).",
			Fix:      "Verify this agent session was expected at this time.",
			Mapping:  "OWASP LLM06",
		}}
	}
	return nil
}

// ---- AT006: Config file modified --------------------------------------------
// OWASP LLM06 | CWE-284 | ATLAS AML.T0048

var configFilePaths = []string{
	".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile",
	".bash_logout", ".zlogout",
	"/etc/profile", "/etc/bashrc", "/etc/environment",
	"sshd_config", "ssh_config", "sudoers",
	"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
	".gitconfig", ".git/config",
	"claude_desktop_config.json", ".cursor/mcp.json",
}

var configWriteTools = []string{
	"write_file", "edit_file", "append_file", "overwrite_file",
	"write_text", "save_file", "put_file",
}

func checkAT006ConfigFileModified(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	isWriteTool := false
	for _, n := range configWriteTools {
		if toolLower == n || strings.Contains(toolLower, n) {
			isWriteTool = true
			break
		}
	}
	if !isWriteTool {
		return nil
	}
	for _, arg := range ev.Args {
		lower := strings.ToLower(arg)
		for _, p := range configFilePaths {
			if strings.Contains(lower, strings.ToLower(p)) {
				return []rules.Finding{{
					RuleID:   "AT006",
					Name:     "Config file modified",
					Severity: rules.SeverityHigh,
					Detail:   "Write tool '" + ev.Tool + "' accessed a config file path: " + arg,
					Fix:      "Verify this modification was intended. Shell rc and SSH config writes may indicate persistence attempts.",
					Mapping:  "OWASP LLM06, CWE-284, ATLAS AML.T0048",
				}}
			}
		}
	}
	return nil
}

// ---- AT007: Cloud metadata endpoint access ----------------------------------
// OWASP LLM08 | CWE-918

var cloudMetadataIndicators = []string{
	"169.254.169.254",
	"metadata.google.internal",
	"169.254.170.2",
}

func checkAT007CloudMetadataAccess(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	for _, arg := range ev.Args {
		for _, ep := range cloudMetadataIndicators {
			if strings.Contains(arg, ep) {
				return []rules.Finding{{
					RuleID:   "AT007",
					Name:     "Cloud metadata endpoint access",
					Severity: rules.SeverityCritical,
					Detail:   "Tool '" + ev.Tool + "' was called with a cloud metadata endpoint URL: " + arg + ". This endpoint returns IAM credentials.",
					Fix:      "This is almost certainly malicious. Revoke cloud credentials immediately and investigate.",
					Mapping:  "OWASP LLM08, CWE-918",
				}}
			}
		}
	}
	return nil
}

// ---- AT008: Version control internal access ---------------------------------
// OWASP LLM02 | CWE-200

var vcsInternalPaths = []string{
	".git/config", ".git/hooks", ".git/ORIG_HEAD",
	".git/packed-refs", ".git/refs/",
	"COMMIT_EDITMSG", "FETCH_HEAD",
}

func checkAT008VCSInternalAccess(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall && ev.Event != logparse.EventResourceRead {
		return nil
	}
	for _, arg := range ev.Args {
		lower := strings.ToLower(arg)
		for _, p := range vcsInternalPaths {
			if strings.Contains(lower, strings.ToLower(p)) {
				return []rules.Finding{{
					RuleID:   "AT008",
					Name:     "VCS internal file access",
					Severity: rules.SeverityMedium,
					Detail:   "Tool arg accesses VCS internals: " + arg + ". Git config and hooks may contain credentials or be writable for persistence.",
					Fix:      "Verify this was expected. Writing to .git/hooks installs persistent code execution.",
					Mapping:  "OWASP LLM02, CWE-200",
				}}
			}
		}
	}
	return nil
}

// ---- AT009: Package manifest write ------------------------------------------
// OWASP LLM03 | CWE-829

var packageManifestFiles = []string{
	"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
	"requirements.txt", "Pipfile", "pyproject.toml",
	"Gemfile", "go.mod", "Cargo.toml", "composer.json", "pom.xml",
}

func checkAT009PackageManifestWrite(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	isWriteTool := false
	for _, n := range configWriteTools {
		if toolLower == n || strings.Contains(toolLower, n) {
			isWriteTool = true
			break
		}
	}
	if !isWriteTool {
		return nil
	}
	for _, arg := range ev.Args {
		lower := strings.ToLower(arg)
		for _, p := range packageManifestFiles {
			if strings.HasSuffix(lower, strings.ToLower(p)) || strings.Contains(lower, "/"+strings.ToLower(p)) {
				return []rules.Finding{{
					RuleID:   "AT009",
					Name:     "Package manifest modified",
					Severity: rules.SeverityHigh,
					Detail:   "Write tool '" + ev.Tool + "' modified a package manifest: " + arg + ". This can introduce malicious dependencies.",
					Fix:      "Review the diff immediately. Malicious dependency injection is a common supply chain attack vector.",
					Mapping:  "OWASP LLM03, ATLAS AML.T0010, CWE-829",
				}}
			}
		}
	}
	return nil
}

// ---- AT010: Browser or keychain access --------------------------------------
// OWASP LLM02 | CWE-522

var browserKeychainTools = []string{
	"get_cookies", "read_cookies", "list_cookies", "export_cookies",
	"get_browser_history", "browser_history",
	"get_saved_passwords", "keychain_get", "keychain_read",
	"get_credentials", "credential_manager",
}

var browserKeychainPaths = []string{
	"Library/Keychains", "login.keychain", "System.keychain",
	"Chrome/Default/Cookies", "Firefox/Profiles", "Safari/Databases",
	"Cookies.sqlite", "logins.json", "key4.db",
	"AppData\\Local\\Google\\Chrome",
}

func checkAT010BrowserOrKeychainAccess(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall && ev.Event != logparse.EventResourceRead {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	for _, n := range browserKeychainTools {
		if toolLower == n || strings.Contains(toolLower, n) {
			return []rules.Finding{{
				RuleID:   "AT010",
				Name:     "Browser or keychain access",
				Severity: rules.SeverityCritical,
				Detail:   "Tool '" + ev.Tool + "' accessed browser cookies, saved passwords, or OS keychain.",
				Fix:      "This is almost certainly malicious. Investigate immediately.",
				Mapping:  "OWASP LLM02, CWE-522",
			}}
		}
	}
	for _, arg := range ev.Args {
		lower := strings.ToLower(arg)
		for _, p := range browserKeychainPaths {
			if strings.Contains(lower, strings.ToLower(p)) {
				return []rules.Finding{{
					RuleID:   "AT010",
					Name:     "Browser or keychain path accessed",
					Severity: rules.SeverityCritical,
					Detail:   "Tool arg references a browser or keychain path: " + arg,
					Fix:      "This is almost certainly malicious. Investigate immediately.",
					Mapping:  "OWASP LLM02, CWE-522",
				}}
			}
		}
	}
	return nil
}

// ---- AT011: Error burst (repeated failures, possible probing) ---------------
// OWASP LLM06 | CWE-307

const (
	errorBurstWindow    = 60 * time.Second
	errorBurstThreshold = 5
)

func checkAT011ErrorBurst(ev *logparse.Event, state *SessionState) []rules.Finding {
	if ev.Event != logparse.EventError {
		return nil
	}
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	// Prune old entries.
	cutoff := now.Add(-errorBurstWindow)
	fresh := state.errorTimes[:0]
	for _, t := range state.errorTimes {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	state.errorTimes = append(fresh, now)
	if len(state.errorTimes) >= errorBurstThreshold {
		return []rules.Finding{{
			RuleID:   "AT011",
			Name:     "Error burst (repeated failures)",
			Severity: rules.SeverityMedium,
			Detail:   "Server '" + ev.Server + "' produced " + itoa(len(state.errorTimes)) + " errors in 60s. May indicate probing, permission scanning, or instability.",
			Fix:      "Investigate the error sequence. Consistent errors on sensitive operations may indicate access probing.",
			Mapping:  "OWASP LLM06, CWE-307",
		}}
	}
	return nil
}

// ---- AT012: Lateral movement (other user home directories) ------------------
// OWASP LLM02 | CWE-22

var otherUserPatterns = []*regexp.Regexp{
	lateralPattern(`/home/[^/]+/`),      // Linux other-user home
	lateralPattern(`/Users/[^/]+/`),     // macOS other-user home
	lateralPattern(`C:\\Users\\[^\\]+\\`), // Windows other-user home
}

func lateralPattern(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}

func checkAT012LateralMovement(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall && ev.Event != logparse.EventResourceRead {
		return nil
	}
	for _, arg := range ev.Args {
		for _, pat := range otherUserPatterns {
			if pat.MatchString(arg) {
				return []rules.Finding{{
					RuleID:   "AT012",
					Name:     "Lateral movement: other user directory",
					Severity: rules.SeverityHigh,
					Detail:   "Tool arg references another user's home directory: " + arg,
					Fix:      "Verify this cross-user access was intended and authorized.",
					Mapping:  "OWASP LLM02, CWE-22",
				}}
			}
		}
	}
	return nil
}

// ---- AT013: Mass file enumeration -------------------------------------------
// OWASP LLM02 | CWE-200

const (
	massEnumWindow     = 30 * time.Second
	massEnumThreshold  = 20
)

var enumToolNames = []string{
	"list_directory", "list_dir", "readdir", "ls", "find_files",
	"search_files", "glob", "list_files", "list_folder",
}

func checkAT013MassFileEnumeration(ev *logparse.Event, state *SessionState) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	isEnum := false
	for _, n := range enumToolNames {
		if toolLower == n || strings.Contains(toolLower, n) {
			isEnum = true
			break
		}
	}
	if !isEnum {
		return nil
	}
	state.readCount++
	if state.readCount == massEnumThreshold {
		return []rules.Finding{{
			RuleID:   "AT013",
			Name:     "Mass file enumeration",
			Severity: rules.SeverityMedium,
			Detail:   "Server '" + ev.Server + "' has called directory listing tools " + itoa(state.readCount) + "+ times in this session. May indicate reconnaissance.",
			Fix:      "Verify this enumeration was expected. Bulk filesystem traversal may indicate data exfiltration preparation.",
			Mapping:  "OWASP LLM02, CWE-200",
		}}
	}
	return nil
}

// ---- AT013 (continued): Persistence write ------------------------------------
// Reusing AT013 prefix -- separate function for clarity.

// ---- AT014: Persistence write -----------------------------------------------
// OWASP LLM06 | CWE-284 | ATLAS AML.T0048

var persistencePaths = []string{
	"crontab", "/etc/cron.", "/var/spool/cron",
	"LaunchAgents", "LaunchDaemons",
	"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
	"CurrentVersion\\Run",
	".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile",
	"/etc/profile.d/", "rc.local",
	"~/.config/autostart",
}

func checkAT013PersistenceWrite(ev *logparse.Event, _ *SessionState) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	isWriteTool := false
	for _, n := range configWriteTools {
		if toolLower == n || strings.Contains(toolLower, n) {
			isWriteTool = true
			break
		}
	}
	if !isWriteTool {
		return nil
	}
	for _, arg := range ev.Args {
		lower := strings.ToLower(arg)
		for _, p := range persistencePaths {
			if strings.Contains(lower, strings.ToLower(p)) {
				return []rules.Finding{{
					RuleID:   "AT014",
					Name:     "Persistence mechanism write",
					Severity: rules.SeverityCritical,
					Detail:   "Write to persistence location: " + arg + ". This installs code that survives reboot.",
					Fix:      "Investigate immediately. Unauthorized persistence installation is a critical indicator of compromise.",
					Mapping:  "OWASP LLM06, CWE-284, ATLAS AML.T0048",
				}}
			}
		}
	}
	return nil
}

// ---- AT014: Arbitrary code execution ----------------------------------------
// OWASP LLM06 | CWE-94

var evalToolNames = []string{
	"eval_code", "run_code", "execute_code", "code_interpreter",
	"python_eval", "js_eval", "run_python", "run_javascript",
	"repl", "sandbox_exec", "compile_and_run",
}

func checkAT014ArbitraryCodeExecution(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	for _, n := range evalToolNames {
		if toolLower == n || strings.Contains(toolLower, n) {
			return []rules.Finding{{
				RuleID:   "AT014",
				Name:     "Arbitrary code execution tool called",
				Severity: rules.SeverityCritical,
				Detail:   "Code interpreter/eval tool '" + ev.Tool + "' was called.",
				Fix:      "Review the code that was executed. Ensure the sandbox has no filesystem, network, or process access.",
				Mapping:  "OWASP LLM06, CWE-94",
			}}
		}
	}
	return nil
}

// ---- AT015: Cross-server data chain -----------------------------------------
// OWASP LLM02 | ATLAS AML.T0057

func checkAT015CrossServerDataChain(ev *logparse.Event, state *SessionState) []rules.Finding {
	if ev.Event != logparse.EventToolsCall && ev.Event != logparse.EventResourceRead {
		return nil
	}
	if ev.Server == "" {
		return nil
	}
	// Track which servers have had outbound network calls after reading data.
	isRead := ev.Event == logparse.EventResourceRead
	if !isRead {
		toolLower := strings.ToLower(ev.Tool)
		for _, n := range []string{"read_file", "read_", "get_file", "list_"} {
			if strings.HasPrefix(toolLower, n) {
				isRead = true
				break
			}
		}
	}
	if isRead {
		state.serverDataSeen[ev.Server] = true
		return nil
	}
	// This is a write/send/network call. If a different server has already read data, flag it.
	toolLower := strings.ToLower(ev.Tool)
	isOutbound := false
	for _, n := range networkToolNames {
		if strings.Contains(toolLower, n) {
			isOutbound = true
			break
		}
	}
	if !isOutbound {
		return nil
	}
	for server := range state.serverDataSeen {
		if server != ev.Server {
			return []rules.Finding{{
				RuleID:   "AT015",
				Name:     "Cross-server data chain",
				Severity: rules.SeverityMedium,
				Detail:   "Data was read from server '" + server + "' and a network call was subsequently made via server '" + ev.Server + "'. Possible data exfiltration chain.",
				Fix:      "Verify that data read from one server being sent via another is an intended workflow.",
				Mapping:  "OWASP LLM02, ATLAS AML.T0057",
			}}
		}
	}
	return nil
}

// ---- AT016: Environment variable dump ---------------------------------------
// OWASP LLM02 | CWE-214 | CWE-526

var envDumpToolNames = []string{
	"get_env", "read_env", "list_env", "dump_env", "get_environment",
	"read_environment", "env_dump", "getenv",
}

func checkAT016EnvVarDump(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	for _, n := range envDumpToolNames {
		if toolLower == n || strings.Contains(toolLower, n) {
			return []rules.Finding{{
				RuleID:   "AT016",
				Name:     "Environment variable access",
				Severity: rules.SeverityHigh,
				Detail:   "Tool '" + ev.Tool + "' accessed environment variables, which may contain API keys and credentials.",
				Fix:      "Verify this was expected. Env dumps are a common credential harvesting technique.",
				Mapping:  "OWASP LLM02, CWE-214, CWE-526",
			}}
		}
	}
	return nil
}

// ---- AT017: Database dump pattern -------------------------------------------
// OWASP LLM02 | CWE-89

var dbDumpToolNames = []string{
	"dump_database", "export_database", "db_dump", "backup_database",
	"export_table", "dump_table", "select_all",
}

func checkAT017DatabaseDump(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	for _, n := range dbDumpToolNames {
		if toolLower == n || strings.Contains(toolLower, n) {
			return []rules.Finding{{
				RuleID:   "AT017",
				Name:     "Database dump/export",
				Severity: rules.SeverityHigh,
				Detail:   "Tool '" + ev.Tool + "' performed a database dump or bulk export.",
				Fix:      "Verify this bulk export was explicitly requested and the data destination is authorized.",
				Mapping:  "OWASP LLM02, CWE-89",
			}}
		}
	}
	// Also flag raw SQL queries.
	for _, arg := range ev.Args {
		lower := strings.ToLower(arg)
		if (strings.Contains(lower, "select ") && strings.Contains(lower, " from ")) &&
			(strings.Contains(lower, "select *") || strings.Contains(lower, "select count")) {
			return []rules.Finding{{
				RuleID:   "AT017",
				Name:     "Bulk SQL query",
				Severity: rules.SeverityMedium,
				Detail:   "Tool '" + ev.Tool + "' was called with a bulk SELECT query in args.",
				Fix:      "Verify unbounded SQL queries are intended. Add LIMIT clauses to prevent unintended data extraction.",
				Mapping:  "OWASP LLM02, CWE-89",
			}}
		}
	}
	return nil
}

// ---- AT018: Network scanning ------------------------------------------------
// OWASP LLM08 | CWE-200

var networkScanToolNames = []string{
	"nmap", "port_scan", "network_scan", "ping_sweep", "arp_scan",
	"traceroute", "dig", "nslookup", "whois",
}

func checkAT018NetworkScan(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	for _, n := range networkScanToolNames {
		if toolLower == n || strings.Contains(toolLower, n) {
			return []rules.Finding{{
				RuleID:   "AT018",
				Name:     "Network scanning",
				Severity: rules.SeverityHigh,
				Detail:   "Tool '" + ev.Tool + "' performs network scanning or reconnaissance.",
				Fix:      "Network scanning tools should not be exposed via MCP. Remove this capability.",
				Mapping:  "OWASP LLM08, CWE-200",
			}}
		}
	}
	return nil
}

// ---- AT019: Clipboard read --------------------------------------------------
// OWASP LLM02 | CWE-359

var clipboardReadTools = []string{
	"read_clipboard", "get_clipboard", "clipboard_read", "get_pasteboard",
}

func checkAT019ClipboardRead(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	for _, n := range clipboardReadTools {
		if toolLower == n || strings.Contains(toolLower, n) {
			return []rules.Finding{{
				RuleID:   "AT019",
				Name:     "Clipboard read",
				Severity: rules.SeverityMedium,
				Detail:   "Tool '" + ev.Tool + "' read clipboard contents. Clipboards often contain passwords and tokens copied by the user.",
				Fix:      "Verify clipboard access was expected in this session.",
				Mapping:  "OWASP LLM02, CWE-359",
			}}
		}
	}
	return nil
}

// ---- AT020: Screen capture --------------------------------------------------
// OWASP LLM02 | CWE-359

var screenCaptureTools = []string{
	"screenshot", "capture_screen", "screen_capture", "take_screenshot",
	"record_screen", "capture_display",
}

func checkAT020ScreenCapture(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	toolLower := strings.ToLower(ev.Tool)
	for _, n := range screenCaptureTools {
		if toolLower == n || strings.Contains(toolLower, n) {
			return []rules.Finding{{
				RuleID:   "AT020",
				Name:     "Screen capture",
				Severity: rules.SeverityHigh,
				Detail:   "Tool '" + ev.Tool + "' captured screen contents.",
				Fix:      "Verify screen capture was explicitly requested. Screenshots can expose sensitive information visible on screen.",
				Mapping:  "OWASP LLM02, CWE-359",
			}}
		}
	}
	return nil
}

// ---- helpers -----------------------------------------------------------------

func itoa(n int) string {
	s := ""
	if n == 0 {
		return "0"
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
