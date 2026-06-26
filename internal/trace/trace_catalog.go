// Package trace — catalog evaluation for trace events.
// Rules AT021-AT100 use data-driven pattern matching on tool names and argument values.
package trace

import (
	"strings"

	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/rules"
)

// traceCatalogRule fires when ANY toolNames substring matches the tool name (case-insensitive),
// OR when ANY argPatterns substring is found in any argument value (case-insensitive).
type traceCatalogRule struct {
	ruleID      string
	name        string
	sev         rules.Severity
	fix         string
	mapping     string
	toolNames   []string // substring matches against tool name
	argPatterns []string // substring matches against any argument value
}

var traceCatalogRules = []traceCatalogRule{
	// ── Credential file access ──────────────────────────────────────────────

	// AT021: AWS credential file access
	{
		ruleID:  "AT021",
		name:    "AWS credential file accessed",
		sev:     rules.SeverityCritical,
		fix:     "Investigate immediately. AWS credentials in agent context enable full cloud account compromise.",
		mapping: "OWASP LLM02, ATLAS AML.T0057, CWE-522",
		argPatterns: []string{
			".aws/credentials", ".aws\\credentials",
			"aws_access_key_id", "aws_secret_access_key",
		},
	},
	// AT022: Kubernetes config access
	{
		ruleID:  "AT022",
		name:    "Kubernetes config file accessed",
		sev:     rules.SeverityCritical,
		fix:     "Investigate immediately. The kubeconfig grants cluster access to all agents and jobs.",
		mapping: "OWASP LLM02, ATLAS AML.T0057, CWE-522",
		argPatterns: []string{
			".kube/config", ".kube\\config", "kubeconfig",
		},
	},
	// AT023: Private key file access
	{
		ruleID:  "AT023",
		name:    "SSH or PGP private key file accessed",
		sev:     rules.SeverityCritical,
		fix:     "Investigate immediately. Private key exposure enables impersonation and lateral movement.",
		mapping: "OWASP LLM02, ATLAS AML.T0057, CWE-312",
		argPatterns: []string{
			"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
			".ssh/id_", ".ssh\\id_",
			"-----begin rsa private", "-----begin openssh private",
			"-----begin ec private", "-----begin private key",
		},
	},
	// AT024: Browser cookie / credential storage access
	{
		ruleID:  "AT024",
		name:    "Browser credential store or cookie database accessed",
		sev:     rules.SeverityCritical,
		fix:     "Investigate immediately. Browser credential stores contain passwords and session tokens for every saved site.",
		mapping: "OWASP LLM02, ATLAS AML.T0057, CWE-522",
		argPatterns: []string{
			"login data", "login keychain",
			"cookies.sqlite", "key4.db",
			"chrome/default/cookies",
			"chromium/default/cookies",
			"library/keychains",
		},
	},
	// AT025: Cloud service credentials in arguments
	{
		ruleID:  "AT025",
		name:    "Cloud or SaaS credential material in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Credential values must never appear in tool arguments. Rotate any exposed credentials immediately.",
		mapping: "OWASP LLM02, CWE-522",
		argPatterns: []string{
			"gcloud/application_default_credentials",
			".config/gcloud/credentials",
			"azure/accesstokens.json",
			"doctl/config.yaml",
			"heroku/credentials",
		},
	},

	// ── Reverse shell & code execution patterns ─────────────────────────────

	// AT026: Netcat reverse shell in arguments
	{
		ruleID:  "AT026",
		name:    "Netcat reverse shell pattern in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Terminate the session. A reverse shell was initiated from within the agent session.",
		mapping: "OWASP LLM06, ATLAS AML.T0043, CWE-78",
		argPatterns: []string{
			"nc -e ", "nc -l", "ncat -e ", "/dev/tcp/", "/dev/udp/",
			"bash -i >& /dev/tcp", "0>&1",
		},
	},
	// AT027: Python reverse shell
	{
		ruleID:  "AT027",
		name:    "Python reverse shell pattern in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Terminate the session. A Python reverse shell was initiated from within the agent session.",
		mapping: "OWASP LLM06, ATLAS AML.T0043, CWE-78",
		argPatterns: []string{
			"socket.connect", "subprocess.popen",
			"os.dup2", "pty.spawn",
			"import socket,subprocess",
		},
	},
	// AT028: Curl-pipe-to-shell pattern
	{
		ruleID:  "AT028",
		name:    "Curl-pipe-to-shell pattern in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Curl-piped-to-shell downloads and executes arbitrary remote code. Investigate immediately.",
		mapping: "OWASP LLM06, CWE-78",
		argPatterns: []string{
			"| sh", "| bash", "| zsh", "| python",
			"|sh", "|bash", "|zsh", "|python",
			"curl | ", "wget | ",
		},
	},
	// AT029: Base64-encoded command in arguments
	{
		ruleID:  "AT029",
		name:    "Base64-encoded command execution in tool arguments",
		sev:     rules.SeverityHigh,
		fix:     "Base64-encoded commands are a common obfuscation technique. Decode and inspect the payload.",
		mapping: "OWASP LLM06, CWE-78",
		argPatterns: []string{
			"base64 -d |", "base64 --decode |",
			"echo * | base64", "| base64 -d",
			"-encodedcommand ", "-enc ",
		},
	},
	// AT030: Eval of downloaded content
	{
		ruleID:  "AT030",
		name:    "Eval of remotely fetched content in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Evaluating downloaded content is a supply-chain attack vector. Investigate immediately.",
		mapping: "OWASP LLM06, CWE-94",
		argPatterns: []string{
			"eval $(curl", "eval $(wget", "eval `curl",
			"exec(requests.get", "exec(urllib",
		},
	},

	// ── Exfiltration patterns ────────────────────────────────────────────────

	// AT031: Cloud storage upload in tool arguments
	{
		ruleID:  "AT031",
		name:    "Cloud storage upload in tool arguments",
		sev:     rules.SeverityHigh,
		fix:     "An agent uploaded data to cloud storage. Verify the destination bucket and contents are authorised.",
		mapping: "OWASP LLM08, CWE-200",
		toolNames: []string{"s3_upload", "s3_put", "gcs_upload", "blob_upload", "upload_file", "cloud_upload"},
		argPatterns: []string{
			"s3://", "gs://", "az://",
		},
	},
	// AT032: External webhook POST in tool arguments
	{
		ruleID:  "AT032",
		name:    "Outbound webhook with external URL",
		sev:     rules.SeverityHigh,
		fix:     "Verify the webhook URL and payload are authorised. External webhooks can silently exfiltrate agent context.",
		mapping: "OWASP LLM08, CWE-918",
		toolNames: []string{"webhook_post", "post_webhook", "send_webhook", "trigger_webhook", "http_post_data"},
	},
	// AT033: Outbound email send
	{
		ruleID:  "AT033",
		name:    "Email sent by agent",
		sev:     rules.SeverityMedium,
		fix:     "Review the recipient and content of the email. Email sends can silently exfiltrate collected data.",
		mapping: "OWASP LLM08, CWE-200",
		toolNames: []string{"send_email", "email_send", "smtp_send", "mail_send", "send_mail"},
	},
	// AT034: Pastebin / gist creation
	{
		ruleID:  "AT034",
		name:    "Public paste or gist created by agent",
		sev:     rules.SeverityMedium,
		fix:     "Review the paste content. Public pastes are an exfiltration channel.",
		mapping: "OWASP LLM08, CWE-200",
		toolNames: []string{"paste_create", "pastebin_post", "create_paste", "gist_create", "create_gist"},
	},
	// AT035: FTP/SFTP upload
	{
		ruleID:  "AT035",
		name:    "FTP or SFTP file upload by agent",
		sev:     rules.SeverityHigh,
		fix:     "Review the destination host and file contents. FTP/SFTP uploads can exfiltrate sensitive files.",
		mapping: "OWASP LLM08, CWE-200",
		toolNames: []string{"ftp_upload", "sftp_upload", "ftp_put", "sftp_put"},
		argPatterns: []string{"ftp://", "sftp://"},
	},

	// ── Persistence writes ────────────────────────────────────────────────────

	// AT036: LaunchAgent / LaunchDaemon write
	{
		ruleID:  "AT036",
		name:    "LaunchAgent or LaunchDaemon property list write",
		sev:     rules.SeverityCritical,
		fix:     "A plist was written to a Launch* directory, establishing boot persistence. Investigate and remove if unauthorised.",
		mapping: "OWASP LLM06, ATLAS AML.T0048, CWE-284",
		argPatterns: []string{
			"library/launchagents/", "library/launchdaemons/",
			"Library/LaunchAgents/", "Library/LaunchDaemons/",
			"/launchagents/", "/launchdaemons/",
		},
	},
	// AT037: Windows registry Run key write
	{
		ruleID:  "AT037",
		name:    "Windows registry startup key write",
		sev:     rules.SeverityCritical,
		fix:     "A registry Run key write establishes persistence. Remove the entry and investigate.",
		mapping: "OWASP LLM06, ATLAS AML.T0048, CWE-284",
		argPatterns: []string{
			"hkcu\\software\\microsoft\\windows\\currentversion\\run",
			"hklm\\software\\microsoft\\windows\\currentversion\\run",
			"currentversion\\run",
		},
	},
	// AT038: Crontab write (file path)
	{
		ruleID:  "AT038",
		name:    "Crontab or cron.d file write",
		sev:     rules.SeverityCritical,
		fix:     "A crontab write establishes scheduled persistence. Review and remove if unauthorised.",
		mapping: "OWASP LLM06, ATLAS AML.T0048, CWE-284",
		argPatterns: []string{
			"/etc/cron", "/var/spool/cron",
			"crontab -", "/cron.d/",
		},
	},
	// AT039: Systemd unit file write
	{
		ruleID:  "AT039",
		name:    "Systemd unit file write",
		sev:     rules.SeverityCritical,
		fix:     "A systemd unit file write can establish persistent privileged execution. Investigate.",
		mapping: "OWASP LLM06, ATLAS AML.T0048, CWE-284",
		argPatterns: []string{
			"/etc/systemd/system/", "/usr/lib/systemd/", "/systemd/user/",
		},
	},
	// AT040: Shell init file write
	{
		ruleID:  "AT040",
		name:    "Shell initialisation file modification",
		sev:     rules.SeverityCritical,
		fix:     "Shell init file modifications run attacker code on every new shell. Investigate.",
		mapping: "OWASP LLM06, ATLAS AML.T0048, CWE-284",
		argPatterns: []string{
			"/.bashrc", "/.zshrc", "/.bash_profile", "/.profile", "/.zprofile",
			"/etc/profile", "/etc/bash.bashrc", "/etc/environment",
		},
	},

	// ── Privilege escalation ──────────────────────────────────────────────────

	// AT041: Sudo invocation with password
	{
		ruleID:  "AT041",
		name:    "Sudo invocation in tool arguments",
		sev:     rules.SeverityHigh,
		fix:     "Sudo commands elevate privilege and can bypass OS controls. Review whether the sudo call was expected.",
		mapping: "OWASP LLM06, CWE-272",
		argPatterns: []string{"sudo ", "sudo\t"},
	},
	// AT042: SUID/capability manipulation
	{
		ruleID:  "AT042",
		name:    "SUID or Linux capability manipulation in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Setting SUID bits or adding capabilities is a privilege escalation technique. Investigate.",
		mapping: "OWASP LLM06, CWE-272",
		argPatterns: []string{
			"chmod +s ", "chmod u+s", "setcap ", "cap_setuid",
		},
	},
	// AT043: Sudoers write
	{
		ruleID:  "AT043",
		name:    "Sudoers file modification in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "A sudoers write grants permanent root access. Investigate immediately.",
		mapping: "OWASP LLM06, CWE-272",
		argPatterns: []string{
			"/etc/sudoers", "/etc/sudoers.d/",
		},
	},

	// ── Defense evasion ──────────────────────────────────────────────────────

	// AT044: Log clearing
	{
		ruleID:  "AT044",
		name:    "Log clearing command in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Log clearing destroys evidence. Investigate what was hidden.",
		mapping: "OWASP LLM06, ATLAS AML.T0054, CWE-223",
		argPatterns: []string{
			"> /var/log/", "truncate -s 0 /var/log",
			"rm -rf /var/log", "clear-eventlog",
			"wevtutil cl ", "auditpol /clear",
		},
	},
	// AT045: Shell history manipulation
	{
		ruleID:  "AT045",
		name:    "Shell history deletion or manipulation in tool arguments",
		sev:     rules.SeverityHigh,
		fix:     "History deletion removes evidence of agent commands. Review surrounding events.",
		mapping: "OWASP LLM06, ATLAS AML.T0054, CWE-223",
		argPatterns: []string{
			"history -c", "unset histfile", "export histsize=0",
			"> ~/.bash_history", "rm ~/.bash_history",
			"> ~/.zsh_history", "rm ~/.zsh_history",
		},
	},
	// AT046: AV/EDR exclusion add
	{
		ruleID:  "AT046",
		name:    "Antivirus or EDR exclusion added in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Adding AV exclusions directly aids malware execution. Investigate immediately.",
		mapping: "OWASP LLM06, ATLAS AML.T0054",
		argPatterns: []string{
			"add-mppreference -exclusion", "exclusionpath",
			"exclusionprocess", "malwareprotection",
		},
	},
	// AT047: Timestomping
	{
		ruleID:  "AT047",
		name:    "File timestamp manipulation in tool arguments",
		sev:     rules.SeverityHigh,
		fix:     "Timestomping defeats forensic file-timeline analysis. Investigate.",
		mapping: "OWASP LLM06, ATLAS AML.T0054",
		argPatterns: []string{
			"touch -t ", "touch -d ", "--reference=", "touch -r ",
		},
	},

	// ── Infrastructure / cloud manipulation ──────────────────────────────────

	// AT048: IAM role/policy modification
	{
		ruleID:  "AT048",
		name:    "Cloud IAM modification by agent",
		sev:     rules.SeverityCritical,
		fix:     "IAM changes may grant persistent access. Review the change and revert if unauthorised.",
		mapping: "OWASP LLM06, ATLAS AML.T0043, CWE-272",
		toolNames: []string{"create_iam_role", "iam_create_role", "attach_iam_policy", "iam_policy_attach", "create_role_binding"},
	},
	// AT049: Cloud firewall/security group modification
	{
		ruleID:  "AT049",
		name:    "Cloud firewall or security group modification by agent",
		sev:     rules.SeverityCritical,
		fix:     "Firewall changes may expose internal services. Review and revert if unauthorised.",
		mapping: "OWASP LLM06, CWE-284",
		toolNames: []string{"add_security_group_rule", "security_group_authorize", "sg_ingress_add", "firewall_rule_add"},
	},
	// AT050: Cloud audit trail disable
	{
		ruleID:  "AT050",
		name:    "Cloud audit trail disabled by agent",
		sev:     rules.SeverityCritical,
		fix:     "Disabling CloudTrail destroys forensic evidence. Re-enable immediately and investigate.",
		mapping: "OWASP LLM06, ATLAS AML.T0054, CWE-223",
		toolNames: []string{"cloudtrail_disable", "disable_cloudtrail", "audit_trail_disable"},
	},

	// ── Container / orchestration ──────────────────────────────────────────────

	// AT051: Container exec
	{
		ruleID:  "AT051",
		name:    "Exec into running container",
		sev:     rules.SeverityCritical,
		fix:     "Container exec sessions can be used for lateral movement. Review the command executed.",
		mapping: "OWASP LLM06, ATLAS AML.T0043, CWE-78",
		toolNames: []string{"docker_exec", "container_exec", "kubectl_exec", "kube_exec", "k8s_exec"},
	},
	// AT052: Privileged container launch
	{
		ruleID:  "AT052",
		name:    "Privileged container launch detected",
		sev:     rules.SeverityCritical,
		fix:     "Privileged containers have full access to the host kernel. Investigate and remove the flag.",
		mapping: "OWASP LLM06, CWE-272",
		argPatterns: []string{
			"--privileged", "--pid=host", "--net=host", "--ipc=host",
			"--cap-add=all", "--cap-add sys_admin",
		},
	},
	// AT053: Kubernetes apply of privileged workload
	{
		ruleID:  "AT053",
		name:    "Kubernetes apply executed by agent",
		sev:     rules.SeverityHigh,
		fix:     "Review the manifest that was applied. kubectl apply can deploy persistent workloads.",
		mapping: "OWASP LLM06, ATLAS AML.T0043",
		toolNames: []string{"kubectl_apply", "k8s_apply", "kube_apply"},
	},

	// ── Sensitive tool category usage ─────────────────────────────────────────

	// AT054: Vault secret read
	{
		ruleID:  "AT054",
		name:    "Credential vault secret read by agent",
		sev:     rules.SeverityHigh,
		fix:     "Review the secret path read. Vault reads surface secrets in the LLM context window.",
		mapping: "OWASP LLM02, CWE-522",
		toolNames: []string{"vault_read", "vault_get", "vault_kv_get", "vault_lookup"},
	},
	// AT055: Private key material in arguments
	{
		ruleID:  "AT055",
		name:    "Private key material found in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Private key material in arguments will appear in logs. Rotate the key immediately.",
		mapping: "OWASP LLM02, CWE-312",
		argPatterns: []string{
			"-----begin rsa private key-----",
			"-----begin openssh private key-----",
			"-----begin ec private key-----",
			"-----begin private key-----",
			"-----begin pgp private key block-----",
		},
	},
	// AT056: MFA seed / TOTP secret in arguments
	{
		ruleID:  "AT056",
		name:    "MFA seed or TOTP secret in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "TOTP seeds appearing in agent arguments can permanently compromise MFA. Rotate the seed immediately.",
		mapping: "OWASP LLM02, CWE-312",
		argPatterns: []string{
			"otpauth://", "totp_secret", "mfa_seed",
		},
	},

	// ── Network attack patterns ────────────────────────────────────────────────

	// AT057: Port scanning in arguments
	{
		ruleID:  "AT057",
		name:    "Port scan command in tool arguments",
		sev:     rules.SeverityHigh,
		fix:     "Port scanning is reconnaissance. Investigate the target and scope.",
		mapping: "OWASP LLM06, ATLAS AML.T0057, CWE-200",
		argPatterns: []string{
			"nmap ", "-p 1-65535", "-p-", "masscan ", "zmap ",
		},
	},
	// AT058: Network packet injection
	{
		ruleID:  "AT058",
		name:    "Raw packet injection in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Raw packet injection is exclusively offensive. Investigate immediately.",
		mapping: "OWASP LLM06, CWE-918",
		argPatterns: []string{
			"scapy", "sendp(", "send(ip(", "raw_socket",
		},
	},
	// AT059: ARP spoofing
	{
		ruleID:  "AT059",
		name:    "ARP spoofing command in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "ARP spoofing enables on-path credential interception. Investigate immediately.",
		mapping: "OWASP LLM06, CWE-350",
		argPatterns: []string{
			"arpspoof", "arp -s ", "nemesis arp",
		},
	},

	// ── Obfuscation and staging ───────────────────────────────────────────────

	// AT060: Hex/octal-encoded shell command
	{
		ruleID:  "AT060",
		name:    "Hex or octal-encoded command in tool arguments",
		sev:     rules.SeverityHigh,
		fix:     "Encoded commands are used to evade detection. Decode and inspect the payload.",
		mapping: "OWASP LLM06, CWE-78",
		argPatterns: []string{
			"$'\\x", "\\x2f\\x62\\x69\\x6e", // /bin encoded
			"$(printf '\\", "echo -e '\\x",
		},
	},
	// AT061: IFS manipulation (obfuscation)
	{
		ruleID:  "AT061",
		name:    "IFS environment variable manipulation (shell obfuscation)",
		sev:     rules.SeverityHigh,
		fix:     "IFS manipulation is used to obfuscate shell commands. Inspect surrounding tool calls.",
		mapping: "OWASP LLM06, CWE-78",
		argPatterns: []string{
			"ifs=", "${ifs}", "$ifs",
		},
	},
	// AT062: Process memory dump
	{
		ruleID:  "AT062",
		name:    "Process memory dump command in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Memory dumps can extract secrets from running processes. Investigate the target process.",
		mapping: "OWASP LLM02, CWE-119",
		argPatterns: []string{
			"procdump", "mimikatz", "lsass.exe",
			"/proc/", "gcore ", "createdump",
		},
	},
	// AT063: Token stealing (Windows)
	{
		ruleID:  "AT063",
		name:    "Windows token stealing pattern in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Token impersonation enables privilege escalation without credentials. Investigate immediately.",
		mapping: "OWASP LLM06, ATLAS AML.T0057, CWE-272",
		argPatterns: []string{
			"impersonateloggedonuser", "duplicatetoken", "seimpersonateprivilege",
			"getsystem", "incognito",
		},
	},

	// ── Browser / application attacks ─────────────────────────────────────────

	// AT064: Browser saved password access tool
	{
		ruleID:  "AT064",
		name:    "Browser saved password access",
		sev:     rules.SeverityCritical,
		fix:     "Browser password store access exposes credentials for every saved site. Investigate.",
		mapping: "OWASP LLM02, CWE-522",
		toolNames: []string{"browser_saved_passwords", "get_saved_passwords", "browser_credential_dump"},
	},
	// AT065: SQL injection via raw query tool
	{
		ruleID:  "AT065",
		name:    "Potentially unsafe raw SQL execution",
		sev:     rules.SeverityHigh,
		fix:     "Raw SQL execution tools can be leveraged for SQL injection. Review the query for injection patterns.",
		mapping: "OWASP LLM06, CWE-89",
		toolNames: []string{"raw_sql", "execute_sql", "sql_exec", "execute_raw_sql"},
	},
	// AT066: Deserialization tool
	{
		ruleID:  "AT066",
		name:    "Unsafe deserialization tool called",
		sev:     rules.SeverityHigh,
		fix:     "Deserialising untrusted data can lead to remote code execution. Ensure input is from a trusted source.",
		mapping: "OWASP LLM06, CWE-502",
		toolNames: []string{"deserialize", "unserialize", "unpickle", "object_deserialize"},
		argPatterns: []string{
			"pickle.loads", "yaml.load(", "marshal.loads",
		},
	},

	// ── Cryptocurrency ────────────────────────────────────────────────────────

	// AT067: Crypto transfer initiated
	{
		ruleID:  "AT067",
		name:    "Cryptocurrency transfer initiated by agent",
		sev:     rules.SeverityCritical,
		fix:     "Agent-initiated fund transfers are an unacceptable financial risk without explicit human approval. Investigate.",
		mapping: "OWASP LLM06, CWE-284",
		toolNames: []string{"crypto_transfer", "send_crypto", "wallet_transfer", "eth_transfer", "btc_send", "token_transfer"},
	},
	// AT068: Wallet key or seed phrase in arguments
	{
		ruleID:  "AT068",
		name:    "Cryptocurrency wallet seed phrase or private key in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Wallet seed phrases in arguments enable total fund loss. Rotate the wallet immediately.",
		mapping: "OWASP LLM02, CWE-312",
		argPatterns: []string{
			"mnemonic", "seed phrase", "xprv", "wallet import format",
		},
	},

	// ── Sensitive data patterns in arguments ──────────────────────────────────

	// AT069: High-entropy string (potential credential) in arguments
	{
		ruleID:  "AT069",
		name:    "AWS access key pattern in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "An AWS access key ID was found in tool arguments. If this is real, rotate it immediately.",
		mapping: "OWASP LLM02, CWE-522",
		argPatterns: []string{
			"akia", "asia", "aida", "aroa", "aipa", // AWS key ID prefixes
		},
	},
	// AT070: GitHub token in arguments
	{
		ruleID:  "AT070",
		name:    "GitHub personal access token in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "A GitHub token found in tool arguments will appear in logs. Rotate it immediately.",
		mapping: "OWASP LLM02, CWE-522",
		argPatterns: []string{
			"ghp_", "gho_", "ghu_", "ghs_", "ghr_",
		},
	},

	// ── Recon patterns ────────────────────────────────────────────────────────

	// AT071: Domain recon tool
	{
		ruleID:  "AT071",
		name:    "Domain or Active Directory recon by agent",
		sev:     rules.SeverityHigh,
		fix:     "Review the scope of the domain recon. AD enumeration provides a complete attack map.",
		mapping: "OWASP LLM02, ATLAS AML.T0057",
		toolNames: []string{"enumerate_domain", "domain_enumerate", "ldap_query", "ad_query", "active_directory_search"},
	},
	// AT072: Cloud resource enumeration
	{
		ruleID:  "AT072",
		name:    "Cloud resource enumeration by agent",
		sev:     rules.SeverityHigh,
		fix:     "Cloud resource enumeration reveals infrastructure for targeting. Investigate the scope.",
		mapping: "OWASP LLM02, ATLAS AML.T0057",
		toolNames: []string{"aws_enumerate", "cloud_enumerate", "aws_list_accounts", "gcp_enumerate", "azure_enumerate"},
	},
	// AT073: Arp/network discovery
	{
		ruleID:  "AT073",
		name:    "Local network discovery in tool arguments",
		sev:     rules.SeverityMedium,
		fix:     "Network discovery reveals internal hosts for targeting. Investigate whether this was intended.",
		mapping: "OWASP LLM02, ATLAS AML.T0057",
		argPatterns: []string{
			"arp -a", "arp-scan", "netdiscover", "fping -a",
		},
	},

	// ── Package / supply chain ─────────────────────────────────────────────────

	// AT074: Package install invoked
	{
		ruleID:  "AT074",
		name:    "Package manager install executed by agent",
		sev:     rules.SeverityHigh,
		fix:     "Package installs run arbitrary post-install scripts. Verify the package name and source.",
		mapping: "OWASP LLM06, CWE-829",
		toolNames: []string{"pip_install", "npm_install", "gem_install", "brew_install", "apt_install", "cargo_install"},
	},
	// AT075: Dependency confusion pattern in package install
	{
		ruleID:  "AT075",
		name:    "Potential dependency confusion in package install arguments",
		sev:     rules.SeverityHigh,
		fix:     "Packages with internal-looking names installed from public registries may be dependency confusion attacks.",
		mapping: "OWASP LLM06, CWE-829",
		argPatterns: []string{
			"--index-url https://pypi", "--extra-index-url",
			"--registry https://registry.npmjs",
		},
	},
	// AT076: Build system hook modification
	{
		ruleID:  "AT076",
		name:    "Build system hook or script modification in tool arguments",
		sev:     rules.SeverityHigh,
		fix:     "Modifying build hooks can inject code into every future build. Investigate.",
		mapping: "OWASP LLM06, CWE-829",
		argPatterns: []string{
			"postinstall", "preinstall", "postbuild",
			".githooks/", ".git/hooks/",
		},
	},

	// ── Additional detection ───────────────────────────────────────────────────

	// AT077: Tor / onion access
	{
		ruleID:  "AT077",
		name:    "Tor or onion address in tool arguments",
		sev:     rules.SeverityHigh,
		fix:     "Tor access in an agent session may indicate C2 communication. Investigate.",
		mapping: "OWASP LLM06, CWE-918",
		argPatterns: []string{".onion", "torproject.org", "tor2web"},
	},
	// AT078: Cryptocurrency mining pool
	{
		ruleID:  "AT078",
		name:    "Cryptocurrency mining pool address in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Mining pool references indicate cryptomining malware. Investigate immediately.",
		mapping: "OWASP LLM06",
		argPatterns: []string{
			"pool.minergate", "xmr.pool", "stratum+tcp://", "pool.supportxmr",
		},
	},
	// AT079: Encoded PowerShell execution
	{
		ruleID:  "AT079",
		name:    "Encoded PowerShell command in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Encoded PowerShell is the most common Windows malware delivery technique. Decode and inspect.",
		mapping: "OWASP LLM06, CWE-78",
		argPatterns: []string{
			"powershell -enc", "powershell -e ", "powershell.exe -enc",
			"powershell -nop ", "powershell -w hidden",
		},
	},
	// AT080: Kernel module load
	{
		ruleID:  "AT080",
		name:    "Kernel module load command in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Loading kernel modules grants ring-0 access. Investigate immediately.",
		mapping: "OWASP LLM06, CWE-272",
		argPatterns: []string{
			"insmod ", "modprobe ", "kldload ",
		},
	},

	// AT081: Lateral movement tool usage
	{
		ruleID:  "AT081",
		name:    "Lateral movement tool invocation in arguments",
		sev:     rules.SeverityCritical,
		fix:     "Lateral movement tools indicate active post-exploitation. Investigate immediately.",
		mapping: "OWASP LLM06, ATLAS AML.T0043, CWE-78",
		argPatterns: []string{
			"wmiexec", "psexec", "impacket", "crackmapexec",
			"pass-the-hash", "pass-the-ticket",
		},
	},
	// AT082: Shadow copy deletion
	{
		ruleID:  "AT082",
		name:    "Shadow copy deletion command in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Shadow copy deletion is a ransomware hallmark. Investigate immediately.",
		mapping: "OWASP LLM06, ATLAS AML.T0054",
		argPatterns: []string{
			"vssadmin delete shadows", "wmic shadowcopy delete",
			"bcdedit /set {default}", "wbadmin delete catalog",
		},
	},
	// AT083: C2 framework tool
	{
		ruleID:  "AT083",
		name:    "Known C2 framework reference in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "C2 framework references indicate active attacker presence. Terminate and isolate the system.",
		mapping: "OWASP LLM06, ATLAS AML.T0048",
		argPatterns: []string{
			"cobalt strike", "cobaltstrike", "metasploit", "msfvenom",
			"meterpreter", "empire", "sliver", "havoc",
		},
	},
	// AT084: Rootkit tool reference
	{
		ruleID:  "AT084",
		name:    "Rootkit tool reference in tool arguments",
		sev:     rules.SeverityCritical,
		fix:     "Rootkit references indicate kernel-level compromise. Assume full system compromise and re-image.",
		mapping: "OWASP LLM06, ATLAS AML.T0048",
		argPatterns: []string{
			"rootkit", "azazel", "jynxkit", "adore-ng",
		},
	},
	// AT085: NTFS alternate data stream usage
	{
		ruleID:  "AT085",
		name:    "NTFS alternate data stream usage in tool arguments",
		sev:     rules.SeverityHigh,
		fix:     "NTFS ADS can hide files and executable code from standard directory listings.",
		mapping: "OWASP LLM06, ATLAS AML.T0054",
		argPatterns: []string{":$data", "type nul > "},
	},
}

// EvalEventCatalog runs catalog-level rules against a single trace event.
func EvalEventCatalog(ev *logparse.Event) []rules.Finding {
	if ev.Event != logparse.EventToolsCall {
		return nil
	}
	var f []rules.Finding
	nameLower := strings.ToLower(ev.Tool)

	// Collect all argument values for pattern matching.
	var allArgs strings.Builder
	for _, v := range ev.Args {
		allArgs.WriteString(strings.ToLower(v))
		allArgs.WriteByte('\n')
	}
	argsStr := allArgs.String()

	for _, rule := range traceCatalogRules {
		var matched bool
		detail := ""

		for _, pat := range rule.toolNames {
			if strings.Contains(nameLower, pat) {
				detail = "Tool '" + ev.Tool + "' matches catalog pattern '" + pat + "'."
				matched = true
				break
			}
		}
		if !matched {
			for _, pat := range rule.argPatterns {
				if strings.Contains(argsStr, strings.ToLower(pat)) {
					detail = "Tool '" + ev.Tool + "' arguments contain pattern '" + pat + "'."
					matched = true
					break
				}
			}
		}
		if matched {
			f = append(f, rules.Finding{
				RuleID:   rule.ruleID,
				Name:     rule.name,
				Severity: rule.sev,
				Detail:   detail,
				Fix:      rule.fix,
				Mapping:  rule.mapping,
			})
		}
	}
	return f
}
