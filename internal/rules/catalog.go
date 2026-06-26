// Package rules — catalog evaluation functions for tools, resources, and prompts.
// Rules MCP027+ use a data-driven pattern-match approach: tool name, description, and
// input schema are each matched against lists of known-dangerous substrings.
package rules

import (
	"strings"

	"github.com/aspex-security/aspex/internal/mcpclient"
)

// toolCatalogRule fires when ANY toolNames substring matches the tool name (case-insensitive),
// OR when ANY descWords substring matches the description. A single rule cannot fire twice.
type toolCatalogRule struct {
	ruleID    string
	name      string
	sev       Severity
	fix       string
	mapping   string
	toolNames []string // match any as substring in lowercase tool name
	descWords []string // match any as substring in lowercase description
	schemaKeys []string // match any as substring in JSON-serialised input schema
}

// resourceCatalogRule fires when ANY uriWords substring matches the resource URI,
// or ANY mimeTypes substring matches the MIME type.
type resourceCatalogRule struct {
	ruleID    string
	name      string
	sev       Severity
	fix       string
	mapping   string
	uriWords  []string
	mimeTypes []string
}

// promptCatalogRule fires when ANY descWords substring matches the prompt description,
// or ANY nameWords substring matches the prompt name,
// or the description length >= minLen (0 = disabled).
type promptCatalogRule struct {
	ruleID    string
	name      string
	sev       Severity
	fix       string
	mapping   string
	descWords []string
	nameWords []string
	minLen    int
}

// ─── Tool catalog ─────────────────────────────────────────────────────────────

var toolCatalogRules = []toolCatalogRule{
	// MCP027: Container execution (docker/podman/lxc)
	{
		ruleID:    "MCP027",
		name:      "Container execution capability",
		sev:       SeverityCritical,
		fix:       "Remove container exec tools unless this server is purpose-built for container management and is strictly scoped.",
		mapping:   "OWASP LLM06, ATLAS AML.T0043, CWE-78",
		toolNames: []string{"docker_exec", "container_exec", "exec_container", "exec_in_container", "docker_run", "podman_exec", "podman_run", "lxc_exec", "lxc_start", "nspawn_exec"},
	},
	// MCP028: Kubernetes / orchestration execution
	{
		ruleID:    "MCP028",
		name:      "Kubernetes execution capability",
		sev:       SeverityCritical,
		fix:       "Remove kubectl exec / apply tools unless this server is purpose-built for cluster management.",
		mapping:   "OWASP LLM06, ATLAS AML.T0043, CWE-78",
		toolNames: []string{"kubectl_exec", "kube_exec", "k8s_exec", "pod_exec", "kubectl_apply", "k8s_apply", "kube_apply", "k8s_deploy", "helm_upgrade", "helm_install", "helm_deploy"},
	},
	// MCP029: Configuration management execution
	{
		ruleID:    "MCP029",
		name:      "Configuration management execution capability",
		sev:       SeverityHigh,
		fix:       "Restrict this tool to a read-only audit role or remove it. Config management tools can modify every host in an inventory.",
		mapping:   "OWASP LLM06, CWE-78",
		toolNames: []string{"ansible_run", "ansible_playbook", "run_playbook", "ansible_exec", "puppet_apply", "chef_run", "salt_cmd", "salt_exec", "cfengine_exec"},
	},
	// MCP030: Infrastructure-as-code destructive operations
	{
		ruleID:    "MCP030",
		name:      "IaC destructive operation (apply/destroy)",
		sev:       SeverityHigh,
		fix:       "Require explicit human approval before calling apply or destroy operations. Restrict to non-production environments.",
		mapping:   "OWASP LLM06, ATLAS AML.T0043",
		toolNames: []string{"terraform_apply", "terraform_destroy", "tf_apply", "tf_destroy", "pulumi_up", "pulumi_destroy", "cdk_deploy", "cdk_destroy"},
	},
	// MCP031: Container image build/push
	{
		ruleID:    "MCP031",
		name:      "Container image build or push capability",
		sev:       SeverityMedium,
		fix:       "Ensure image builds cannot include injected commands and pushes target only authorised registries.",
		mapping:   "OWASP LLM06, CWE-829",
		toolNames: []string{"docker_build", "build_docker_image", "build_image", "image_build", "image_push", "docker_push", "podman_build", "podman_push", "container_registry_push", "push_to_ecr", "ecr_push", "gcr_push"},
	},
	// MCP032: Package manager execution
	{
		ruleID:    "MCP032",
		name:      "Package manager execution capability",
		sev:       SeverityHigh,
		fix:       "Package manager install tools can run arbitrary post-install scripts. Remove or strictly scope to a vetted allow-list.",
		mapping:   "OWASP LLM06, CWE-829",
		toolNames: []string{"pip_install", "pip_exec", "npm_install", "npm_exec", "yarn_add", "yarn_exec", "gem_install", "bundle_exec", "brew_install", "apt_install", "apt_get_install", "yum_install", "dnf_install", "cargo_install", "go_install", "pnpm_exec", "pnpm_install", "composer_install"},
	},
	// MCP033: Build system execution
	{
		ruleID:    "MCP033",
		name:      "Build system execution capability",
		sev:       SeverityMedium,
		fix:       "Build scripts can contain arbitrary shell commands. Ensure the build root is not writable by untrusted code.",
		mapping:   "OWASP LLM06, CWE-78",
		toolNames: []string{"make_exec", "run_make", "gradle_exec", "mvn_exec", "maven_exec", "gradle_run", "cmake_exec", "bazel_run", "sbt_run", "mix_run", "lein_run"},
	},
	// MCP034: Additional language REPL/eval
	{
		ruleID:    "MCP034",
		name:      "Language REPL or eval capability",
		sev:       SeverityCritical,
		fix:       "Arbitrary code execution via a language REPL is a complete sandbox escape. Remove unless this is a sandboxed code-execution service.",
		mapping:   "OWASP LLM06, CWE-94",
		toolNames: []string{"ruby_eval", "ruby_exec", "perl_eval", "php_eval", "lua_eval", "groovy_eval", "kotlin_eval", "scala_eval", "r_eval", "julia_eval", "swift_eval", "elixir_eval", "haskell_eval", "clojure_eval"},
	},
	// MCP035: Credential vault access
	{
		ruleID:    "MCP035",
		name:      "Credential vault access capability",
		sev:       SeverityCritical,
		fix:       "Vault read tools expose secrets to the LLM context. Limit to the minimum required secret paths and log every access.",
		mapping:   "OWASP LLM02, ATLAS AML.T0057, CWE-522",
		toolNames: []string{"vault_read", "vault_get", "vault_lookup", "vault_kv_get", "vault_secret", "hashicorp_vault_read"},
	},
	// MCP036: Password / generic secret retrieval
	{
		ruleID:    "MCP036",
		name:      "Password or secret retrieval capability",
		sev:       SeverityCritical,
		fix:       "Tools that return plaintext passwords or secrets expose them to the LLM context window. Remove or replace with a scoped token exchange.",
		mapping:   "OWASP LLM02, CWE-522",
		toolNames: []string{"get_password", "password_get", "fetch_password", "password_read", "get_secret", "fetch_secret", "secret_fetch", "secret_retrieve", "secret_read"},
	},
	// MCP037: API key / auth token extraction
	{
		ruleID:    "MCP037",
		name:      "API key or auth token extraction capability",
		sev:       SeverityCritical,
		fix:       "Remove or replace with a scoped credential-vending approach that does not return the raw token value.",
		mapping:   "OWASP LLM02, CWE-522",
		toolNames: []string{"get_api_key", "list_api_keys", "api_key_get", "get_auth_token", "auth_token_get", "get_bearer_token", "bearer_token_get", "get_access_token", "access_token_fetch"},
	},
	// MCP038: Private key access
	{
		ruleID:    "MCP038",
		name:      "Private key access capability",
		sev:       SeverityCritical,
		fix:       "Private keys must never pass through an LLM context. Remove this tool entirely.",
		mapping:   "OWASP LLM02, CWE-321, CWE-522",
		toolNames: []string{"get_private_key", "private_key_get", "export_private_key", "get_pgp_key", "pgp_key_export", "gpg_export", "gpg_key_get", "get_pgp_private", "read_private_key"},
	},
	// MCP039: SSH key access
	{
		ruleID:    "MCP039",
		name:      "SSH key access capability",
		sev:       SeverityCritical,
		fix:       "SSH private keys must never appear in LLM context. Remove this tool and use an SSH agent instead.",
		mapping:   "OWASP LLM02, CWE-312, CWE-522",
		toolNames: []string{"get_ssh_key", "ssh_key_get", "read_ssh_key", "export_ssh_key", "ssh_key_read", "ssh_private_key"},
	},
	// MCP040: OAuth / service account credentials
	{
		ruleID:    "MCP040",
		name:      "OAuth token or service account key extraction",
		sev:       SeverityCritical,
		fix:       "OAuth tokens and service account keys in the LLM context can be exfiltrated. Remove or scope to short-lived tokens with minimal permissions.",
		mapping:   "OWASP LLM02, CWE-522",
		toolNames: []string{"get_oauth_token", "oauth_token_get", "get_service_account_key", "service_account_credentials", "get_refresh_token", "refresh_token_get", "get_id_token", "generate_id_token_for", "impersonate_service_account"},
	},
	// MCP041: Keystore / certificate export
	{
		ruleID:    "MCP041",
		name:      "Keystore or certificate export capability",
		sev:       SeverityHigh,
		fix:       "Keystores and private certificates must not pass through an LLM. Remove or replace with a dedicated HSM integration.",
		mapping:   "OWASP LLM02, CWE-312",
		toolNames: []string{"read_keystore", "keystore_get", "cert_export", "get_certificate", "export_certificate", "keystore_export", "export_cert"},
	},
	// MCP042: Email send (exfiltration vector)
	{
		ruleID:    "MCP042",
		name:      "Email send capability",
		sev:       SeverityHigh,
		fix:       "Email send tools can be used to exfiltrate data the agent has collected. Restrict recipients to a hard-coded allow-list.",
		mapping:   "OWASP LLM08, CWE-200",
		toolNames: []string{"send_email", "email_send", "smtp_send", "mail_send", "send_mail", "compose_email", "email_message_create"},
	},
	// MCP043: Chat platform message send
	{
		ruleID:    "MCP043",
		name:      "Chat platform message send capability",
		sev:       SeverityMedium,
		fix:       "Chat send tools can exfiltrate data. Restrict to authorised channels and add per-message content review if possible.",
		mapping:   "OWASP LLM08, CWE-200",
		toolNames: []string{"slack_send_message", "slack_post_message", "discord_send", "discord_post", "teams_send", "teams_post", "send_teams_message", "telegram_send", "signal_send"},
	},
	// MCP044: Outbound webhook / HTTP POST
	{
		ruleID:    "MCP044",
		name:      "Outbound webhook or arbitrary HTTP POST capability",
		sev:       SeverityHigh,
		fix:       "Outbound HTTP POST with caller-controlled body and URL is a general exfiltration primitive. Restrict URL to an explicit allow-list.",
		mapping:   "OWASP LLM08, CWE-918",
		toolNames: []string{"webhook_post", "post_webhook", "send_webhook", "trigger_webhook", "webhook_send", "http_post_data", "post_to_url"},
	},
	// MCP045: Cloud storage upload
	{
		ruleID:    "MCP045",
		name:      "Cloud storage upload capability",
		sev:       SeverityHigh,
		fix:       "Cloud upload tools can exfiltrate local files to attacker-controlled buckets. Restrict destination bucket/prefix via configuration.",
		mapping:   "OWASP LLM08, CWE-200",
		toolNames: []string{"s3_upload", "put_s3_object", "s3_put", "gcs_upload", "azure_upload", "blob_upload", "upload_to_cloud", "cloud_upload", "upload_to_s3", "s3_put_object"},
	},
	// MCP046: File upload / share link
	{
		ruleID:    "MCP046",
		name:      "File upload or share link generation capability",
		sev:       SeverityHigh,
		fix:       "File upload and share tools can exfiltrate arbitrary local files. Scope to allowed directories and require explicit confirmation.",
		mapping:   "OWASP LLM08, CWE-200",
		toolNames: []string{"upload_file", "file_upload", "create_share_link", "generate_share", "share_file", "ftp_upload", "sftp_upload", "scp_upload", "rclone_copy", "rsync_push"},
	},
	// MCP047: Pastebin / gist creation
	{
		ruleID:    "MCP047",
		name:      "Paste or gist creation capability",
		sev:       SeverityMedium,
		fix:       "Paste creation tools can silently exfiltrate data to public or semi-public URLs. Limit to private pastes with expiry.",
		mapping:   "OWASP LLM08, CWE-200",
		toolNames: []string{"paste_create", "pastebin_post", "create_paste", "gist_create", "create_gist"},
	},
	// MCP048: Audio / microphone capture
	{
		ruleID:    "MCP048",
		name:      "Audio or microphone capture capability",
		sev:       SeverityHigh,
		fix:       "Remove audio capture tools. Recording ambient audio without user consent is a serious privacy violation.",
		mapping:   "OWASP LLM02, CWE-359",
		toolNames: []string{"record_audio", "audio_record", "microphone_capture", "microphone_record", "capture_audio", "listen_mic", "ambient_listen"},
	},
	// MCP049: Camera / video capture
	{
		ruleID:    "MCP049",
		name:      "Camera or video capture capability",
		sev:       SeverityHigh,
		fix:       "Remove camera capture tools. Video recording without user consent is a serious privacy violation.",
		mapping:   "OWASP LLM02, CWE-359",
		toolNames: []string{"camera_capture", "capture_camera", "webcam_capture", "webcam_record", "video_capture", "record_video", "camera_record"},
	},
	// MCP050: Keystroke / input capture
	{
		ruleID:    "MCP050",
		name:      "Keystroke or input capture capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool entirely. Keystroke logging is spyware.",
		mapping:   "OWASP LLM02, ATLAS AML.T0057, CWE-359",
		toolNames: []string{"keylog", "keystroke_log", "keyboard_capture", "input_capture", "keylogger", "record_keystrokes", "capture_input"},
	},
	// MCP051: Window / UI enumeration
	{
		ruleID:    "MCP051",
		name:      "Window or UI enumeration capability",
		sev:       SeverityMedium,
		fix:       "Window enumeration exposes application context to the agent. Remove unless essential to the tool's stated purpose.",
		mapping:   "OWASP LLM02, CWE-359",
		toolNames: []string{"get_active_window", "list_windows", "enumerate_windows", "window_title_get", "get_window_list"},
	},
	// MCP052: Location / GPS tracking
	{
		ruleID:    "MCP052",
		name:      "Location or GPS tracking capability",
		sev:       SeverityHigh,
		fix:       "Remove location tracking tools unless the server's sole purpose is navigation or mapping with explicit user consent.",
		mapping:   "OWASP LLM02, CWE-359",
		toolNames: []string{"get_location", "location_get", "gps_read", "location_track", "track_location", "get_gps"},
	},
	// MCP053: Wireless / Bluetooth device scan
	{
		ruleID:    "MCP053",
		name:      "Wireless or Bluetooth device scan capability",
		sev:       SeverityMedium,
		fix:       "Wireless scanning can fingerprint nearby devices and expose physical location. Remove unless the server explicitly requires it.",
		mapping:   "OWASP LLM02, CWE-359",
		toolNames: []string{"bluetooth_scan", "ble_scan", "wifi_scan", "network_device_scan", "device_discover"},
	},
	// MCP054: User / account enumeration
	{
		ruleID:    "MCP054",
		name:      "User or account enumeration capability",
		sev:       SeverityMedium,
		fix:       "User enumeration aids privilege escalation and targeted attacks. Scope this tool to read-only with minimal returned fields.",
		mapping:   "OWASP LLM02, CWE-200",
		toolNames: []string{"enumerate_users", "user_enumerate", "list_local_users", "list_domain_users", "get_user_list", "ldap_query_users", "ad_user_list"},
	},
	// MCP055: Domain / Active Directory reconnaissance
	{
		ruleID:    "MCP055",
		name:      "Domain or Active Directory reconnaissance capability",
		sev:       SeverityHigh,
		fix:       "AD/LDAP recon tools provide a complete map of the org for attackers. Remove or restrict to a read-only service account with minimal scope.",
		mapping:   "OWASP LLM02, ATLAS AML.T0057, CWE-200",
		toolNames: []string{"enumerate_domain", "domain_enumerate", "ldap_query", "ad_query", "active_directory_search", "get_domain_info"},
	},
	// MCP056: Cloud account enumeration
	{
		ruleID:    "MCP056",
		name:      "Cloud account or resource enumeration capability",
		sev:       SeverityHigh,
		fix:       "Cloud account recon exposes your entire infrastructure surface. Restrict to the minimum required read permissions.",
		mapping:   "OWASP LLM02, ATLAS AML.T0057, CWE-200",
		toolNames: []string{"aws_list_accounts", "aws_enumerate", "list_aws_resources", "gcp_enumerate", "azure_enumerate", "cloud_enumerate", "list_cloud_resources"},
	},
	// MCP057: IAM role / policy modification
	{
		ruleID:    "MCP057",
		name:      "IAM role or policy modification capability",
		sev:       SeverityCritical,
		fix:       "IAM modification is an immediate privilege-escalation risk. Remove and use a separate out-of-band provisioning process.",
		mapping:   "OWASP LLM06, ATLAS AML.T0043, CWE-272",
		toolNames: []string{"create_iam_role", "iam_create_role", "attach_iam_policy", "iam_policy_attach", "create_role_binding", "iam_modify", "iam_create_policy", "add_iam_binding"},
	},
	// MCP058: Security group / firewall modification
	{
		ruleID:    "MCP058",
		name:      "Security group or firewall rule modification capability",
		sev:       SeverityCritical,
		fix:       "Firewall modification can expose internal services to the internet. Remove or require explicit change-management approval.",
		mapping:   "OWASP LLM06, CWE-284",
		toolNames: []string{"add_security_group_rule", "security_group_authorize", "sg_ingress_add", "firewall_rule_add", "add_firewall_rule", "network_acl_add", "sg_rule_create"},
	},
	// MCP059: Cloud compute provisioning
	{
		ruleID:    "MCP059",
		name:      "Cloud compute instance provisioning capability",
		sev:       SeverityHigh,
		fix:       "Agent-initiated compute provisioning can incur cost and create resources outside of security controls. Restrict to dev environments.",
		mapping:   "OWASP LLM06, ATLAS AML.T0043",
		toolNames: []string{"create_ec2_instance", "ec2_run_instance", "vm_create", "vm_provision", "create_vm", "launch_instance", "gce_create", "azure_vm_create"},
	},
	// MCP060: Cloud storage bucket policy modification
	{
		ruleID:    "MCP060",
		name:      "Cloud storage bucket policy modification capability",
		sev:       SeverityCritical,
		fix:       "Making S3/GCS buckets public is a leading cause of data breaches. Remove or hard-code deny for public-read ACLs.",
		mapping:   "OWASP LLM06, CWE-732",
		toolNames: []string{"set_bucket_policy", "bucket_policy_put", "s3_put_bucket_policy", "make_public", "bucket_acl_set", "bucket_make_public"},
	},
	// MCP061: DNS record modification
	{
		ruleID:    "MCP061",
		name:      "DNS record modification capability",
		sev:       SeverityHigh,
		fix:       "DNS modification enables subdomain takeover and traffic hijacking. Restrict to a dedicated subdomain zone and require review.",
		mapping:   "OWASP LLM06, CWE-350",
		toolNames: []string{"dns_record_create", "create_dns_record", "route53_create_record", "dns_add", "add_dns_record", "cloudflare_create_record", "dns_record_upsert"},
	},
	// MCP062: Serverless function deployment
	{
		ruleID:    "MCP062",
		name:      "Serverless function deployment capability",
		sev:       SeverityHigh,
		fix:       "Deploying arbitrary code to serverless infrastructure is a supply-chain risk. Restrict to a dedicated staging environment with code review.",
		mapping:   "OWASP LLM06, CWE-829",
		toolNames: []string{"deploy_lambda", "create_lambda", "lambda_create", "function_deploy", "deploy_function", "create_function", "cloudfunction_deploy", "lambda_deploy"},
	},
	// MCP063: Windows registry key write
	{
		ruleID:    "MCP063",
		name:      "Windows registry write capability",
		sev:       SeverityCritical,
		fix:       "Registry writes under HKCU\\Run, HKLM\\Run, or similar keys establish persistence. Remove or restrict to known-safe registry paths.",
		mapping:   "OWASP LLM06, ATLAS AML.T0048, CWE-284",
		toolNames: []string{"registry_write", "reg_write", "registry_set", "reg_set_value", "write_registry", "hkcu_write", "hklm_write"},
	},
	// MCP064: Login item / startup add
	{
		ruleID:    "MCP064",
		name:      "Login item or startup item write capability",
		sev:       SeverityCritical,
		fix:       "Login item writes establish persistence across reboots. Remove unless the server manages user-facing agent launchers.",
		mapping:   "OWASP LLM06, ATLAS AML.T0048, CWE-284",
		toolNames: []string{"login_item_add", "add_login_item", "startup_item_add", "add_startup", "startup_add"},
	},
	// MCP065: Daemon / system service installation
	{
		ruleID:    "MCP065",
		name:      "System daemon or service installation capability",
		sev:       SeverityCritical,
		fix:       "Daemon installation achieves boot-persistent code execution. Remove and use an out-of-band service management process.",
		mapping:   "OWASP LLM06, ATLAS AML.T0048, CWE-284",
		toolNames: []string{"daemon_install", "install_daemon", "create_daemon", "service_install", "install_service", "create_service"},
	},
	// MCP066: Systemd unit creation
	{
		ruleID:    "MCP066",
		name:      "Systemd unit file creation capability",
		sev:       SeverityCritical,
		fix:       "Creating systemd units establishes privileged persistence. Remove and use a configuration management workflow instead.",
		mapping:   "OWASP LLM06, ATLAS AML.T0048, CWE-284",
		toolNames: []string{"systemd_unit_create", "create_systemd_unit", "systemd_enable", "unit_file_create", "systemd_install"},
	},
	// MCP067: Shell init file modification
	{
		ruleID:    "MCP067",
		name:      "Shell initialisation file modification capability",
		sev:       SeverityCritical,
		fix:       "Modifying .bashrc/.zshrc/profile runs attacker-controlled code on every new shell. Remove.",
		mapping:   "OWASP LLM06, ATLAS AML.T0048, CWE-284",
		toolNames: []string{"bashrc_write", "zshrc_write", "profile_write", "write_profile", "shell_config_write"},
	},
	// MCP068: Scheduled task creation
	{
		ruleID:    "MCP068",
		name:      "Scheduled task or at-job creation capability",
		sev:       SeverityCritical,
		fix:       "Scheduled tasks establish persistence and enable deferred code execution. Remove or restrict to read-only task listing.",
		mapping:   "OWASP LLM06, ATLAS AML.T0048, CWE-284",
		toolNames: []string{"at_schedule", "atjob_create", "schedule_at", "create_scheduled_task", "schtasks_create"},
	},
	// MCP069: Log clearing / audit tampering
	{
		ruleID:    "MCP069",
		name:      "Log clearing or audit log tampering capability",
		sev:       SeverityCritical,
		fix:       "Remove log deletion tools. Clearing logs destroys forensic evidence of attacker activity.",
		mapping:   "OWASP LLM06, ATLAS AML.T0054, CWE-223",
		toolNames: []string{"clear_logs", "log_clear", "audit_log_clear", "wipe_logs", "delete_logs", "log_delete", "clear_event_log", "event_log_clear"},
	},
	// MCP070: Shell history deletion
	{
		ruleID:    "MCP070",
		name:      "Shell history deletion capability",
		sev:       SeverityHigh,
		fix:       "Shell history deletion removes evidence of commands run. Remove this tool.",
		mapping:   "OWASP LLM06, ATLAS AML.T0054, CWE-223",
		toolNames: []string{"history_clear", "clear_history", "delete_history", "clear_shell_history", "bash_history_clear"},
	},
	// MCP071: File timestamp modification (timestomping)
	{
		ruleID:    "MCP071",
		name:      "File timestamp modification (timestomping) capability",
		sev:       SeverityHigh,
		fix:       "Timestomping defeats forensic file-timeline analysis. Remove this tool.",
		mapping:   "OWASP LLM06, ATLAS AML.T0054",
		toolNames: []string{"file_timestomp", "timestomp", "modify_timestamps", "change_file_time", "touch_timestamp"},
	},
	// MCP072: Antivirus / EDR bypass
	{
		ruleID:    "MCP072",
		name:      "Antivirus or EDR bypass capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool. Any tool that disables or excludes AV/EDR directly aids malware execution.",
		mapping:   "OWASP LLM06, ATLAS AML.T0054",
		toolNames: []string{"av_exclude", "antivirus_exclude", "av_exclusion_add", "edr_bypass", "disable_av", "av_disable", "tamper_protection_disable", "defender_exclude"},
	},
	// MCP073: Shadow copy / VSS deletion
	{
		ruleID:    "MCP073",
		name:      "Shadow copy or volume snapshot deletion capability",
		sev:       SeverityCritical,
		fix:       "Shadow copy deletion is a hallmark of ransomware. Remove this tool immediately.",
		mapping:   "OWASP LLM06, ATLAS AML.T0054",
		toolNames: []string{"shadow_copy_delete", "vss_delete", "delete_shadow_copies", "vssadmin_delete", "wmic_shadowcopy_delete"},
	},
	// MCP074: File attribute hiding
	{
		ruleID:    "MCP074",
		name:      "File hidden attribute manipulation capability",
		sev:       SeverityMedium,
		fix:       "Setting hidden attributes aids attacker persistence by concealing files. Remove unless explicitly required.",
		mapping:   "OWASP LLM06, ATLAS AML.T0054",
		toolNames: []string{"file_hide", "hide_file", "set_hidden", "set_hidden_attribute", "attrib_hide"},
	},
	// MCP075: Audit / logging disable
	{
		ruleID:    "MCP075",
		name:      "Audit or system logging disable capability",
		sev:       SeverityCritical,
		fix:       "Disabling system logging destroys forensic evidence. Remove this tool entirely.",
		mapping:   "OWASP LLM06, ATLAS AML.T0054, CWE-223",
		toolNames: []string{"disable_audit", "audit_disable", "disable_logging", "log_disable", "disable_syslog"},
	},
	// MCP076: Sudo / root execution
	{
		ruleID:    "MCP076",
		name:      "Sudo or root-privileged execution capability",
		sev:       SeverityCritical,
		fix:       "Root execution from an MCP tool call bypasses all OS-level access controls. Remove and implement the minimum required privileged operation directly.",
		mapping:   "OWASP LLM06, CWE-272",
		toolNames: []string{"run_as_root", "exec_as_root", "sudo_exec", "sudo_run", "execute_privileged", "run_privileged"},
	},
	// MCP077: Setuid / capability manipulation
	{
		ruleID:    "MCP077",
		name:      "Setuid or Linux capability manipulation capability",
		sev:       SeverityCritical,
		fix:       "Setting SUID bits or adding Linux capabilities enables privilege escalation. Remove.",
		mapping:   "OWASP LLM06, CWE-272",
		toolNames: []string{"setuid_set", "add_setuid", "cap_add_linux", "add_capability", "set_capability", "setcap_add"},
	},
	// MCP078: Sudoers file modification
	{
		ruleID:    "MCP078",
		name:      "Sudoers file modification capability",
		sev:       SeverityCritical,
		fix:       "Modifying sudoers grants permanent root access. Remove and use a dedicated privilege management system.",
		mapping:   "OWASP LLM06, CWE-272",
		toolNames: []string{"sudoers_add", "add_to_sudoers", "sudoers_write", "write_sudoers", "visudo_write"},
	},
	// MCP079: Process / code injection
	{
		ruleID:    "MCP079",
		name:      "Process injection or DLL injection capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool. Process injection is a core attacker technique with no legitimate MCP server use case.",
		mapping:   "OWASP LLM06, CWE-94",
		toolNames: []string{"dll_inject", "inject_dll", "process_inject", "code_inject", "inject_shellcode", "reflective_inject", "dll_load_inject"},
	},
	// MCP080: File archiving (data staging)
	{
		ruleID:    "MCP080",
		name:      "Bulk file archiving capability (potential data staging)",
		sev:       SeverityMedium,
		fix:       "Bulk archiving is often used to stage data before exfiltration. Ensure archive tools cannot be targeted at sensitive directories.",
		mapping:   "OWASP LLM08, CWE-200",
		toolNames: []string{"compress_files", "archive_files", "zip_directory", "create_archive", "tar_create", "compress_directory", "bulk_archive"},
	},
	// MCP081: Bulk file encryption (ransomware / staging)
	{
		ruleID:    "MCP081",
		name:      "Bulk file encryption capability",
		sev:       SeverityHigh,
		fix:       "Bulk encryption of files is the primary action of ransomware. Remove unless this is a dedicated backup-encryption service with strict path controls.",
		mapping:   "OWASP LLM06, ATLAS AML.T0048",
		toolNames: []string{"encrypt_files", "file_encrypt", "encrypt_directory", "bulk_encrypt", "directory_encrypt"},
	},
	// MCP082: Reverse / bind shell
	{
		ruleID:    "MCP082",
		name:      "Reverse shell or bind shell capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool immediately. Reverse and bind shells have no legitimate MCP server use case.",
		mapping:   "OWASP LLM06, ATLAS AML.T0043, CWE-78",
		toolNames: []string{"reverse_shell", "bind_shell", "shell_connect_back", "spawn_reverse_shell", "revshell"},
	},
	// MCP083: Port forwarding / tunneling
	{
		ruleID:    "MCP083",
		name:      "Port forwarding or tunnel creation capability",
		sev:       SeverityHigh,
		fix:       "Port forwarding tunnels can expose internal services or establish C2 channels. Remove or restrict to specific source/destination pairs.",
		mapping:   "OWASP LLM06, CWE-918",
		toolNames: []string{"port_forward", "port_tunnel", "create_tunnel", "ssh_tunnel_create", "tcp_tunnel", "socat_tunnel"},
	},
	// MCP084: DNS / ICMP covert channel
	{
		ruleID:    "MCP084",
		name:      "Covert channel or DNS/ICMP tunnel capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool. Covert tunneling is exclusively used to bypass network controls.",
		mapping:   "OWASP LLM06, CWE-918",
		toolNames: []string{"dns_tunnel", "dns_covert_channel", "icmp_tunnel", "covert_tunnel", "dns_c2"},
	},
	// MCP085: Proxy / Tor anonymisation
	{
		ruleID:    "MCP085",
		name:      "Proxy, SOCKS, or Tor anonymisation setup capability",
		sev:       SeverityHigh,
		fix:       "Anonymisation infrastructure is used to hide attacker activity and bypass egress controls. Remove.",
		mapping:   "OWASP LLM06, CWE-918",
		toolNames: []string{"socks_proxy", "proxy_setup", "tor_connect", "onion_connect", "setup_proxy", "socks5_connect"},
	},
	// MCP086: Memory read / process memory access
	{
		ruleID:    "MCP086",
		name:      "Memory read or process memory access capability",
		sev:       SeverityCritical,
		fix:       "Process memory access can extract secrets from running applications. Remove.",
		mapping:   "OWASP LLM02, CWE-119",
		toolNames: []string{"read_memory", "write_memory", "process_memory_read", "memory_dump", "memdump", "read_proc_mem"},
	},
	// MCP087: Kernel module operations
	{
		ruleID:    "MCP087",
		name:      "Kernel module loading capability",
		sev:       SeverityCritical,
		fix:       "Loading kernel modules grants ring-0 access and can disable all OS security. Remove.",
		mapping:   "OWASP LLM06, CWE-272",
		toolNames: []string{"load_kernel_module", "insmod_run", "kernel_module_install", "load_driver", "driver_install"},
	},
	// MCP088: Database user / privilege manipulation
	{
		ruleID:    "MCP088",
		name:      "Database user or privilege manipulation capability",
		sev:       SeverityHigh,
		fix:       "Database privilege grants persist beyond the agent session. Remove and use an out-of-band DBA workflow.",
		mapping:   "OWASP LLM06, CWE-272",
		toolNames: []string{"db_create_user", "db_grant_privilege", "sql_create_user", "postgres_create_user", "mysql_create_user", "db_add_user"},
	},
	// MCP089: Database raw / unparameterised query
	{
		ruleID:    "MCP089",
		name:      "Raw or unparameterised database query capability",
		sev:       SeverityHigh,
		fix:       "Raw SQL execution enables SQL injection and unrestricted data access. Use a parameterised query interface with a read-only role.",
		mapping:   "OWASP LLM06, CWE-89",
		toolNames: []string{"raw_sql", "sql_exec", "execute_sql", "db_query_raw", "run_sql_query", "execute_raw_sql", "unsafe_sql"},
	},
	// MCP090: Database drop / truncate
	{
		ruleID:    "MCP090",
		name:      "Database drop or truncate capability",
		sev:       SeverityHigh,
		fix:       "DROP/TRUNCATE is irreversible. Remove or require explicit human confirmation.",
		mapping:   "OWASP LLM06, CWE-89",
		toolNames: []string{"drop_table", "drop_database", "truncate_table", "db_drop", "sql_drop", "db_destroy"},
	},
	// MCP091: Cryptocurrency wallet access
	{
		ruleID:    "MCP091",
		name:      "Cryptocurrency wallet key or seed phrase access",
		sev:       SeverityCritical,
		fix:       "Wallet keys and seed phrases in LLM context enable total fund loss. Remove and never expose them through an MCP interface.",
		mapping:   "OWASP LLM02, CWE-312",
		toolNames: []string{"wallet_get_key", "export_wallet", "wallet_seed", "mnemonic_get", "get_seed_phrase", "wallet_dump", "wallet_export"},
	},
	// MCP092: Cryptocurrency transfer
	{
		ruleID:    "MCP092",
		name:      "Cryptocurrency transfer capability",
		sev:       SeverityCritical,
		fix:       "An agent initiating fund transfers without human approval is an unacceptable financial risk. Remove and require out-of-band confirmation.",
		mapping:   "OWASP LLM06, CWE-284",
		toolNames: []string{"crypto_transfer", "send_crypto", "wallet_transfer", "eth_transfer", "btc_send", "token_transfer"},
	},
	// MCP093: Browser stored password access
	{
		ruleID:    "MCP093",
		name:      "Browser stored password access capability",
		sev:       SeverityCritical,
		fix:       "Browser password stores contain credentials for every site the user has visited. Remove entirely.",
		mapping:   "OWASP LLM02, CWE-522",
		toolNames: []string{"browser_saved_passwords", "get_saved_passwords", "browser_credential_dump", "browser_passwords_get"},
	},
	// MCP094: Root TLS certificate installation
	{
		ruleID:    "MCP094",
		name:      "Root TLS certificate installation capability",
		sev:       SeverityCritical,
		fix:       "Installing a root CA enables TLS MITM for all traffic. Remove.",
		mapping:   "OWASP LLM06, CWE-295",
		toolNames: []string{"install_root_cert", "add_root_certificate", "trust_certificate", "cert_install", "ca_install", "root_ca_install"},
	},
	// MCP095: Email forwarding / inbox rule creation
	{
		ruleID:    "MCP095",
		name:      "Email forwarding or inbox rule creation capability",
		sev:       SeverityHigh,
		fix:       "Inbox rules that forward email are a classic Business Email Compromise technique. Remove or require human review.",
		mapping:   "OWASP LLM06, ATLAS AML.T0048",
		toolNames: []string{"email_rule_create", "mail_rule_add", "create_mail_rule", "inbox_rule_create", "email_forward_add", "mail_forward", "setup_email_forward"},
	},
	// MCP096: Cloud audit trail disable
	{
		ruleID:    "MCP096",
		name:      "Cloud audit trail or CloudTrail disable capability",
		sev:       SeverityCritical,
		fix:       "Disabling CloudTrail / cloud audit logs destroys evidence of attacker actions. Remove this tool.",
		mapping:   "OWASP LLM06, ATLAS AML.T0054, CWE-223",
		toolNames: []string{"cloudtrail_disable", "disable_cloudtrail", "audit_trail_disable", "logging_disable_cloud", "disable_cloud_audit"},
	},
	// MCP097: Cloud access key generation
	{
		ruleID:    "MCP097",
		name:      "Cloud IAM access key generation capability",
		sev:       SeverityHigh,
		fix:       "Generating IAM access keys creates long-lived credentials. Remove or restrict to specific IAM users with minimal permissions.",
		mapping:   "OWASP LLM06, CWE-522",
		toolNames: []string{"create_access_key", "iam_create_access_key", "generate_access_key", "iam_key_create", "aws_create_key"},
	},
	// MCP098: Cloud resource bulk deletion
	{
		ruleID:    "MCP098",
		name:      "Cloud resource bulk deletion capability",
		sev:       SeverityCritical,
		fix:       "Bulk resource deletion is irreversible. Remove and use a change-management workflow with mandatory approval.",
		mapping:   "OWASP LLM06, CWE-284",
		toolNames: []string{"delete_all_resources", "bulk_delete_resources", "destroy_environment", "nuke_resources", "nuke_account"},
	},
	// MCP099: Cloud MFA device deletion
	{
		ruleID:    "MCP099",
		name:      "Cloud MFA device deletion capability",
		sev:       SeverityCritical,
		fix:       "Deleting MFA devices weakens account security posture. Remove and handle via identity management workflows.",
		mapping:   "OWASP LLM06, CWE-308",
		toolNames: []string{"delete_mfa_device", "mfa_device_remove", "deactivate_mfa", "mfa_delete", "disable_mfa"},
	},
	// MCP100: Cloud snapshot export / share
	{
		ruleID:    "MCP100",
		name:      "Cloud snapshot export or share capability",
		sev:       SeverityHigh,
		fix:       "Sharing snapshots can expose disk contents including secrets. Restrict destination to approved account IDs.",
		mapping:   "OWASP LLM08, CWE-200",
		toolNames: []string{"share_snapshot", "export_snapshot", "snapshot_copy_to", "ami_share", "ami_copy", "snapshot_share"},
	},
	// MCP101: Network packet capture
	{
		ruleID:    "MCP101",
		name:      "Network packet capture capability",
		sev:       SeverityHigh,
		fix:       "Packet capture can intercept cleartext credentials and session tokens on the local network. Remove.",
		mapping:   "OWASP LLM02, CWE-311",
		toolNames: []string{"packet_capture", "pcap_capture", "traffic_capture", "sniff_traffic", "network_capture", "tcpdump_start"},
	},
	// MCP102: Credential brute-force
	{
		ruleID:    "MCP102",
		name:      "Credential brute-force or password spray capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool. Brute-force and spray tools have no legitimate MCP server use case.",
		mapping:   "OWASP LLM06, CWE-307",
		toolNames: []string{"brute_force", "bruteforce_login", "password_spray", "credential_stuff", "credential_bruteforce"},
	},
	// MCP103: Lateral movement
	{
		ruleID:    "MCP103",
		name:      "Lateral movement execution capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool. Lateral movement tools (psexec, wmiexec, pass-the-hash) are exclusively offensive.",
		mapping:   "OWASP LLM06, ATLAS AML.T0043, CWE-78",
		toolNames: []string{"lateral_move", "pivot_to", "move_laterally", "wmiexec", "psexec_exec", "pass_the_hash", "pass_the_ticket"},
	},
	// MCP104: C2 implant / beacon install
	{
		ruleID:    "MCP104",
		name:      "C2 beacon or implant installation capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool immediately. Installing C2 beacons or implants is exclusively offensive.",
		mapping:   "OWASP LLM06, ATLAS AML.T0048",
		toolNames: []string{"beacon_create", "c2_install", "install_beacon", "c2_beacon_setup", "implant_install", "implant_deploy", "stager_run"},
	},
	// MCP105: Password hash extraction
	{
		ruleID:    "MCP105",
		name:      "Password hash extraction capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool. Password hash dumps enable offline cracking of all system credentials.",
		mapping:   "OWASP LLM02, ATLAS AML.T0057, CWE-522",
		toolNames: []string{"extract_password_hash", "dump_password_hashes", "get_ntlm_hash", "hash_dump", "ntds_dump", "sam_dump"},
	},
	// MCP106: ARP spoofing
	{
		ruleID:    "MCP106",
		name:      "ARP spoofing or cache poisoning capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool. ARP spoofing enables on-path credential interception.",
		mapping:   "OWASP LLM06, CWE-350",
		toolNames: []string{"arp_spoof", "arp_poison", "arp_cache_poison"},
	},
	// MCP107: SSL/TLS interception / stripping
	{
		ruleID:    "MCP107",
		name:      "SSL stripping or TLS interception capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool. TLS stripping exposes all HTTPS traffic to cleartext.",
		mapping:   "OWASP LLM06, CWE-295",
		toolNames: []string{"ssl_strip", "tls_intercept", "mitm_ssl", "https_strip", "ssl_intercept"},
	},
	// MCP108: Anti-forensic secure-delete
	{
		ruleID:    "MCP108",
		name:      "Anti-forensic file shredding capability",
		sev:       SeverityHigh,
		fix:       "Secure file shredding destroys forensic evidence. Remove unless this is a dedicated privacy-tool server.",
		mapping:   "OWASP LLM06, ATLAS AML.T0054",
		toolNames: []string{"shred_file", "secure_delete", "overwrite_file", "forensic_prevent", "wipe_file", "file_shred"},
	},
	// MCP109: Boot record / bootloader modification
	{
		ruleID:    "MCP109",
		name:      "Boot record or bootloader modification capability",
		sev:       SeverityCritical,
		fix:       "Remove this tool. Bootloader modification is a rootkit/bootkit technique.",
		mapping:   "OWASP LLM06, ATLAS AML.T0048",
		toolNames: []string{"mbr_write", "boot_record_modify", "grub_modify", "bootloader_install", "uefi_write"},
	},
	// MCP110: Git credential helper manipulation
	{
		ruleID:    "MCP110",
		name:      "Git credential helper modification capability",
		sev:       SeverityHigh,
		fix:       "Modifying the git credential helper can redirect credential lookups to an attacker-controlled process. Remove.",
		mapping:   "OWASP LLM06, CWE-522",
		toolNames: []string{"git_credential_helper_set", "configure_git_credentials", "git_credential_store_write"},
	},

	// ── Description-based rules ─────────────────────────────────────────────
	// MCP111: Tool description claims unrestricted access
	{
		ruleID:  "MCP111",
		name:    "Tool claims unrestricted or unlimited access",
		sev:     SeverityHigh,
		fix:     "A tool advertising 'unrestricted access' or 'no limitations' is a red flag. Verify and restrict its scope.",
		mapping: "OWASP LLM02, CWE-284",
		descWords: []string{
			"unrestricted access", "full access to", "access anything",
			"no limitations", "without restrictions", "unlimited access",
		},
	},
	// MCP112: Tool description mentions bypassing security controls
	{
		ruleID:  "MCP112",
		name:    "Tool description references bypassing security controls",
		sev:     SeverityCritical,
		fix:     "A tool that explicitly describes bypassing security controls must be removed.",
		mapping: "OWASP LLM06, CWE-284",
		descWords: []string{
			"bypass security", "skip authentication", "disable firewall",
			"bypass antivirus", "evade detection", "bypass edr",
			"bypass endpoint", "disable uac",
		},
	},
	// MCP113: Tool description references privilege escalation
	{
		ruleID:  "MCP113",
		name:    "Tool description references privilege escalation",
		sev:     SeverityCritical,
		fix:     "Remove this tool. Privilege escalation capabilities must not be exposed through MCP.",
		mapping: "OWASP LLM06, CWE-272",
		descWords: []string{
			"privilege escalation", "gain root", "become root",
			"elevate privilege", "get admin", "escalate to admin",
		},
	},
	// MCP114: Tool description references C2 / malware concepts
	{
		ruleID:  "MCP114",
		name:    "Tool description references C2 or malware concepts",
		sev:     SeverityCritical,
		fix:     "Remove this server. Any tool referencing command-and-control or malware concepts is malicious.",
		mapping: "OWASP LLM06, ATLAS AML.T0048",
		descWords: []string{
			"command and control", "c2 server", "command-and-control",
			"install implant", "deploy malware", "spread to",
		},
	},
	// MCP115: Tool description references credential harvesting
	{
		ruleID:  "MCP115",
		name:    "Tool description references credential harvesting",
		sev:     SeverityCritical,
		fix:     "Remove this tool. Any tool explicitly advertising credential collection is malicious.",
		mapping: "OWASP LLM02, ATLAS AML.T0057",
		descWords: []string{
			"harvest credentials", "credential harvesting", "collect passwords",
			"steal credentials", "phish credentials",
		},
	},
	// MCP116: Tool description references data exfiltration
	{
		ruleID:  "MCP116",
		name:    "Tool description references data exfiltration",
		sev:     SeverityCritical,
		fix:     "Remove this tool immediately.",
		mapping: "OWASP LLM08, ATLAS AML.T0057",
		descWords: []string{
			"exfiltrate", "data theft", "steal data", "exfil data",
			"data exfiltration",
		},
	},
	// MCP117: Tool description references keylogging
	{
		ruleID:  "MCP117",
		name:    "Tool description references keystroke logging",
		sev:     SeverityCritical,
		fix:     "Remove this tool. Keystroke logging is spyware.",
		mapping: "OWASP LLM02, CWE-359",
		descWords: []string{
			"keylog", "keystroke capture", "keyboard monitoring",
			"record keystrokes", "capture keystrokes",
		},
	},
	// MCP118: Tool description promises complete control
	{
		ruleID:  "MCP118",
		name:    "Tool description promises complete or total control",
		sev:     SeverityHigh,
		fix:     "Tools that promise 'complete control' are almost certainly over-privileged. Audit and restrict.",
		mapping: "OWASP LLM02, CWE-284",
		descWords: []string{
			"complete control", "total control", "full control of",
			"take control of", "take over",
		},
	},
	// MCP119: Tool description references rootkit concepts
	{
		ruleID:  "MCP119",
		name:    "Tool description references rootkit or bootkit concepts",
		sev:     SeverityCritical,
		fix:     "Remove this server. Any rootkit reference in a tool description is definitive malware evidence.",
		mapping: "OWASP LLM06, ATLAS AML.T0048",
		descWords: []string{
			"rootkit", "bootkit", "kernel backdoor", "ring 0 ", "ring0 ",
		},
	},
	// MCP120: Tool description references ransomware behaviour
	{
		ruleID:  "MCP120",
		name:    "Tool description references ransomware-like behaviour",
		sev:     SeverityCritical,
		fix:     "Remove this server immediately.",
		mapping: "OWASP LLM06, ATLAS AML.T0048",
		descWords: []string{
			"encrypt all files", "ransom", "ransomware", "demand payment",
			"decrypt for payment",
		},
	},

	// ── Schema-based rules ───────────────────────────────────────────────────
	// MCP121: Schema accepts a shell_command key
	{
		ruleID:     "MCP121",
		name:       "Tool schema accepts a shell_command parameter",
		sev:        SeverityCritical,
		fix:        "Shell command parameters without strict pattern constraints enable injection. Remove or validate with an explicit allow-list.",
		mapping:    "OWASP LLM06, CWE-78",
		schemaKeys: []string{"\"shell_command\"", "\"bash_cmd\"", "\"shell_script\""},
	},
	// MCP122: Schema accepts a sudo_password / root_password key
	{
		ruleID:     "MCP122",
		name:       "Tool schema accepts a sudo or root password parameter",
		sev:        SeverityCritical,
		fix:        "Accepting passwords through MCP tool parameters exposes them in LLM context. Redesign to use an agent or out-of-band sudo configuration.",
		mapping:    "OWASP LLM02, CWE-522",
		schemaKeys: []string{"\"sudo_password\"", "\"root_password\"", "\"admin_password\""},
	},
	// MCP123: Schema accepts an aws_secret_access_key
	{
		ruleID:     "MCP123",
		name:       "Tool schema accepts an AWS secret access key parameter",
		sev:        SeverityCritical,
		fix:        "Never pass AWS credentials through MCP tool parameters. Use IAM roles or instance profiles instead.",
		mapping:    "OWASP LLM02, CWE-522",
		schemaKeys: []string{"\"secret_access_key\"", "\"aws_secret\"", "\"secretaccesskey\""},
	},
	// MCP124: Schema accepts a private_key parameter
	{
		ruleID:     "MCP124",
		name:       "Tool schema accepts a private key parameter",
		sev:        SeverityCritical,
		fix:        "Private keys must not pass through MCP tool parameters. Use a key reference (path or ID) and load the key server-side.",
		mapping:    "OWASP LLM02, CWE-321",
		schemaKeys: []string{"\"private_key\"", "\"privatekey\"", "\"pem_key\"", "\"rsa_key\""},
	},
	// MCP125: Schema accepts an encryption_key / master_key parameter
	{
		ruleID:     "MCP125",
		name:       "Tool schema accepts an encryption or master key parameter",
		sev:        SeverityCritical,
		fix:        "Encryption keys in parameters appear in LLM context and logs. Pass a key reference, not the key value.",
		mapping:    "OWASP LLM02, CWE-312",
		schemaKeys: []string{"\"encryption_key\"", "\"master_key\"", "\"symmetric_key\"", "\"kek\""},
	},
}

// ─── Resource catalog ─────────────────────────────────────────────────────────

var resourceCatalogRules = []resourceCatalogRule{
	{
		ruleID:   "MCP130",
		name:     "Sensitive Unix credential file exposed as resource",
		sev:      SeverityCritical,
		fix:      "Remove /etc/shadow, /etc/sudoers, and similar credential files from the resource list.",
		mapping:  "OWASP LLM02, CWE-522",
		uriWords: []string{"/etc/shadow", "etc/sudoers", "etc/passwd", ".ssh/authorized_keys"},
	},
	{
		ruleID:   "MCP131",
		name:     "SSH private key exposed as resource",
		sev:      SeverityCritical,
		fix:      "Remove SSH private key resources. SSH keys must never be exposed through MCP.",
		mapping:  "OWASP LLM02, CWE-312",
		uriWords: []string{".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_dsa", "id_rsa", "id_ed25519"},
	},
	{
		ruleID:   "MCP132",
		name:     "Cloud credential file exposed as resource",
		sev:      SeverityCritical,
		fix:      "Remove cloud credential files from the resource list. Use IAM roles instead of static credentials.",
		mapping:  "OWASP LLM02, CWE-522",
		uriWords: []string{".aws/credentials", ".aws/config", "application_default_credentials", ".kube/config", "kubeconfig"},
	},
	{
		ruleID:   "MCP133",
		name:     "Environment or secrets file exposed as resource",
		sev:      SeverityHigh,
		fix:      "Remove .env and secrets files from the resource list. Store secrets in a vault, not in files.",
		mapping:  "OWASP LLM02, CWE-312",
		uriWords: []string{".env", "secrets.yaml", "secrets.json", "secrets.toml", "vault.token", ".vault-token", "credentials.json"},
	},
	{
		ruleID:   "MCP134",
		name:     "Private key or certificate file exposed as resource",
		sev:      SeverityCritical,
		fix:      "Remove PEM/P12/JKS key material from the resource list.",
		mapping:  "OWASP LLM02, CWE-321",
		uriWords: []string{"private_key", "privkey", ".pem", ".p12", ".pfx", ".jks", "keystore."},
	},
	{
		ruleID:   "MCP135",
		name:     "Password or credential text file exposed as resource",
		sev:      SeverityHigh,
		fix:      "Remove password and credential text files from the resource list.",
		mapping:  "OWASP LLM02, CWE-522",
		uriWords: []string{".htpasswd", "passwords.txt", "pass.txt", "credentials.txt", "password.txt"},
	},
	{
		ruleID:   "MCP136",
		name:     "Database credential file exposed as resource",
		sev:      SeverityHigh,
		fix:      "Remove database credential files from the resource list.",
		mapping:  "OWASP LLM02, CWE-522",
		uriWords: []string{"database.yml", "database.json", "db.env", "db_password", "database.php"},
	},
	{
		ruleID:   "MCP137",
		name:     "Linux /proc or /dev file exposed as resource",
		sev:      SeverityHigh,
		fix:      "Remove /proc and /dev entries from the resource list. These expose kernel-level data.",
		mapping:  "OWASP LLM02, CWE-200",
		uriWords: []string{"/proc/", "/dev/mem", "/dev/kmem", "/sys/kernel"},
	},
	{
		ruleID:   "MCP138",
		name:     "Application framework secret file exposed as resource",
		sev:      SeverityHigh,
		fix:      "Remove Rails master.key, Spring application.yml, and similar framework secret files from the resource list.",
		mapping:  "OWASP LLM02, CWE-312",
		uriWords: []string{"master.key", "credentials.yml.enc", "application.properties", ".npmrc", ".pypirc", ".gem/credentials"},
	},
	{
		ruleID:   "MCP139",
		name:     "Root home directory exposed as resource",
		sev:      SeverityHigh,
		fix:      "Remove root's home directory from the resource list.",
		mapping:  "OWASP LLM02, CWE-200",
		uriWords: []string{"/root/", "c:\\users\\administrator\\", "c:/users/administrator/"},
	},
	{
		ruleID:  "MCP140",
		name:    "Executable binary exposed as resource",
		sev:     SeverityMedium,
		fix:     "Remove executable and shared-library resources. MCP resources should expose data, not code.",
		mapping: "OWASP LLM06, CWE-829",
		mimeTypes: []string{
			"application/x-executable",
			"application/x-sharedlib",
			"application/x-mach-binary",
			"application/vnd.microsoft.portable-executable",
			"application/x-sh",
			"application/x-shellscript",
		},
	},
}

// ─── Prompt catalog ──────────────────────────────────────────────────────────

var promptCatalogRules = []promptCatalogRule{
	{
		ruleID:    "MCP150",
		name:      "Prompt requests password or API key",
		sev:       SeverityHigh,
		fix:       "Prompts that ask for secrets embed those secrets in LLM context. Remove and use a credential-vending tool instead.",
		mapping:   "OWASP LLM02, CWE-522",
		descWords: []string{"password", "api key", "api_key", "secret key", "access token", "auth token", "private key", "passphrase"},
	},
	{
		ruleID:    "MCP151",
		name:      "Prompt injection pattern in prompt description",
		sev:       SeverityCritical,
		fix:       "Remove this prompt. Injection phrases in prompt descriptions indicate an attempt to override LLM instructions.",
		mapping:   "OWASP LLM01, ATLAS AML.T0051, CWE-77",
		descWords: []string{"ignore previous", "ignore your", "forget your", "new instructions", "override your", "system prompt override", "jailbreak", "dan mode", "disregard your training"},
	},
	{
		ruleID:    "MCP152",
		name:      "Prompt requests personally identifiable information",
		sev:       SeverityHigh,
		fix:       "Remove prompts that ask for PII. These may be used to harvest sensitive user data.",
		mapping:   "OWASP LLM02, CWE-359",
		descWords: []string{"social security", "credit card", "date of birth", "passport number", "driver's license", "national id", "tax id", "ssn"},
	},
	{
		ruleID:    "MCP153",
		name:      "Prompt asks LLM to roleplay or ignore its training",
		sev:       SeverityHigh,
		fix:       "Remove this prompt. Roleplay and persona-override instructions are standard jailbreak vectors.",
		mapping:   "OWASP LLM01, ATLAS AML.T0051",
		descWords: []string{"pretend you are", "act as if", "roleplay as", "you are now", "forget you are an ai", "disregard your training", "ignore your guidelines"},
	},
	{
		ruleID:  "MCP154",
		name:    "Prompt name suggests credential or authentication context",
		sev:     SeverityMedium,
		fix:     "Review this prompt to confirm it does not expose or request sensitive credentials.",
		mapping: "OWASP LLM02, CWE-522",
		nameWords: []string{"credential", "authenticate", "login", "password_", "secret_", "auth_"},
	},
	{
		ruleID: "MCP155",
		name:   "Prompt description exceeds 2 000 characters (data-stuffing risk)",
		sev:    SeverityMedium,
		fix:    "Extremely long prompt descriptions may be used to smuggle instructions or data past LLM context filters. Review the content.",
		mapping: "OWASP LLM01, CWE-20",
		minLen:  2000,
	},
}

// ─── EvalToolCatalog ──────────────────────────────────────────────────────────

// EvalToolCatalog runs catalog-level rules against a single tool.
func EvalToolCatalog(t *mcpclient.Tool) []Finding {
	var f []Finding
	nameLower := strings.ToLower(t.Name)
	descLower := strings.ToLower(t.Description)
	schemaLower := strings.ToLower(string(t.InputSchema))

	for _, rule := range toolCatalogRules {
		var matched bool
		detail := ""

		if !matched {
			for _, pat := range rule.toolNames {
				if strings.Contains(nameLower, pat) {
					detail = "Tool '" + t.Name + "' name contains '" + pat + "'."
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, word := range rule.descWords {
				if strings.Contains(descLower, word) {
					detail = "Tool '" + t.Name + "' description contains '" + word + "'."
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, key := range rule.schemaKeys {
				if strings.Contains(schemaLower, key) {
					detail = "Tool '" + t.Name + "' input schema contains '" + key + "'."
					matched = true
					break
				}
			}
		}
		if matched {
			f = append(f, Finding{
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

// ─── EvalResourceCatalog ──────────────────────────────────────────────────────

// EvalResourceCatalog runs catalog-level rules against a single resource.
func EvalResourceCatalog(r *mcpclient.Resource) []Finding {
	var f []Finding
	uriLower := strings.ToLower(r.URI)
	mimeLower := strings.ToLower(r.MimeType)

	for _, rule := range resourceCatalogRules {
		var matched bool
		detail := ""

		if !matched {
			for _, word := range rule.uriWords {
				if strings.Contains(uriLower, word) {
					detail = "Resource URI '" + r.URI + "' matches sensitive pattern '" + word + "'."
					matched = true
					break
				}
			}
		}
		if !matched && mimeLower != "" {
			for _, mt := range rule.mimeTypes {
				if strings.Contains(mimeLower, mt) {
					detail = "Resource '" + r.Name + "' has MIME type '" + r.MimeType + "' which indicates an executable."
					matched = true
					break
				}
			}
		}
		if matched {
			f = append(f, Finding{
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

// ─── EvalPromptCatalog ────────────────────────────────────────────────────────

// EvalPromptCatalog runs catalog-level rules against a single prompt.
func EvalPromptCatalog(p *mcpclient.Prompt) []Finding {
	var f []Finding
	descLower := strings.ToLower(p.Description)
	nameLower := strings.ToLower(p.Name)

	// Also check for injectionPhrasePatterns defined in rules.go.
	for _, pat := range injectionPhrasePatterns {
		if pat.MatchString(descLower) {
			f = append(f, Finding{
				RuleID:   "MCP156",
				Name:     "Regex-matched prompt injection pattern in prompt description",
				Severity: SeverityCritical,
				Detail:   "Prompt '" + p.Name + "' description matches prompt-injection regex: " + pat.String(),
				Fix:      "Remove or rewrite the prompt description. Do not trust this server.",
				Mapping:  "OWASP LLM01, ATLAS AML.T0051, CWE-77",
			})
			break
		}
	}

	for _, rule := range promptCatalogRules {
		var matched bool
		detail := ""

		if !matched && rule.minLen > 0 && len(p.Description) >= rule.minLen {
			detail = "Prompt '" + p.Name + "' description is " + itoa(len(p.Description)) + " characters."
			matched = true
		}
		if !matched {
			for _, word := range rule.descWords {
				if strings.Contains(descLower, word) {
					detail = "Prompt '" + p.Name + "' description contains '" + word + "'."
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, word := range rule.nameWords {
				if strings.Contains(nameLower, word) {
					detail = "Prompt name '" + p.Name + "' contains '" + word + "'."
					matched = true
					break
				}
			}
		}
		if matched {
			f = append(f, Finding{
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

