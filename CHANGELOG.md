# Changelog

All notable changes to Aspex are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.3] — 2026-06-27

### Changed

- `aspex` TUI: after a tool exits, prompt the user to return to the menu instead of quitting. Press any key to go back, Q to exit.

---

## [0.3.2] — 2026-06-27

### Fixed

- `aspex` TUI layout was scrambled in Warp and other terminals — raw mode requires `\r\n` line endings, not bare `\n`

---

## [0.3.1] — 2026-06-26

### Added

- `aspex` — unified interactive launcher with arrow-key TUI menu. Run with no arguments for a guided menu across all three tools; press `→` for per-tool option submenus (quick-launch presets). Pass-through mode: `aspex scan`, `aspex trace`, `aspex attack` forward directly to the underlying binary.
- `aspex-attack` routing — until the standalone attack binary ships, `aspex attack` routes to `aspex-scan redteam` automatically.

---

## [0.3.0] — 2026-06-26

### Added

**aspex-scan — `--explain` flag**
- Every HIGH and CRITICAL finding now renders a structured security advisory when `--explain` is passed: **WHY** the pattern is dangerous, a concrete **EXPLOIT** scenario, the worst-case **IMPACT**, and a **CONFIDENCE** level
- Covers all 38 CRITICAL and HIGH rules in the catalog (`internal/rules/advisories.go`)
- Transforms the tool from "here's a rule ID" into "here's why an attacker would care and exactly what to change"

**aspex-scan — `redteam` command**
- Actively calls live MCP tools with adversarial payloads and analyzes responses for exploitation evidence
- Five probe categories: `prompt-injection` (8 payloads + detectors), `path-traversal` (4 payloads), `ssrf` (4 payloads including AWS/GCP metadata endpoints), `error-disclosure` (null/oversized/malformed inputs), `prompt-leakage` (system prompt extraction)
- Probes are auto-selected per tool based on parameter names and JSON schema: URL parameters get SSRF probes, path parameters get traversal probes, every tool gets error disclosure and leakage probes
- Flags: `--server` (filter by name), `--timeout` (default 10s), `--categories`, `--json`

**aspex-scan — category security score breakdown**
- Main scan output now shows a per-category breakdown below the health bar: Prompt Security · Tool Security · Data Protection · Supply Chain · Network Security · Access Control
- Each category shows a mini bar chart, letter grade (A+ through F), and the primary driver finding
- Computed from existing rule results — zero extra scanning cost

### Fixed

- `bufio.Scanner` replaced with `bufio.Reader.ReadString` in all four log parsers (claude, claude-code, cursor, windsurf) — eliminates `token too long` errors when Claude Code session transcripts contain lines exceeding the 8 MB scanner limit

---

## [0.2.0] — 2026-06-26

### Added

**aspex-scan — new commands**
- `inventory` — enumerate every MCP server and tool across all clients; table and `--json` output
- `attack-paths` — novel cross-server attack chain analysis: maps per-server capabilities (file-read, shell-exec, network-send, credential-read, persistence, env-read, email-send) and surfaces dangerous combinations that form complete attack chains (Data Exfiltration, Credential Theft, Persistence via Shell, C2, Env Var Exfiltration, Email Exfiltration) with MITRE ATT&CK tactic + reference
- `shadow` — tool name collision detection across all servers; surfaces ambiguous routing that enables interception of tool calls intended for trusted servers; classifies collisions as CRITICAL/HIGH/MEDIUM by transport and capability
- `phantom` — clean-face attack detection: calls `tools/list` twice per server with a configurable delay and diffs results; flags added/removed tools, changed descriptions (including injection-signal language detection), and servers that become unreachable on the second call
- `completion <shell>` — shell completions for bash, zsh, fish, PowerShell
- `version --check` — query GitHub Releases API for a newer version

**aspex-trace — new commands**
- `stats` — fast activity dashboard (client/server/tool breakdowns) without evaluating detection rules
- `session [id]` — forensic timeline reconstruction: list recent sessions or drill into a specific one to see every event in chronological order with rule findings inline
- `export` — export all events to CSV or JSONL for SIEM ingest or custom analysis
- `live` — real-time monitoring: polls logs on a configurable interval and prints new findings as they appear; clean Ctrl-C via signal handler
- `killchain` — multi-event attack pattern reconstruction: correlates suspicious events within a 5-minute window into coherent kill chain patterns (Exfiltration Trifecta, Persistence Establishment, Recon to Credential, Lateral Movement, Injection Signature) with MITRE ATT&CK references
- `provenance` — instruction provenance tracing: links each HIGH/CRITICAL finding backward to the preceding ingestion event (file_read, web_fetch, browser_load, resource_read) most likely to have delivered the injected instruction; confidence-scored by temporal proximity and event distance
- `completion <shell>` — shell completions for bash, zsh, fish, PowerShell
- `version --check` — query GitHub Releases API for a newer version

**aspex-trace — client support**
- Added **Cline** (`saoudrizwan.claude-dev` VS Code extension) — parses `api_conversation_history.json` from extension globalStorage
- Added **Roo Code** (`rooveterinaryinc.roo-cline`) — same format as Cline

**Both tools**
- `Makefile` with `build`, `test`, `test-cover`, `lint`, `clean`, `install`, `completions`, `release-dry-run`, `vuln` targets
- `version --check` respects `ASPEX_NO_UPDATE_CHECK` environment variable

### Security

- Fixed `os.Exit(1)` in `checkTraceExitCode` — now returns `errTraceExitOne` sentinel so defers run before exit
- AT069 AWS key detection rule now uses strict 20-character regex instead of 4-char prefix substring (eliminates false positives on paths containing `akia` etc.)
- Added SSE memory bound (`io.LimitReader` at 10 MB) to prevent unbounded response reads
- Removed placeholder `CVE-2025-12345` / `CVE-2025-54321` IDs from registry
- Removed `some-bad-mcp` test entry from known-bad registry
- ANSI escape injection defense: all server-supplied strings sanitized before terminal output
- Binary checksum verification in npm installers and GitHub Actions composite actions
- Removed `packages: write` from release workflow permissions
- Removed `continue-on-error: true` from npm publish steps

### Fixed

- `checkAT013PersistenceWrite` renamed to `checkAT014PersistenceWrite` (was misidentified)
- Removed dead `strings.Contains(cmd, os.PathSeparator)` no-op block from inspector
- Scanner buffers now grow lazily (64 KB initial, 4 MB max) instead of pre-allocating 4 MB

---

## [0.1.0] — 2025-06-26

### Added

**aspex-scan**
- 250+ detection rules covering prompt injection, credential exposure, code execution, data exfiltration, persistence, surveillance, privilege escalation, defense evasion, C2, and supply chain risks (MCP001–MCP156)
- Scored risk report (0–100 health score) with per-server and overall bands
- Support for 8 MCP clients: Claude Desktop, Claude Code CLI, Cursor, VS Code, Windsurf, Cline, Roo-Cline, Continue.dev, Zed
- stdio and HTTP/SSE transport inspection
- `--json`, `--html`, `--sarif` output modes
- `inspect <server>` subcommand for single-server deep inspection
- `diff --baseline` subcommand for rug-pull detection
- `verify <package>` subcommand against known-malicious registry
- `install-hook` / `uninstall-hook` git pre-commit integration
- `--watch` mode for automatic rescan on config change
- `--fail-on` exit code for CI gating
- GitHub Actions composite action (`aspex-scan-action`)

**aspex-trace**
- 85+ detection rules across credential access, shell execution, reverse shells, exfiltration, persistence, privilege escalation, defense evasion, surveillance, recon, supply chain, obfuscation, and C2 (AT001–AT085)
- Reads native log files from Claude Desktop, Claude Code CLI, Cursor, Windsurf — no proxy, no config change
- Session activity summary with file-access heatmap and git commit counter
- `--summary` compact mode
- `--suppress-noise` mode for coding-agent sessions
- Behavioral baseline: `baseline --learn` + `--baseline` deviation detection
- `--json`, `--sarif` output modes
- `--fail-on` exit code for CI gating
- GitHub Actions composite action (`aspex-trace-action`)

**Both tools**
- Homebrew tap: `brew install aspex-security/tap/aspex`
- npm packages: `aspex-scan`, `aspex-trace`
- Release binaries signed with cosign (keyless, Sigstore) + SPDX SBOM
- Offline-only: no data sent anywhere

[0.1.0]: https://github.com/aspex-security/aspex/releases/tag/v0.1.0
