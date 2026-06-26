# Changelog

All notable changes to Aspex are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] — 2026-06-26

### Added

**aspex-scan — new commands**
- `inventory` — enumerate every MCP server and tool across all clients; table and `--json` output
- `attack-paths` — novel cross-server attack chain analysis: maps per-server capabilities (file-read, shell-exec, network-send, credential-read, persistence, env-read, email-send) and surfaces dangerous combinations that form complete attack chains (Data Exfiltration, Credential Theft, Persistence via Shell, C2, Env Var Exfiltration, Email Exfiltration) with MITRE ATT&CK tactic + reference
- `completion <shell>` — shell completions for bash, zsh, fish, PowerShell
- `version --check` — query GitHub Releases API for a newer version

**aspex-trace — new commands**
- `stats` — fast activity dashboard (client/server/tool breakdowns) without evaluating detection rules
- `session [id]` — forensic timeline reconstruction: list recent sessions or drill into a specific one to see every event in chronological order with rule findings inline
- `export` — export all events to CSV or JSONL for SIEM ingest or custom analysis
- `live` — real-time monitoring: polls logs on a configurable interval and prints new findings as they appear
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
