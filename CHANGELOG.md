# Changelog

All notable changes to Aspex are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.7.0] - 2026-09-11

The release that makes attack paths, trace credibility, and contributor-authored
rules real. See ASSESSMENT.md for the reasoning.

### Added
- Trace evidence levels: every kill chain labels each statement OBSERVED (in
  the log), INFERRED (from ordering and timing, not proof of causation), or
  POSSIBLE (what the composition would allow, which the log cannot confirm -
  payloads are not captured). Rendered in the terminal and in `--json`
  (`evidence`, `same_session`). Chain descriptions no longer assert success.
- Trace session boundaries: analysis and kill-chain detection run per agent
  session (Claude Code's session id, or a 30-minute idle-gap split), so a read
  in one conversation and a send in another are never joined into a chain.
- MCP200: a per-server rule for a server whose writable root reaches the
  agent's own MCP config, hooks, instruction, or memory files, even with no
  ingress present. Severity by blast radius: user-global executable state HIGH,
  global instructions/memory MEDIUM, this-repo `.mcp.json` MEDIUM, this-repo
  instruction files LOW.
- `aspex-scan hooks`: discovers Claude Code lifecycle hooks (commands the agent
  runs automatically) from user and project settings, and judges each -
  curl|sh / base64|sh / reverse shell CRITICAL, credentials+network HIGH,
  credentials or network MEDIUM, everything else INFO. `--json`, `--fail-on`.
- Declarative catalog rules: the 116 substring rules moved to embedded
  `internal/rules/catalog_rules.yaml`. Adding a detection is now a YAML entry
  plus a corpus fixture, no Go. The loader fails CI on a duplicate id or
  invalid severity. New rule MCP126 (tool can disable transport security) was
  added this way as the proof.
- Attack paths rebuilt on evidence (`internal/attackpath`). Capabilities are
  derived from live tool lists, or inferred for well-known packages in static
  scans; filesystem scope comes from the allowed roots in the config
  (home or `/` is sensitive, a project directory is project, undeclared is
  unknown). Six compositions, each with evidence for both halves, the path
  hop by hop, impact, remediation, and a confidence level: AP001 sensitive
  data exfiltration, AP002 credential exfiltration, AP003 persistent agent
  compromise (writable MCP config, hooks, instructions, or memory reachable
  by a server while external content can enter), AP004 memory poisoning,
  AP005 remote control, AP006 untrusted content to command execution.
- Attack paths appear in the default `aspex-scan` report (top four; all in
  `aspex-scan attack-paths` and `--json` under `attackPaths`), participate in
  `--fail-on`, can be accepted in `.aspex.yaml` by ID, and are recorded in
  baselines by ID and server set.
- Score cap: one critical path caps the overall score at 39, one high path at
  69, with the reason printed and exported as `scoreCapReason`. Ten
  informational findings no longer outrank one real composition.
- The `aspex` snapshot headline reports how many attack paths exist and the
  worst one.
- `ASSESSMENT.md`: architecture, weaknesses, and priorities.

### Changed
- A capability on its own is no longer reported as a "chain": a shell server
  alone, or a fetch server alone, produces no path entry. The old
  implementation reported any `read_file` plus anything named `fetch` as a
  CRITICAL "Data Exfiltration" regardless of scope, and a lone shell tool as
  "Persistence via Shell".
- Tool classification is token-based: `user_profile` is not a shell profile,
  `slack_reply_to_thread` is not a REPL, `create_pull_request` is a GitHub
  channel and not arbitrary HTTP egress.
- `aspex-scan attack-paths --json`: `chains` entries gain `id`, `confidence`,
  `evidence`, `impact`, `remediation`; `capabilities` entries gain `static`,
  `fileScope`, `roots`, `evidence`, `agentStateWrites`. Existing fields are
  unchanged.
- npm publishing uses npm Trusted Publishing (OIDC from the release workflow)
  instead of a stored token. `aspex@0.6.1` was the first version on npm.

### Fixed
- MCP006 (secrets in env) no longer flags a secret-shaped key whose value is a
  keychain, `$VAR`, or vault reference: that is the recommended state, not a
  finding. Only plaintext literals are flagged, split by blast radius (cloud,
  database, private keys CRITICAL; scoped API tokens HIGH). Discovery records
  the value shape, never the value. The official GitHub or Slack server with a
  keychain reference now scores clean instead of 39.

## [0.6.1] - 2026-09-10

### Added
- npm package `aspex`: `npx aspex` / `npm i -g aspex`. Downloads the matching
  release archive at install time, verifies it against `checksums.txt`, and
  exposes all five commands through Node shims. Replaces the never-published
  `@aspex/scan` and `@aspex/trace` packages. Publishing runs only when
  `NPM_TOKEN` is set and uses npm provenance.

### Removed
- All vendor footers and links from aspex-scan, aspex-trace, the HTML report,
  README, docs, Homebrew caveats, GitHub Actions and the Jamf script. Aspex is
  an independent open-source project.

### Fixed
- `aspex` launcher no longer exits when a tool it ran returns non-zero.
  aspex-trace defaults to `--fail-on high`, so any HIGH finding ended the
  whole menu session. The launcher now reports the status and returns.
- aspex-trace footer hint printed `--since 24h0m0s`; now `--since 24h`.
- GitHub Actions: `--fail-on` is passed to the binaries (it was only used in
  the failure message, so neither action could fail a build); the scan action
  writes and uploads SARIF when `upload-sarif` is true (the input was dead).
- Release: `version.Version` and `BuildDate` were consts, so GoReleaser's `-X`
  ldflags were silently ignored and binaries reported "built dev". Now vars.
- Release: npm publish never authenticated because the workflow lacked
  `setup-node` with `registry-url`; the package version was also hardcoded
  instead of taken from the tag.
- Homebrew formula text (description, caveats) in `.goreleaser.yaml` now matches
  the trace-first positioning.

## [0.6.0] - 2026-09-10

The release that turns Aspex from "a scanner with a trace tool" into "see what
your agents actually did, then scan what they could do."

### Added
- `aspex` with no arguments now shows a 30-day snapshot first: tool calls your
  agents made, how many went to servers no scan has checked, how many tripped a
  detection rule, and the static score of every configured server. Then the menu.
- `aspex share`: the same headlines as a privacy-safe Markdown card (counts and
  score only, no server names, paths, or commands). `aspex snapshot` prints the
  panel alone for scripts and CI logs.
- `aspex-scan --with-trace`: joins static findings with observed activity from
  aspex-trace logs, ranks servers by risk x use, and lists servers agents call
  that appear in no scanned config. Log names are matched by normalized token
  (`plugin_slack_slack` matches `slack`).
- `.aspex.yaml` policy (`aspex-scan init`): accept a risk with a required reason
  and optional expiry; override or disable any rule's severity; set a default
  `fail_on`. Applied before scoring and before the gate. Expired ignores warn.
- Finding baseline: `--save-baseline` / `--baseline` so only new findings fail
  the gate on an estate with existing findings.
- Claude Code discovery: `~/.claude.json` (user and per-project scopes), project
  `.mcp.json`, and installed plugin `.mcp.json` files. Previously Claude Code
  servers were not discovered at all.
- Detection corpus (`testdata/corpus/`): known-malicious fixtures that must fire
  named rules and popular benign servers that must stay below a stated
  severity. Both run in CI.
- Parallel server inspection (`-j/--concurrency`, default 8). A 7-server scan on
  the maintainer's machine went from 20.2s to 7.0s.
- `aspex-scan doctor` subcommand; `aspex-doctor` remains as an alias.
- JSON output gains `policy`, `suppressed`, `baselined`, and `activity` fields.
- End-to-end tests (`cmd/aspex-scan/e2e_test.go`, `internal/snapshot`) drive the
  real command tree against a fixture home with configs and agent logs; CI now
  also runs gofmt, staticcheck, and deadcode. Four unreachable functions removed.

### Fixed
- `--fail-on` was ignored whenever `--json` or `--sarif` was also passed: the
  command returned after writing output and never reached the exit-code check.
  Any CI job using machine-readable output could not fail. Found by the new
  end-to-end tests. Both output modes now apply the gate.
- AT015 (cross-server data chain) fired on every outbound call after any other
  server had done any read, with no time bound and no dedupe, and treated
  reading a web page as a data read. Thirty days of logs on the maintainer's
  machine produced 103 findings that were two browser servers taking turns.
  Now: one finding per reader->sender pair, 10-minute window, web-content
  reads excluded. Same logs: 2 findings.
- MCP020 matched `repl` as a substring and flagged the official Slack server's
  `slack_reply_to_thread` as CRITICAL code execution. Now token-bounded.
- MCP001 whitelisted U+200B entirely (a trivial bypass). A lone zero-width
  space is still tolerated; three or more, or one splitting a word, is flagged.
- MCP001 had no pattern for "ignore all previous instructions". Added.
- MCP010 and doctor flagged OAuth-authenticated remote servers as having no
  auth. `ServerEntry.OAuth` now records an `oauth` block.
- `aspex-scan fix` can now remove project-scoped servers nested in
  `~/.claude.json`, not just report them removed.
- Docs: `--fail-on` takes a severity, not a score; Claude Code config paths were
  wrong; aspex-trace reads logs, it does not intercept sessions.

## [0.5.5] - 2026-06-29

### Added
- aspex-scan: **Score delta** — summary box now shows change since last scan (`↑ +12 pts`, `↓ -5 pts`, `= no change`)
- aspex-scan: **Prioritized fix plan** — after each scan, shows "Top actions to improve your score" ranked by estimated point gain (e.g. `Fix Secrets in config env across 2 servers (~+70 pts)`)
- aspex-scan: **First-run calibration** — on first-ever scan, explains that a low score is typical for developer machines and most findings are fixable in under 30 minutes
- aspex-scan: **`--share` flag** — prints a privacy-safe Markdown summary (no server names, URLs, or values) suitable for sharing with a team or security review
- aspex-scan: **`--report soc2|iso27001`** — generates a compliance mapping report, showing PASS/FAIL per control with matching findings, and an overall posture verdict
- aspex-scan: **`explain <server-name>`** subcommand — deep-inspection narrative per server: score, all findings with full advisory (why/exploit/impact), and a risk summary sentence
- aspex-scan: **`fix env`** subcommand — generates macOS Keychain migration commands for each hardcoded credential found in MCP configs (`security add-generic-password` + `$(security find-generic-password ...)` replacement snippets)
- aspex-scan: **Continuous monitoring prompt** — footer now suggests `aspex-scan cron --interval 1h` when findings exist
- internal: new `history` package reads previous scan logs from the OS cache dir to power score delta and first-run detection

---

## [0.5.4] - 2026-06-29

### Fixed
- aspex-scan: `npm` added to `knownRuntimes` — servers launched via `npm exec` (e.g. Onyx MCP gateway) were treated as static-only, causing 0 tools to be enumerated and all tool-level rules (prompt injection, credential exposure, etc.) to be silently skipped
- aspex-scan MCP021: plaintext HTTP remote server now correctly rated CRITICAL (was MEDIUM); transmitting MCP tool calls over unencrypted HTTP is a critical interception risk
- aspex-scan MCP001: prompt injection patterns now also checked against `metadata.description` in the server config entry (static analysis, no server connection required)
- aspex-doctor: removed over-broad `"AUTH"` pattern from `dangerousEnvPatterns` — it matched `OAUTH` state flags (`USE_STAGING_OAUTH`, `CLAUDE_CODE_OAUTH_SCOPES`, `CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH`, `CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH`) causing false positives
- aspex-doctor: vars ending in `_URL` are no longer flagged as secrets — URLs are endpoints, not credentials
- aspex-doctor: added known OAuth state vars to `envFalsePositives` (`USE_STAGING_OAUTH`, `USE_LOCAL_OAUTH`, `CLAUDE_CODE_*`, `MCP_GATEWAY_OAUTH_PROVIDERS_URL`)
- aspex-doctor: config-secrets findings now deduplicated by key name across all server blocks — gateway-style configs where N servers share the same env block no longer report the same key N times

---

## [0.5.3] - 2026-06-29

### Fixed
- aspex-doctor: section headers were garbled on all sections except Environment due to byte-slicing multi-byte UTF-8 `─` characters (each is 3 bytes; `sep[:52]` was cutting mid-rune). Fixed by using `strings.Repeat("─", N)` directly.
- aspex-doctor: uninstalled clients (vscode, windsurf, etc.) no longer show as red `✗ config not found` — collapsed to a single dim `· not detected: ...` line
- aspex-scan attack-paths: 14 near-duplicate findings now grouped by attack type (4 blocks instead of 14), with all server pairs listed under each type

---

## [0.5.2] - 2026-06-29

### Added
- aspex TUI: SCAN submenu now includes "HTML report" option - runs `aspex-scan --html ~/aspex-report.html` and opens the result in the browser automatically

---

## [0.5.1] - 2026-06-29

### Security
- Fixed SSRF vulnerability in --notify webhook URL handler (no host validation, RFC1918 bypass)
- Fixed terminal escape injection in aspex-doctor (server-supplied strings not sanitized)
- Fixed bufio.Scanner 64 KB hard cap causing silent data loss on large MCP server tool lists
- Fixed HTTP client timeout missing in redteam probe runner (malicious server could hang indefinitely)
- Fixed subprocess spawned from relative path in inspector without path validation
- Fixed http.DefaultClient with no timeout/redirect guard in version check

### Fixed
- aspex-scan fix --dry-run now defaults to true (previously documented as default but wasn't)
- aspex-attack no longer shows green CLEAN verdict implying safety; now shows explicit probe count disclaimer
- aspex-attack now has --fail-on flag for CI gating
- aspex doctor pass-through added to aspex launcher (aspex doctor now works)
- aspex-trace always shows activity footprint summary even when no anomalies found
- discover.DiscoverAll errors now surfaced as warnings instead of silently discarded
- seen map in aspex-scan cron capped at 10,000 entries to prevent memory leak
- NO_COLOR environment variable now respected by all binaries
- aspex-scan phantom --interval now accepts duration strings (e.g. 5s, 1m)
- Homoglyph detection map: fixed identity mapping 's'->''s'' to correctly detect U+A731

### Documentation
- Removed cosign signing claims from README and SECURITY.md (not yet implemented)
- Fixed rule counts: 140+ scan rules, 220+ total rules
- Added privacy caveat for aspex-attack (it does call tools/call)
- SECURITY.md supported versions updated to include 0.3.x-0.5.x
- CONTRIBUTING.md: added fork/branch workflow, fixed Go version reference
- install.sh: now installs all 5 binaries
- CHANGELOG: added reference links for all releases

### OSS
- Added GitHub issue templates (bug report, false positive, feature request)
- Added PR template
- CI: all 5 binaries now built and tested
- CI: govulncheck now blocks merges

---

## [0.5.0] - 2026-06-29

### Added

**aspex-doctor - local health check**
- New `aspex-doctor` command runs a fast (~2s) health check across 5 categories: client configs, environment secrets, hardcoded config secrets, filesystem exposure, and network security
- Clients: shows which MCP clients are installed, config validity, and server count
- Environment: scans shell env var names for secret patterns (API keys, tokens, passwords) that are inherited by all MCP server processes - never prints values
- Config secrets: detects credentials hardcoded in MCP config env blocks
- Filesystem: flags overly broad path grants (root `/`, home dir, volume roots)
- Network: flags HTTP remote servers (critical) and HTTPS servers without auth tokens (warning)
- Flags: `--json`, `--no-color`, `--version`
- Added to `aspex` TUI launcher as the fourth menu item

---

## [0.4.0] - 2026-06-28

### Added

**aspex-attack - standalone binary**
- `aspex-attack` is now a first-class binary (previously routed to `aspex-scan redteam`)
- Flags: `--server`, `--timeout`, `--categories`, `--json`, `--no-color`, `--clients`
- Unicode block progress bar per-tool; confirmation prompt before probing; per-server summary table

**aspex-scan fix - config hardening**
- New `aspex-scan fix` command removes dangerous MCP servers from JSON config files
- Flags: `--dry-run`, `--severity critical`, `--output path`, `--client name`
- Handles all 4 config variants: `mcpServers` map, `mcp.servers`, `context_servers`, `mcpServers` array

**aspex-scan cron - scheduled scanning**
- New `aspex-scan cron` command runs continuous scans on a configurable interval
- Only reports new findings (deduplicates across runs via `seen` map)
- Flags: `--interval 1h`, `--notify <webhook-url>`, `--quiet`

**aspex-trace live - webhook alerting**
- `aspex-trace live --notify <url>` sends HIGH+ findings to a Slack or generic webhook
- Slack format auto-detected for `hooks.slack.com` URLs (blocks with emoji severity indicators)
- Generic JSON for other endpoints; Bearer token via `?token=` query param

**VS Code extension**
- New `extensions/vscode-aspex/` extension scans MCP config files inline
- Scan on save, manual scan command, workspace-wide scan command
- Findings appear as VS Code diagnostics in Problems panel with severity levels
- Configurable binary path, severity threshold, and scan-on-save toggle

---

## [0.3.4] - 2026-06-27

### Changed

**aspex-scan redteam - false positive reduction**
- `system-prompt-leak` detector now requires clear compliance signals (e.g. "I am now DAN", "my system prompt is:") rather than firing on the word "instructions" echoed back in tool error messages
- `prompt-leakage` detector now requires specific system-prompt disclosure phrases; generic words like "always"/"never" in tool output no longer trigger it
- Probes that receive a tool error response now skip injection/leakage detectors - a rejected malformed input is not a vulnerability
- Error disclosure detectors still run on error responses (stack traces, internal paths in errors are valid findings)

**aspex-scan redteam - UX**
- Confirmation prompt before probing: shows scope (server list, timeout) and requires explicit `y` to proceed
- Per-tool progress indicator while probing: shows `tool-name (N probes)…` in-place, replaced by result on completion

---

## [0.3.3] - 2026-06-27

### Changed

- `aspex` TUI: after a tool exits, prompt the user to return to the menu instead of quitting. Press any key to go back, Q to exit.

---

## [0.3.2] - 2026-06-27

### Fixed

- `aspex` TUI layout was scrambled in Warp and other terminals - raw mode requires `\r\n` line endings, not bare `\n`

---

## [0.3.1] - 2026-06-26

### Added

- `aspex` - unified interactive launcher with arrow-key TUI menu. Run with no arguments for a guided menu across all three tools; press `→` for per-tool option submenus (quick-launch presets). Pass-through mode: `aspex scan`, `aspex trace`, `aspex attack` forward directly to the underlying binary.
- `aspex-attack` routing - until the standalone attack binary ships, `aspex attack` routes to `aspex-scan redteam` automatically.

---

## [0.3.0] - 2026-06-26

### Added

**aspex-scan - `--explain` flag**
- Every HIGH and CRITICAL finding now renders a structured security advisory when `--explain` is passed: **WHY** the pattern is dangerous, a concrete **EXPLOIT** scenario, the worst-case **IMPACT**, and a **CONFIDENCE** level
- Covers all 38 CRITICAL and HIGH rules in the catalog (`internal/rules/advisories.go`)
- Transforms the tool from "here's a rule ID" into "here's why an attacker would care and exactly what to change"

**aspex-scan - `redteam` command**
- Actively calls live MCP tools with adversarial payloads and analyzes responses for exploitation evidence
- Five probe categories: `prompt-injection` (8 payloads + detectors), `path-traversal` (4 payloads), `ssrf` (4 payloads including AWS/GCP metadata endpoints), `error-disclosure` (null/oversized/malformed inputs), `prompt-leakage` (system prompt extraction)
- Probes are auto-selected per tool based on parameter names and JSON schema: URL parameters get SSRF probes, path parameters get traversal probes, every tool gets error disclosure and leakage probes
- Flags: `--server` (filter by name), `--timeout` (default 10s), `--categories`, `--json`

**aspex-scan - category security score breakdown**
- Main scan output now shows a per-category breakdown below the health bar: Prompt Security · Tool Security · Data Protection · Supply Chain · Network Security · Access Control
- Each category shows a mini bar chart, letter grade (A+ through F), and the primary driver finding
- Computed from existing rule results - zero extra scanning cost

### Fixed

- `bufio.Scanner` replaced with `bufio.Reader.ReadString` in all four log parsers (claude, claude-code, cursor, windsurf) - eliminates `token too long` errors when Claude Code session transcripts contain lines exceeding the 8 MB scanner limit

---

## [0.2.0] - 2026-06-26

### Added

**aspex-scan - new commands**
- `inventory` - enumerate every MCP server and tool across all clients; table and `--json` output
- `attack-paths` - novel cross-server attack chain analysis: maps per-server capabilities (file-read, shell-exec, network-send, credential-read, persistence, env-read, email-send) and surfaces dangerous combinations that form complete attack chains (Data Exfiltration, Credential Theft, Persistence via Shell, C2, Env Var Exfiltration, Email Exfiltration) with MITRE ATT&CK tactic + reference
- `shadow` - tool name collision detection across all servers; surfaces ambiguous routing that enables interception of tool calls intended for trusted servers; classifies collisions as CRITICAL/HIGH/MEDIUM by transport and capability
- `phantom` - clean-face attack detection: calls `tools/list` twice per server with a configurable delay and diffs results; flags added/removed tools, changed descriptions (including injection-signal language detection), and servers that become unreachable on the second call
- `completion <shell>` - shell completions for bash, zsh, fish, PowerShell
- `version --check` - query GitHub Releases API for a newer version

**aspex-trace - new commands**
- `stats` - fast activity dashboard (client/server/tool breakdowns) without evaluating detection rules
- `session [id]` - forensic timeline reconstruction: list recent sessions or drill into a specific one to see every event in chronological order with rule findings inline
- `export` - export all events to CSV or JSONL for SIEM ingest or custom analysis
- `live` - real-time monitoring: polls logs on a configurable interval and prints new findings as they appear; clean Ctrl-C via signal handler
- `killchain` - multi-event attack pattern reconstruction: correlates suspicious events within a 5-minute window into coherent kill chain patterns (Exfiltration Trifecta, Persistence Establishment, Recon to Credential, Lateral Movement, Injection Signature) with MITRE ATT&CK references
- `provenance` - instruction provenance tracing: links each HIGH/CRITICAL finding backward to the preceding ingestion event (file_read, web_fetch, browser_load, resource_read) most likely to have delivered the injected instruction; confidence-scored by temporal proximity and event distance
- `completion <shell>` - shell completions for bash, zsh, fish, PowerShell
- `version --check` - query GitHub Releases API for a newer version

**aspex-trace - client support**
- Added **Cline** (`saoudrizwan.claude-dev` VS Code extension) - parses `api_conversation_history.json` from extension globalStorage
- Added **Roo Code** (`rooveterinaryinc.roo-cline`) - same format as Cline

**Both tools**
- `Makefile` with `build`, `test`, `test-cover`, `lint`, `clean`, `install`, `completions`, `release-dry-run`, `vuln` targets
- `version --check` respects `ASPEX_NO_UPDATE_CHECK` environment variable

### Security

- Fixed `os.Exit(1)` in `checkTraceExitCode` - now returns `errTraceExitOne` sentinel so defers run before exit
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

## [0.1.0] - 2025-06-26

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
- Reads native log files from Claude Desktop, Claude Code CLI, Cursor, Windsurf - no proxy, no config change
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

[0.5.5]: https://github.com/aspex-security/aspex/releases/tag/v0.5.5
[0.5.4]: https://github.com/aspex-security/aspex/releases/tag/v0.5.4
[0.5.3]: https://github.com/aspex-security/aspex/releases/tag/v0.5.3
[0.5.2]: https://github.com/aspex-security/aspex/releases/tag/v0.5.2
[0.5.1]: https://github.com/aspex-security/aspex/releases/tag/v0.5.1
[0.5.0]: https://github.com/aspex-security/aspex/releases/tag/v0.5.0
[0.4.0]: https://github.com/aspex-security/aspex/releases/tag/v0.4.0
[0.3.4]: https://github.com/aspex-security/aspex/releases/tag/v0.3.4
[0.3.3]: https://github.com/aspex-security/aspex/releases/tag/v0.3.3
[0.3.2]: https://github.com/aspex-security/aspex/releases/tag/v0.3.2
[0.3.1]: https://github.com/aspex-security/aspex/releases/tag/v0.3.1
[0.3.0]: https://github.com/aspex-security/aspex/releases/tag/v0.3.0
[0.2.0]: https://github.com/aspex-security/aspex/releases/tag/v0.2.0
[0.1.0]: https://github.com/aspex-security/aspex/releases/tag/v0.1.0
