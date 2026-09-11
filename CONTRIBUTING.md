# Contributing to Aspex

Thank you for taking the time to contribute. This project is open to community contributions under the Apache-2.0 license.

The highest-value contributions are:

1. **New aspex-scan rules** -- new patterns that catch real-world misconfigurations or malicious MCP server behaviors.
2. **New aspex-trace anomaly rules** -- new patterns that flag suspicious agent activity in logs.
3. **Log format updates** -- when a supported client ships a new version that changes its log format.
4. **New client support** -- config discovery or log parsing for a newly popular MCP client.
5. **Known-bad registry entries** -- documented findings on publicly available npm MCP packages.
6. **Bug reports with reproducible cases** -- especially false positives and missed detections.

---

## Fork & Branch Workflow

1. Fork the repo on GitHub.
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/aspex`
3. Create a branch: `git checkout -b feat/your-feature-name`
4. Make changes, run `make test`.
5. Push: `git push origin feat/your-feature-name`
6. Open a PR targeting `main` on `aspex-security/aspex`.

---

## Development setup

```sh
git clone https://github.com/aspex-security/aspex
cd aspex
go mod download
go test ./...

# Run aspex-scan in static mode against your own config
go run ./cmd/aspex-scan --no-exec

# Run aspex-trace against your local logs
go run ./cmd/aspex-trace
```

Requirements: Go 1.25 or later. No other dependencies needed for development.

---

## Adding a detection rule

Most rules match a tool name, description, or input schema against a list of
substrings. These are **data, not code**: add an entry to
[`internal/rules/catalog_rules.yaml`](internal/rules/catalog_rules.yaml) and a
corpus fixture. No Go, no recompiled logic to review.

```yaml
# under tools: (also resources: and prompts:)
  - id: MCP126
    name: Tool can disable transport security
    severity: high            # critical | high | medium | low | info
    fix: Remove tools that turn off certificate verification.
    mapping: OWASP LLM08, CWE-295, CWE-319
    tool_names:               # match any as a substring of the lowercased tool name
      - disable_tls
      - allow_insecure
    desc_words:               # ...or the description
      - disable certificate verification
    schema_keys:              # ...or the JSON input schema
      - '"insecure"'
```

`resources:` entries use `uri_words` / `mime_types`; `prompts:` use
`desc_words` / `name_words` / `min_len`. IDs must be unique; the loader panics
(and CI fails) on a duplicate id or an invalid severity.

Then add a corpus fixture that proves it fires (and, ideally, a benign fixture
that proves it does not over-fire) - see "Adding a corpus fixture" below. That
is the whole change: `go test ./...` runs your fixture against the rule.

**When a rule needs real logic** (regex, cross-field conditions, filesystem
scope), write Go instead:

1. Add a `checkMCPNNN` function to [`internal/rules/rules.go`](internal/rules/rules.go) returning `[]Finding`.
2. Call it from `EvalServer`.
3. Add positive and negative unit tests in [`internal/rules/rules_test.go`](internal/rules/rules_test.go).

**Rule doc page format:**

```markdown
# MCP027 -- Rule title

**Severity:** CRITICAL / HIGH / MEDIUM / LOW
**Frameworks:** OWASP LLM01, ATLAS AML.T0051, CWE-77

## What it detects

One paragraph.

## Why it matters

One paragraph.

## Example finding

(paste a realistic finding from the terminal output)

## Fix

Concrete remediation advice.
```

Rule IDs are assigned sequentially. Check existing rules before picking a number. If you are unsure whether a pattern belongs in the catalog, open an issue first.

**Finding fields:**

```go
rules.Finding{
    RuleID:   "MCP027",
    Name:     "Short title shown in the report",
    Severity: rules.SeverityHigh,
    Detail:   "One sentence explaining what was detected and why it is risky.",
    Fix:      "One sentence of remediation advice.",
    Mapping:  "OWASP LLM06, CWE-78",  // comma-separated framework refs
}
```

---

## Adding a capability, an attack path, or a client

The environment model is small on purpose. Before adding, check whether an
existing capability already covers the case.

- **Capability**: add a `Cap...` bit in `internal/attackpath/attackpath.go`
  (`AllCapabilities`, `String()`), classify the tool tokens that grant it in
  `classifyTool`, add static inference for well-known packages in
  `knownPackages` if applicable, and give it a human name in
  `agentenv.dangerousCaps` so drift reads well. Add a corpus scenario that
  expects it.
- **Attack path**: add an `APnnn` composition in `attackpath.detectChains`
  with Steps that name real tools, an Impact that never claims the path was
  used, a Remediation, and a severity that comes from what the composition
  reaches. Add a scenario under `testdata/corpus/scenarios/` that expects it
  and a `false-positive` scenario that must not report it.
- **Client (config discovery)**: see below; also add its project-level files
  to `agentenv.projectFiles` so `aspex diff` between revisions sees them, and
  to `agentenv.discoverInstructions` for user-level instruction files.
- **Trace parser**: see below; set `Event.Session` when the client records a
  session id so analysis stays per session.
- **Corpus scenario**: `testdata/corpus/README.md`.

---

## Adding an aspex-trace anomaly rule

Trace rules operate on `logparse.Event` values. Stateful rules can also update `*SessionState` to track patterns across multiple events.

**Steps:**

1. Add a check function to [`internal/trace/trace.go`](internal/trace/trace.go). Follow the naming convention `checkATNNN`.
2. Call it from `evalEvent` (or the stateful loop in `AnalyzeEvents` if cross-event state is needed).
3. Add a unit test in [`internal/trace/trace_test.go`](internal/trace/trace_test.go) with fixture log events.
4. Add fixture log lines to [`testdata/logs/`](testdata/logs/) if needed.
5. Add a doc page at [`docs/trace-rules/ATNNN.md`](docs/trace-rules/).

Stateful rules that track window-based patterns (error bursts, enumeration counts) should use the `SessionState` struct in `trace.go` rather than package-level state.

---

## Adding a new MCP client (aspex-scan discovery)

1. Add a client constant to [`internal/discover/discover.go`](internal/discover/discover.go).
2. Add a `clientConfigPaths` case with OS-specific paths.
3. Add a parser function (`parseXxx`) that reads the config format.
4. Add the client to `AllClients`.
5. Document the config path in [`docs/config-locations.md`](docs/config-locations.md) with the tested client version pinned.
6. Add fixture configs in [`testdata/configs/`](testdata/configs/).

Config parsers must never read env variable values, only key names. Env values stay on the user's machine.

---

## Adding a new MCP client (aspex-trace log parsing)

1. Create a parser file in [`internal/logparse/`](internal/logparse/) (e.g., `vscode.go`).
2. Export `ParseXxxLogReader(r io.Reader, since time.Time) ([]Event, error)` and `XxxLogPaths() []string`.
3. Wire it into [`cmd/aspex-trace/main.go`](cmd/aspex-trace/main.go).
4. Document the log format in [`docs/log-formats.md`](docs/log-formats.md) with the tested client version pinned.
5. Add fixture log files in [`testdata/logs/<client>/`](testdata/logs/).

Log format parsing is a maintenance surface. Always pin the tested client version in `docs/log-formats.md`. If a new client version changes the format, update the doc and add a new fixture.

---

## Adding a known-bad registry entry

The registry lives in [`internal/registry/registry.go`](internal/registry/registry.go) and [`data/known-bad.json`](data/known-bad.json). Both must be kept in sync.

Criteria for inclusion:

- The package is publicly available on npm (or another package registry).
- The finding is reproducible against the specified version.
- The finding represents a genuine security risk (not a stylistic concern).
- You have either reported the issue to the maintainer or confirmed the package is abandoned/malicious.

Entry format (JSON):

```json
{
  "package": "@scope/package-name",
  "version": "<1.2.3",
  "ruleIDs": ["MCP003", "MCP006"],
  "severity": "critical",
  "summary": "One sentence describing the vulnerability.",
  "fixedIn": "1.2.3",
  "cve": "CVE-2025-XXXXX",
  "reported": "2025-09-01"
}
```

If no fix exists yet, set `"fixedIn": ""`. CVE is optional.

---

## Adding a corpus fixture (highest-signal contribution)

`testdata/corpus/` is Aspex's detection contract. CI runs every fixture on every change:

- `malicious/*.json` - a server exhibiting a known attack pattern. Declares `expect_rules`: the rule IDs that **must** fire. A rule change that stops catching it fails CI.
- `benign/*.json` - a real, popular, well-behaved server (the official filesystem, GitHub, Slack, fetch servers, ...). Declares `max_severity`: the highest severity Aspex **may** report. A rule change that starts flagging it louder than that fails CI as a false positive.

Both kinds matter equally. A scanner nobody trusts on the servers they actually use is a scanner nobody runs.

```json
{
  "name": "official-fetch",
  "description": "Why this fixture exists and what severity is reasonable, in one or two sentences.",
  "entry": {"Name": "fetch", "Client": "claude", "Command": "uvx", "Args": ["mcp-server-fetch==2025.4.7"]},
  "tools": [
    {"name": "fetch", "description": "Fetches a URL from the internet.", "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}}
  ],
  "max_severity": "high"
}
```

Use the server's real tool names, descriptions, and schemas (copy them from `aspex-scan inventory --json`). For a malicious fixture, describe the pattern generically and keep the payload minimal - the point is the shape of the attack, not a working exploit.

Run `go test ./internal/rules/ -run TestCorpus -v` to see each fixture pass or fail individually.

---

## Pull request checklist

- [ ] `go test ./...` passes
- [ ] `go vet ./...` clean
- [ ] New rule has a unit test with a positive fixture (triggers) and a negative fixture (does not trigger)
- [ ] `docs/rules/` or `docs/trace-rules/` updated if adding a rule
- [ ] `docs/config-locations.md` or `docs/log-formats.md` updated if adding a client
- [ ] `data/known-bad.json` and `internal/registry/registry.go` updated in sync if adding a registry entry
- [ ] No em dashes introduced anywhere (see style guide below)
- [ ] No network calls, telemetry, or side effects added to rule or parser code

---

## Style guide

- **No em dashes** in code comments, help text, doc pages, or error messages. Use periods, commas, colons, or parentheses instead.
- **Comments explain why, not what.** Only add a comment when the reason for the code is non-obvious to a future reader.
- **No telemetry.** No network calls in rule, parser, or report code. The tools must work fully offline.
- **Tests must be deterministic.** Use fixture files in `testdata/`. Do not use live network calls, live filesystem paths outside the test's temp dir, or time-dependent behavior.
- **Stay local.** Everything runs on one machine against local configs and logs. Do not add features that need a server, an account, or a hosted service.

---

## Reporting security vulnerabilities

Please do not open a public GitHub issue for security vulnerabilities in this project. Email [steven.d@onyx.security](mailto:steven.d@onyx.security) instead. See [SECURITY.md](SECURITY.md) for the full policy.

## Maintainer contact

For questions not suited to a public issue, email [steven.d@onyx.security](mailto:steven.d@onyx.security).
