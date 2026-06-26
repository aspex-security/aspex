# Contributing to Aspex

Thank you for taking the time to contribute. This project is maintained by [Onyx Security](https://onyx.security) and open to community contributions under the Apache-2.0 license.

The highest-value contributions are:

1. **New aspex-scan rules** -- new patterns that catch real-world misconfigurations or malicious MCP server behaviors.
2. **New aspex-trace anomaly rules** -- new patterns that flag suspicious agent activity in logs.
3. **Log format updates** -- when a supported client ships a new version that changes its log format.
4. **New client support** -- config discovery or log parsing for a newly popular MCP client.
5. **Known-bad registry entries** -- documented findings on publicly available npm MCP packages.
6. **Bug reports with reproducible cases** -- especially false positives and missed detections.

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

Requirements: Go 1.24 or later. No other dependencies needed for development.

---

## Adding an aspex-scan rule

Each rule is a deterministic check that takes a server or tool as input and returns zero or more `Finding` values. Rules must be offline (no network calls), side-effect free, and deterministic.

**Steps:**

1. Add a check function to [`internal/rules/rules.go`](internal/rules/rules.go). Follow the naming convention `checkMCPNNN`. Return `[]Finding`.
2. Call it from `EvalServer` or `evalTool` as appropriate.
3. Add a unit test in [`internal/rules/rules_test.go`](internal/rules/rules_test.go) with at least one fixture that triggers the rule and one that does not.
4. Add a fixture config in [`testdata/configs/`](testdata/configs/) if the test requires a config file.
5. Add a doc page at [`docs/rules/MCPNNN.md`](docs/rules/).

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
- **Keep the OSS/paid line.** Discovery, inspection, scoring, and audit on one machine: OSS. Continuous, fleet-wide, enforcing: Onyx Security SaaS. Do not add features that blur this line.

---

## Reporting security vulnerabilities

Please do not open a public GitHub issue for security vulnerabilities in this project. Email [steven.d@onyx.security](mailto:steven.d@onyx.security) instead. See [SECURITY.md](SECURITY.md) for the full policy.

## Maintainer contact

For questions not suited to a public issue, email [steven.d@onyx.security](mailto:steven.d@onyx.security).
