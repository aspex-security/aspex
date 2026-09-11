# Aspex: current-state assessment

Updated 2026-09-11, before the "local security debugger" milestones. Concise by
design; the code is the detail.

## Existing functionality

- `aspex-scan`: discovers 9 clients' MCP configs, inspects servers live or
  statically, 150+ rules (116 as YAML data), 0-100 score, policy (.aspex.yaml),
  finding baseline, SARIF/JSON/HTML, `--with-trace` correlation, `hooks`,
  `doctor`, `inventory`, `shadow`, `phantom`, `redteam`, `diff --baseline`
  (finding-level), `--watch` (mtime poll + rescan), `cron`, pre-commit hook.
- `internal/attackpath`: evidence-backed capability model (bitmask, Evidence,
  FileScope from allowed roots, agent-state write targets) and six
  compositions AP001-AP006 with severity from composition, confidence from
  evidence. Feeds the default report, score cap, gate, policy, baseline.
- `aspex-trace`: parses 6 clients' logs, 85+ rules, per-session analysis,
  kill chains with OBSERVED/INFERRED/POSSIBLE evidence, provenance
  (ingestion -> suspicious call, timed confidence), behavioral baseline,
  live tail, export.
- `aspex` launcher: 30-day snapshot, menu, `share`, passthrough.
- Corpus: `testdata/corpus/{malicious,benign}` server fixtures with
  `expect_rules` / `max_severity`, run in CI.
- Release: GoReleaser, Homebrew, npm (OIDC), GitHub Actions (scan, trace).

## Strengths

- The capability + evidence model in `attackpath` is the right foundation:
  scoped, tested, conservative wording, static inference at lower confidence.
- Trace evidence semantics already separate observed from inferred.
- Detection contract (corpus) prevents regressions and false positives.
- Local-first is real: no network calls except downloads; no telemetry.

## Spec mapping (after this pass)

| Spec feature | Before | After |
|---|---|---|
| Normalized environment/capability graph | PARTIAL | EXISTS: `internal/agentenv` (servers, hooks, skills, instructions, resources, destinations, paths, blast radius; fingerprints; deterministic) |
| Skills discovery | MISSING | EXISTS: `internal/skills` |
| `aspex lock` | MISSING | EXISTS: schema v1, byte-identical, no secrets |
| `aspex verify` | MISSING | EXISTS: classified drift, `--fail-on` by class; registry lookup moved to `check-package` |
| `aspex diff` (security impact) | PARTIAL | EXISTS: revisions, lockfiles, lock vs now; Markdown; engine independent of git |
| PR / CI review | PARTIAL | EXISTS: `aspex-diff-action` (comment + gate); scan action unchanged |
| `aspex explain <question>` | MISSING | EXISTS: bounded queries, computed verdicts; server narrative kept |
| `aspex tighten` | MISSING | EXISTS: allowlists + roots, qualitative reduction, never edits |
| `aspex bom` | MISSING | EXISTS: tree + `aspex-asbom/v1`; CycloneDX/SPDX mapping documented, not claimed |
| `aspex mcp` | MISSING | EXISTS: read-only, six tools, `security_impact` for proposals |
| `aspex explore` | MISSING | EXISTS: loopback-only, embedded UI, dataset tested; frontend is vanilla JS, untested beyond serving |
| Corpus as scenario benchmark | PARTIAL | EXISTS: scenarios with truth/expect/must_not_report, `corpus test`, README |
| Capability-aware history | PARTIAL | EXISTS: environment snapshots + `history` |
| Watch integration | PARTIAL | EXISTS: drift printed between rescans (still mtime polling) |
| Finding evidence levels (scan) | PARTIAL | PARTIAL: paths and drift carry evidence; per-rule findings still Detail only |
| Blast radius | MISSING | EXISTS: level + reasons in scan, bom, diff, lock |

## Weak implementations / duplicated concepts

- Two notions of "baseline": finding baseline (`policy.Baseline`) and trace
  behavioral baseline (`internal/baseline`). Acceptable, but the new lockfile
  must not become a third; it is the environment fingerprint, and `diff
  --baseline` should sit beside it as the finding-level view.
- `internal/hook` (git pre-commit installer) vs `internal/hooks` (agent
  lifecycle hooks). Names are close; kept, documented.
- `history` parses old JSON with capitalized field names; brittle.

## Architecture decision

`internal/agentenv` is one deterministic `Environment` assembled from the
existing detectors (attackpath for servers, hooks, skills, instruction files)
with fingerprints, destinations, blast radius and attack paths. lock, verify,
diff, explain, tighten, bom, mcp, explore, history and watch all consume this
one model. Nothing existing was rewritten; attackpath stays the capability
engine, and `report` stays below `agentenv` (it has its own small
`BlastRadius` type to avoid an import cycle).

## Remaining

- Cursor and Windsurf have no hook system today; when they grow one, add it to
  `internal/hooks` and the environment model.
- CycloneDX export covers servers, destinations, hooks, skills and attack
  paths; capabilities and scope ride as properties by design.

## Debugger phase (simulate, data flow, explain, reproduction)

Added on top of the environment model, reusing it:

| Capability | State |
|---|---|
| `aspex simulate` (counterfactual) | NEW: clone inputs, apply hypotheticals, rebuild, compare. Side-effect free (tested). |
| Data-flow queries (`explain "where could data from X go"` / "what could reach Y") | NEW: forward and reverse over the same graph; REACHABLE / POTENTIAL / OBSERVED. |
| `explain <finding-id>` | NEW: stable per-path definitions, evidence, and simulated path-breaking controls. |
| `explain "…?"` with "what breaks this path" | IMPROVED: every YES ends with concrete controls, each simulated. |
| Path-breaking controls (remediation engine) | NEW: one engine feeds explain, diff, tighten, PR review, MCP, explorer. |
| `diff` | IMPROVED: Markdown leads with the story and a recommended fix from the control engine. |
| `tighten` | IMPROVED: each recommendation carries its simulated security impact and honest functional note. |
| `aspex inspect <cmd|path>` | IMPROVED: environment-aware pre-install inspection via the simulator; static by default, never executes packages. |
| `aspex-trace repro create` / `replay` | NEW: redacted, analysis-only reproduction bundles; malicious bundles refused. |
| `corpus import` | NEW: bundle -> scenario skeleton (home anonymized). |
| `explore` | IMPROVED: trust-boundary lanes, data-flow view, persistence/session boundary, per-path controls, colour-independent evidence, escaped untrusted content. |
| `aspex mcp` | IMPROVED: simulate_change, explain_path, data_flow (read-only). |
| Terminal hardening | IMPROVED: OSC escape stripping; adversarial-content tests. |

The moat is now the combination working off one model: what CAN happen (scan),
what DID (trace), what CHANGED (diff), WHY (explain, data flow), WHAT IF
(simulate), reproduced safely (repro) and benchmarked (corpus).
