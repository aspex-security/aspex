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

## Missing pieces (spec mapping)

| Spec feature | Status | Notes |
|---|---|---|
| Normalized environment/capability graph | PARTIAL | `attackpath.ServerCapabilities` covers servers. No shared model that also holds hooks, skills, instructions, destinations, blast radius; each command re-derives. |
| Skills discovery | MISSING | Hooks yes (`internal/hooks`), skills no. |
| `aspex lock` | MISSING | `inventory --json` is the closest; no fingerprints, no schema version, not designed for diffing. |
| `aspex verify` (drift) | MISSING | `aspex-scan verify` today = known-bad registry lookup. Name clash to resolve. `diff --baseline` compares findings, not capabilities. |
| `aspex diff` (security impact) | PARTIAL | `internal/diff` compares finding sets. No capability/scope/path/blast-radius diff, no git revisions, no markdown. |
| PR/CI security review | PARTIAL | Scan action uploads SARIF and gates on severity. No capability diff comment. |
| `aspex explore` | MISSING | |
| `aspex explain <question>` | MISSING | `aspex-scan explain <server>` prints a per-server narrative. Different thing; keep both under one command. |
| `aspex tighten` | MISSING | `--with-trace` shows usage per server; no recommendations. |
| `aspex bom` | MISSING | |
| `aspex mcp` (read-only) | MISSING | |
| Corpus as scenario benchmark | PARTIAL | Server-level fixtures only; no environment scenarios with expected capabilities/paths/forbidden findings; no TP/FN/FP summary command. |
| Capability-aware history | PARTIAL | `internal/history` stores score deltas only. |
| Watch integration | PARTIAL | Rescans on mtime; reports findings, not drift. |
| Finding evidence levels | EXISTS (trace) / PARTIAL (scan) | Attack paths carry evidence; per-rule findings carry Detail only. |
| Blast radius | MISSING | One number (score) with a cap reason. |

## Weak implementations / duplicated concepts

- Two notions of "baseline": finding baseline (`policy.Baseline`) and trace
  behavioral baseline (`internal/baseline`). Acceptable, but the new lockfile
  must not become a third; it is the environment fingerprint, and `diff
  --baseline` should sit beside it as the finding-level view.
- `internal/hook` (git pre-commit installer) vs `internal/hooks` (agent
  lifecycle hooks). Names are close; kept, documented.
- `history` parses old JSON with capitalized field names; brittle.

## Architecture decision for this pass

Introduce `internal/agentenv`: one deterministic `Environment` assembled from
the existing detectors (attackpath for servers, hooks, new skills discovery,
instruction files) with fingerprints, destinations, blast radius and attack
paths. Every new command (lock, verify, diff, explain, tighten, bom, mcp,
explore's graph view) consumes this one model. Nothing existing is rewritten;
attackpath stays the capability engine.

## Implementation priorities

1. agentenv + skills discovery + blast radius (foundation).
2. lock / verify / diff (+ markdown for PRs, git revisions).
3. explain (deterministic queries over agentenv).
4. tighten (agentenv + trace activity).
5. bom, mcp (read-only), explore (loopback, embedded UI).
6. corpus scenarios + runner; history/watch integration; CLI unification;
   README/docs.
