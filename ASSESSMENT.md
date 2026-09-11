# Aspex engineering assessment

Date: 2026-09-11. Baseline: v0.6.1 (commit 0546e49). Kept deliberately short;
this document exists to justify implementation choices, not to replace them.

## Current architecture

Go, two dependencies (cobra, yaml). Five binaries share `internal/`:

```
cmd/aspex-scan      discover -> inspect (parallel) -> rules -> score -> report
cmd/aspex-trace     logparse -> trace rules / killchain / provenance -> report
cmd/aspex           snapshot (scan x trace join) -> TUI
internal/discover   9 client config formats -> ServerEntry (name, cmd, args, env keys, url)
internal/inspect    connects to a server (stdio/HTTP) or stays static -> Server{Entry, Tools}
internal/rules      152 scan rules: 36 hand-written checks + 116 table-driven substring rules
internal/attackpath capability bitmask per server -> pairwise "chains"
internal/score      per-server deductions, worst-weighted overall
internal/trace      85 per-event rules + 3 stateful; killchain, provenance separate
internal/policy     .aspex.yaml ignore/severity/fail_on, finding baseline
internal/correlate  joins scan servers with trace activity by normalized name
```

Adding a rule: a Go function or a table row plus a test. Adding a client: a
path function and a parser. Adding a trace source: a parser returning
`logparse.Event`. All three are straightforward. There is no normalized
capability model: `rules` reasons about tools directly, `attackpath` has its
own bitmask, `trace` has its own name lists. The same idea ("this tool sends
data out") is encoded three times with three different word lists.

## Strengths

- Local-first, offline, single binary. Nothing to deploy, nothing phones home.
- Discovery covers every mainstream client, including Claude Code's three scopes.
- Trace from native logs with no proxy is genuinely differentiated; killchain
  and provenance already reason about sequences and sources.
- Policy, baseline, corpus tests, e2e tests, CI lint gates: the project has a
  contract with its users about what it will and will not flag.

## Weaknesses (ordered by security impact)

1. **Attack-path analysis is the most valuable idea in the codebase and the
   weakest implementation.** Any `read_file` plus any tool whose name contains
   `fetch`, `http`, or `request` is CRITICAL "Data Exfiltration", regardless of
   the filesystem server's allowed roots. The official filesystem server scoped
   to one project plus the official fetch server, a normal setup, scores
   CRITICAL. A shell-exec server alone is reported as a "chain". Steps contain
   attacker fiction rather than evidence. Substring matching turns a
   `user_profile` tool into "persistence". There are no tests. And none of it
   reaches the default `aspex-scan` output, the score, or `--fail-on`.
2. **Capability is conflated with risk.** MCP006 rates any token-shaped env key
   CRITICAL; every legitimate GitHub or Slack server with a token scores 39.
   Severity is deducted per finding, so ten informational findings outweigh a
   real composition.
3. **No persistence model.** Nothing asks whether the agent can rewrite its
   own instructions (`CLAUDE.md`, `.cursorrules`), its own MCP config
   (`.mcp.json`, `~/.claude.json`), or its hooks (`~/.claude/settings.json`).
   Those are the writes that survive the session.
4. **Trace conclusions do not distinguish observed from inferred.** Kill chain
   descriptions read as fact ("was read, then an outbound call") which is
   observed, but "possible exfiltration" and "prompt injection signature" are
   inferences presented in the same voice.
5. Static (`--no-exec`) scans know nothing about capabilities because
   capabilities are derived from tool lists only, even for the well-known
   official servers whose capabilities are fixed.

## Highest-value improvements

1. Rebuild attack paths on evidence: capability + scope + egress class,
   severity from the composition, confidence from the evidence quality,
   remediation that names the specific roots and tools. Surface in the default
   scan, the score, JSON, and the gate. Infer capabilities for well-known
   packages so static scans and the snapshot benefit.
2. Persistence as a first-class target: writable agent config, instructions,
   hooks, and memory, distinguished by whether writing them yields code
   execution on the next session.
3. Score: a composition caps the score; informational findings do not sink it.
4. Trace: OBSERVED / INFERRED / POSSIBLE labeling in killchain output.

## Implementation priorities for this pass

P0: items 1 and 2 above with tests, default-scan integration, README.
P1: item 3 (score cap) alongside, since it is small and makes 1 matter for CI.
P2: item 4 if time remains; otherwise documented in the roadmap.
