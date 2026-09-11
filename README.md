<div align="center">

<img src="docs/logo.svg" width="88" height="88" alt="Aspex logo"/>

# Aspex

### See what your AI agents actually did. Then scan what they could do.

**Your AI coding agent made hundreds of tool calls this month. Do you know where they went?**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/aspex-security/aspex/actions/workflows/ci.yml/badge.svg)](https://github.com/aspex-security/aspex/actions/workflows/ci.yml)
[![MCP-scanned by Aspex](https://img.shields.io/badge/MCP--scanned-by%20Aspex-5B44C3)](https://github.com/aspex-security/aspex)

```sh
brew install aspex-security/tap/aspex && aspex     # or: npx aspex
```

**Offline. No account. One binary. Nothing leaves your machine. Ever.**

<img src="docs/snapshot.svg" width="820" alt="aspex snapshot: 320 tool calls in 30 days, 316 of them to servers no security scan had ever checked"/>

<sub>Real output from the maintainer's own machine, 1.9 seconds after typing <code>aspex</code>.</sub>

</div>

---

## Why this exists

Claude Code, Cursor, Windsurf and friends reach the world through **MCP servers** - programs that give the agent your filesystem, your GitHub, your database, your browser. Most people install them by pasting a config from a README.

Every MCP security tool so far answers one question: *what could this server do?* Aspex answers that too. But it started from the other one, the one nobody was answering:

**What did my agents actually do?**

Aspex reads the log files your AI clients already write. No proxy. No config change. It works on last month's sessions. Then it joins that with a static scan of every configured server, so you learn which risky servers are actually in use, and which servers your agents use that nothing has ever checked.

| | Tool | Question | How |
|---|---|---|---|
| **After** | `aspex-trace` | What did my agents do? | Reads native client logs. Reconstructs kill chains (credential read → outbound call), traces injected instructions back to their source. 85+ rules. |
| **Before** | `aspex-scan` | What can this environment do? | Every configured server, 140+ rules, a 0-100 score, and the compositions across servers that no single-server view can see. |
| **Both** | `aspex` | Show me. | The snapshot above, then a menu. `aspex share` gives you a privacy-safe card to post. |

---

## The finding a single-server scanner cannot make

You know your filesystem server reads files. You know your browser server reaches the internet. Aspex tells you what the two are together, with the evidence for each half. This is real output from the maintainer's machine:

```
  CRITICAL  AP001  Potential sensitive data exfiltration path  confidence: high
     filesystem
       └─ read_file: reads files by path
       └─ read_text_file: reads files by path
       └─ read_media_file: reads files by path
       └─ read_multiple_files: reads files by path
       └─ allowed root /Users/steven (home directory: includes ~/.ssh, ~/.aws, browser profiles)
       └─ and 5 more items (see --json)
     playwright
       └─ browser_navigate: reaches network destinations (takes a URL parameter)
       └─ browser_navigate_back: reaches network destinations
       └─ browser_network_request: reaches network destinations
       └─ browser_tabs: reaches network destinations (takes a URL parameter)
       └─ and 1 more item (see --json)

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

Severity comes from the composition, not from a keyword: the same filesystem server scoped to one project directory plus the same browser is HIGH, not CRITICAL, because the reachable files change. Confidence comes from the evidence: `high` when the tools were listed live, `medium` when inferred from a well-known package in a static scan. A capability on its own is never reported as a path.

The same reasoning finds the write that survives the session: a server that can modify `~/.claude.json`, `.mcp.json`, or `~/.claude/settings.json` hooks while another brings web content into the context is a **persistent agent compromise path**, because a modified MCP config runs code at the next session start without anyone asking again.

One critical path caps the score at 39 and fails `--fail-on high` in CI, even when every server looks fine on its own. [All six paths and their severity rules](https://aspex.mintlify.site/tools/scan#attack-paths).

---

## Sixty seconds

```sh
aspex                    # what your agents did this month, then the menu
aspex share              # same headlines, no names or paths - paste it anywhere
aspex-trace killchain    # multi-step attack patterns in your agent sessions
aspex-scan               # audit every configured MCP server (7 servers in ~7s)
aspex-scan doctor        # 2-second pre-flight: leaked secrets, broad paths, plaintext HTTP
```

Works with Claude Code, Claude Desktop, Cursor, Windsurf, Cline, Roo-Cline, Continue, and Zed. Claude Code's user, project, and plugin scopes are all read.

---

## Make it yours

```sh
aspex-scan init                                  # .aspex.yaml: accept a risk with a reason, set your own severities
aspex-scan --save-baseline aspex-baseline.json   # snapshot today's findings...
aspex-scan --baseline aspex-baseline.json        # ...then fail only on NEW ones
aspex-scan --with-trace                          # rank risky servers by how much your agents actually use them
```

Accepted risks need a reason and can expire, so nothing is silently forgotten. [Policy guide](https://aspex.mintlify.site/guides/policy).

## CI

```yaml
- uses: aspex-security/aspex/.github/actions/aspex-scan-action@main
  with:
    fail-on: high
```

Reads `.aspex.yaml` and your baseline from the repo. Emits SARIF for GitHub Code Scanning. [CI guide](https://aspex.mintlify.site/guides/ci-integration).

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
brew install aspex-security/tap/aspex                                                  # macOS / Linux
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
