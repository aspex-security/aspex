<div align="center">

# Aspex

### Know what your agents can do. Know what they actually did.

A local security debugger for AI agents. Offline, deterministic, one binary.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/aspex-security/aspex/actions/workflows/ci.yml/badge.svg)](https://github.com/aspex-security/aspex/actions/workflows/ci.yml)
[![Rules](https://img.shields.io/badge/rules-225%2B-ec3013)](https://aspex.mintlify.site/reference/rules)

```sh
brew install aspex-security/tap/aspex && aspex     # or: npx aspex
```

<img src="docs/hero.svg" width="960" alt="aspex with no arguments: what your agents did in the last 30 days, joined with the risk of each configured server">

<sub>Real output from the maintainer's machine. 2.3 seconds, nothing sent anywhere.</sub>

</div>

## Why

Your coding agent reaches the world through MCP servers, skills and hooks. Each one looks fine alone. A filesystem server scoped to your home directory next to a browser server is a path from `~/.ssh` to any URL an injected instruction chooses. Aspex reasons about them **together**, from the configs and logs already on your machine.

No proxy. No LLM. No SaaS. Dependabot tells you when dependencies change; Aspex tells you when your agent's *capabilities* change.

## Three questions

| Question | Run | You get |
|---|---|---|
| **What can my agents do?** | `aspex scan`<br>`aspex explain "…"` | Every server, tool, hook and skill; cross-server attack paths with evidence; yes/no answers computed from the capability graph. [Docs →](https://aspex.mintlify.site/tools/scan) |
| **What did they actually do?** | `aspex trace`<br>`aspex explore` | Tool calls from your clients' own logs; kill chains and provenance labeled OBSERVED / INFERRED / POSSIBLE. [Docs →](https://aspex.mintlify.site/tools/trace) |
| **What changed?** | `aspex lock` / `verify`<br>`aspex diff main..HEAD` | New tools, poisoned descriptions, wider scope, new attack paths. Exit 1 in CI on drift you did not accept. [Docs →](https://aspex.mintlify.site/tools/change-detection) |

Then `aspex tighten` turns what your agents actually used into least-privilege allowlists. It recommends; it never edits your config.

## What a finding looks like

Every server below is an official, well-behaved package. The problem is the composition:

```
$ aspex scan

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

     Fix
       scope filesystem to specific project directories instead of
       /Users/steven; constrain playwright to an allowlist of
       destinations. Either change alone removes the path.
```

Nothing here claims the path was walked; that is `aspex trace`'s job. [More real output: explain, diff, trace →](https://aspex.mintlify.site/quickstart)

## Why you can trust it

- **Offline.** No account, no telemetry. The only network call is the download.
- **Deterministic.** Two runs over the same state produce byte-identical output. Answers are computed from the capability graph, never generated.
- **Under contract.** `testdata/corpus/` holds malicious servers that **must** fire and popular real servers that **must not**. CI runs both on every change.
- **Honest about limits.** Not a proxy, not a blocker. Cloud connectors it cannot scan are shown as "in use, never scanned" rather than hidden.

## Install

```sh
brew install aspex-security/tap/aspex                                                  # macOS
npx aspex                                                                              # anywhere with Node
curl -fsSL https://raw.githubusercontent.com/aspex-security/aspex/main/install.sh | sh  # Linux / WSL
```

Or a static binary from [Releases](https://github.com/aspex-security/aspex/releases). Every release ships SHA-256 checksums and an SPDX SBOM.

## Docs

| | | |
|---|---|---|
| [**Quickstart**](https://aspex.mintlify.site/quickstart)<br><sub>First scan in a minute</sub> | [**How Aspex reasons**](https://aspex.mintlify.site/concepts/how-aspex-reasons)<br><sub>Capabilities, paths, confidence</sub> | [**CI integration**](https://aspex.mintlify.site/guides/ci-integration)<br><sub>Gate PRs on security drift</sub> |
| [**Commands**](https://aspex.mintlify.site/tools/launcher)<br><sub>scan · trace · explain · lock · diff · tighten · bom · mcp</sub> | [**Rules**](https://aspex.mintlify.site/reference/rules)<br><sub>225+ rules, OWASP / ATLAS / CWE</sub> | [**Let your agent ask Aspex**](https://aspex.mintlify.site/tools/mcp)<br><sub>Read-only MCP server</sub> |

## Contributing

The most valuable PR is a corpus fixture: a malicious pattern Aspex should catch, or a popular server it should leave alone. About 15 minutes. See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: email steven.d@onyx.security, not a public issue.

Apache-2.0. Free forever, and it stays offline.
