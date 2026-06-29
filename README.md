<div align="center">

<img src="docs/logo.svg" width="88" height="88" alt="Aspex logo"/>

# Aspex

### AI Agent Security Toolkit

**Scan your MCP servers before you trust them. Audit what your agents actually did.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/aspex-security/aspex/actions/workflows/ci.yml/badge.svg)](https://github.com/aspex-security/aspex/actions/workflows/ci.yml)
[![MCP-scanned by Aspex](https://img.shields.io/badge/MCP--scanned-by%20Aspex-5B44C3)](https://github.com/aspex-security/aspex)

```sh
brew install aspex-security/tap/aspex
```

**Offline. No account. No data leaves your machine. Ever.**

</div>

---

## What is Aspex?

Aspex is an open-source security toolkit for developers using AI coding agents. It covers the complete attack surface of any MCP-powered workflow - from static config analysis to live runtime auditing.

You wired an MCP server into Claude Code or Cursor. You copy-pasted the config from a README. The agent now has access to your filesystem, your GitHub, your browser. Do you know what that server is actually capable of? Do you know what it did the last time your agent ran?

Aspex is the answer to both questions.

| Tool | What it does |
|---|---|
| `aspex-scan` | Static analysis of MCP server configurations - 140+ rules, 0-100 security score |
| `aspex-trace` | Runtime audit of AI agent activity logs - no proxy, no config change |
| `aspex-attack` | Active red-teaming of live MCP tools with adversarial payloads |
| `aspex-doctor` | Fast local health check for your AI agent setup (~2 seconds) |

Run `aspex` for an interactive launcher that puts all four tools at your fingertips.

---

## Quick start

```sh
# Scan every MCP server configured on this machine
aspex-scan

# Check what your agent did in the last 24 hours
aspex-trace

# Quick health check of your AI setup
aspex-doctor

# Interactive menu (arrow keys)
aspex
```

---

## Install

```sh
# macOS / Linux (recommended)
brew install aspex-security/tap/aspex

# Linux / Windows WSL
curl -fsSL https://raw.githubusercontent.com/aspex-security/aspex/main/install.sh | sh

# Manual: download a binary from GitHub releases
# https://github.com/aspex-security/aspex/releases
```

---

## Documentation

Full reference, guides, and examples at **[docs.aspex.security](https://docs.aspex.security)**

- [aspex-scan reference](https://docs.aspex.security/tools/scan)
- [aspex-trace reference](https://docs.aspex.security/tools/trace)
- [aspex-attack reference](https://docs.aspex.security/tools/attack)
- [aspex-doctor reference](https://docs.aspex.security/tools/doctor)
- [CI integration guide](https://docs.aspex.security/guides/ci-integration)
- [Daily workflow guide](https://docs.aspex.security/guides/daily-workflow)

---

## Privacy

Aspex never sends configs, findings, file paths, or tool names anywhere. No telemetry. No account. No proxy. The only network call is downloading the binary at install time.

Every release ships SHA-256 checksums and a full SPDX software bill of materials.

For fleet-wide coverage and enterprise policy enforcement, see [Onyx Security](https://onyx.security).

---

## Contributing

The most impactful contributions are new detection rules and log format updates as clients evolve. Adding a rule takes about 15 minutes - see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache-2.0. See [LICENSE](LICENSE). Built and maintained by [Onyx Security](https://onyx.security). Free forever.
