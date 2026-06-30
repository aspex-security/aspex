<div align="center">

<img src="docs/logo.svg" width="88" height="88" alt="Aspex logo"/>

# Aspex

### MCP Security Toolkit

**Know what your MCP servers can do. Know what your agents actually did.**

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

Aspex is an open-source security toolkit for developers using AI coding agents. It answers two questions every MCP user should be asking:

You wired an MCP server into Claude Code or Cursor. You copy-pasted the config from a README. The agent now has access to your filesystem, your GitHub, your browser.

**Do you know what that server is actually capable of? Do you know what it did the last time your agent ran?**

| Tool | What it does |
|---|---|
| `aspex-scan` | Static analysis of every MCP server on your machine - 140+ rules, 0-100 security score, cross-server attack paths |
| `aspex-trace` | Runtime audit of your AI agent logs - reconstructs kill chains, traces instruction provenance, no proxy required |

---

## Quick start

Run `aspex` for an interactive menu - arrow keys to navigate, enter to run:

```sh
aspex
```

Or run directly:

```sh
aspex-scan               # Audit every MCP server on this machine
aspex-scan doctor        # Pre-flight health check (~2 seconds)
aspex-trace              # Review what your agent did in the last 24 hours
aspex-trace killchain    # Reconstruct multi-step attack patterns
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

Full reference, guides, and examples at **[aspex.mintlify.site](https://aspex.mintlify.site)**

- [aspex-scan reference](https://aspex.mintlify.site/tools/scan)
- [aspex-trace reference](https://aspex.mintlify.site/tools/trace)
- [CI integration guide](https://aspex.mintlify.site/guides/ci-integration)
- [Daily workflow guide](https://aspex.mintlify.site/guides/daily-workflow)

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
