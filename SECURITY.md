# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.5.x | Yes |
| 0.4.x | Yes |
| 0.3.x | Yes |
| 0.2.x | Yes |
| 0.1.x | Critical fixes only |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: [steven.d@onyx.security](mailto:steven.d@onyx.security)

Please include:
- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a minimal proof of concept.
- The version of the tool affected.
- Whether you believe this is being actively exploited.

We aim to acknowledge reports within 2 business days and to ship a fix within 14 days for confirmed vulnerabilities. We will credit reporters in the release notes unless you request otherwise.

---

## Threat model

### What these tools do

- `aspex-scan` reads MCP client config files from disk (read-only) and, by default, launches each configured stdio MCP server as a subprocess to call `initialize`, `tools/list`, `resources/list`, and `prompts/list`. It never calls `tools/call`.
- `aspex-trace` reads MCP client log files from disk (read-only).
- Neither tool modifies any file, sends any data to a remote endpoint, or persists state beyond the terminal session.

### Risks of running aspex-scan

**Launching third-party MCP servers is execution of third-party code.** This is the same thing your MCP client does when you use it. The risks and mitigations:

| Risk | Mitigation |
|---|---|
| A malicious server exploits the MCP client (these tools) | The tool only sends `initialize` and `*list` calls. It never sends `tools/call`. The attack surface is narrow. |
| A malicious server exfiltrates data via its own network connections once launched | Use `--no-exec` for static-only analysis. No server subprocess is started. |
| A malicious server modifies files on disk once launched | Run in a sandboxed environment (macOS Sandbox, Docker, gVisor) for untrusted servers. |

Use `--no-exec` if you do not trust the servers in your config. This flag skips subprocess launch entirely and performs static analysis only (config file parsing, package metadata, env key names).

### What these tools never do

- Never call `tools/call` on any MCP server.
- Never read env variable values from config files (only key names are inspected for patterns like `_SECRET`, `_TOKEN`, `_KEY`).
- Never send findings, configs, file paths, tool names, or any scan data to any remote endpoint.
- Never modify MCP client configs or log files.
- No telemetry. Both tools are fully offline; no data is ever sent anywhere.

### Supply chain

Release binaries are built with CGO disabled and reproducible build flags. Release binaries are distributed via Homebrew (formula verified by SHA-256 checksum) and GitHub Releases (SHA-256 checksums in checksums.txt). Cosign signing is planned for a future release.

Every release includes:

- SPDX SBOM (`sbom.spdx.json`)

Verify a release binary:

```sh
# Download checksums.txt from the release page, then:
sha256sum --check --ignore-missing checksums.txt
```

### Dependencies

Go module dependencies are pinned in `go.sum` and audited by:

- `govulncheck` in CI on every push and PR.

### CI/CD

The release pipeline runs in GitHub Actions with the following controls:

- NPM publish gated on the same signed release artifacts.

---

## Responsible disclosure history

No public disclosures to date. This section will be updated as issues are resolved.
