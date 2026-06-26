# Show HN: Two free CLI tools to audit your MCP setup (before and after)

**Title:** Show HN: aspex-scan and aspex-trace -- audit MCP servers before you trust them, trace what your agents actually did

---

**Body:**

I've been building security tooling for AI/agent infrastructure at Onyx, and two problems keep coming up whenever I talk to developers using MCP:

1. They have no idea what the MCP servers they installed are actually capable of. Copy-paste from a README, add to config, done. No review.

2. After an agent session, there is no unified view of what tools were called, what files were touched, or what left the machine.

So I built two small offline CLI tools to close both gaps.

**aspex-scan** reads your MCP client configs (Claude Desktop, Cursor, VS Code, Windsurf), connects to each server, enumerates tools, and produces a scored risk report. It checks for 26 things: prompt injection in tool descriptions, shell execution capability, secrets in plaintext env blocks, browser cookie/keychain access, cloud metadata endpoint references (169.254.169.254), persistence mechanisms (cron, LaunchAgent, rc files), unpinned @latest sources, and more. Everything maps to OWASP LLM Top 10, MITRE ATLAS, and CWE.

```
npx @aspex/scan
```

**aspex-trace** reads the native log files that Claude Desktop and Cursor already write to disk and parses them into a security-annotated audit trail. No proxy, no config change. It checks for 20 anomaly patterns: sensitive path access (.env, .ssh, .aws/credentials), outbound network calls, shell execution, cross-server data chains, persistence writes, off-hours activity, and more.

```
npx @aspex/trace
```

Both tools are fully offline. No data is sent anywhere. No account required. Apache-2.0. Binaries are cosign-signed with SLSA provenance.

When I run mcp-scan against my own laptop right now it flags my Cursor filesystem server for having a write_file tool with no path restrictions. That finding is real and I'm fixing it.

Would be curious what people find when they run it. Happy to explain any of the rule logic.

GitHub: https://github.com/aspex-security/aspex

---

**Anticipated questions:**

*"Isn't launching third-party MCP servers to inspect them itself risky?"*

Yes, and the README covers this. `--no-exec` does static analysis only (parse configs and package metadata, don't launch). The default behavior matches what your MCP client already does. We only call `tools/list`, never `tools/call`.

*"How is this different from Invariant's mcp-scan?"*

Invariant's tool phones home to an LLM API for analysis. Ours is fully offline, deterministic, and covers more clients. The scoring model and rule catalog are also substantially broader.

*"What's the business model?"*

These tools scan one machine at a time. [Onyx](https://onyx.security) does fleet-wide continuous monitoring, MCP gateway enforcement, and attack-path correlation. The OSS tools are genuinely free and will stay that way.
