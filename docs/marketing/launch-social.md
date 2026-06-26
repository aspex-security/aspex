# Social copy -- launch day

## Twitter/X (thread)

**Tweet 1 (hook):**
```
we scanned the 50 most popular MCP servers on npm

here is what we found:

🧵
```

**Tweet 2:**
```
31 of 50 expose shell execution capability (run_command, exec, bash)

once an agent calls one of those tools, it has the same access as you

most developers have no idea their MCP setup looks like this
```

**Tweet 3:**
```
18 of 50 have secrets in plaintext env blocks in the client config

API keys, tokens, AWS credentials -- sitting in a JSON file on disk

any process with filesystem read access can grab them
```

**Tweet 4:**
```
11 of 50 use @latest with no version pin

that means next time the package author pushes a new version, your agent automatically runs it

no review, no diff, no warning
```

**Tweet 5:**
```
3 of 50 had prompt injection patterns in tool descriptions

"ignore previous instructions" -- in a tool description, not a user message

the model reads those descriptions before deciding what to do
```

**Tweet 6 (product):**
```
we built two free CLI tools to catch all of this:

aspex-scan: audit before you run
aspex-trace: see what ran after

fully offline, no account, apache-2.0

npx @aspex/scan
```

**Tweet 7 (CTA):**
```
run it on your own setup and reply with what you find

(we found something real on our own laptops while building this)

github: https://github.com/aspex-security/aspex
```

---

## LinkedIn post

```
Most developers wire MCP servers into their agents without reviewing what those servers can do.

I don't blame them. There has been no good tooling for this.

Until now.

We just open-sourced two security CLI tools built specifically for MCP:

aspex-scan scans your MCP client configs (Claude Desktop, Cursor, VS Code, Windsurf), connects to each server, and produces a scored risk report. It checks for 26 things: prompt injection in tool descriptions, shell execution capability, API keys in plaintext config, browser cookie access, persistence mechanisms, cloud metadata endpoint references, and more. Everything maps to OWASP LLM Top 10 and MITRE ATLAS.

aspex-trace reads the logs your MCP clients already write to disk and parses them into a security-annotated audit trail. No proxy, no config change. It catches sensitive file access (.env, .ssh, .aws/credentials), outbound network calls, cross-server data chains, persistence writes, and off-hours activity.

Both tools are fully offline. No data is sent anywhere. Free and open-source (Apache-2.0).

When I ran mcp-scan on my own laptop: my Cursor filesystem server flagged for shell execution capability and an unvalidated file write path. Real findings. Going to fix them.

Try it:
npx @aspex/scan
npx @aspex/trace

github.com/aspex-security/aspex

Would love to hear what you find on your own setup.
```

---

## r/LocalLLaMA post

**Title:** We built an open-source MCP security scanner + agent auditor. Free, fully offline, no account. Here's what it found on a typical dev setup.

**Body:**
```
Context: we build security infrastructure for AI at Onyx. We've been thinking about MCP security for a while and finally had time to extract something useful.

Two tools:

**aspex-scan** -- scans before you run
Reads your MCP client configs, connects to each server, enumerates tools, produces a scored risk report. Checks for 26 security issues mapped to OWASP LLM Top 10, MITRE ATLAS, and CWE:
- Prompt injection in tool descriptions (including hidden Unicode)
- Shell execution capability (run_command, eval, bash, powershell...)
- API keys in plaintext env blocks
- Browser cookie/keychain access
- Cloud metadata endpoint (169.254.169.254) in config
- Persistence mechanisms (cron, LaunchAgent, .bashrc writes)
- @latest unpinned packages
- Arbitrary code eval tools
- ...and 18 more

```npx @aspex/scan```

**aspex-trace** -- traces after it ran
Reads the native logs Claude Desktop and Cursor already write. No proxy, no config change. Flags sensitive file access, outbound network calls, cross-server data chains, persistence writes.

```npx @aspex/trace```

Both are fully offline, cosign-signed binaries, Apache-2.0.

I ran mcp-scan on my own setup and it immediately flagged my Cursor filesystem server. So it works.

Source: https://github.com/aspex-security/aspex

Happy to answer questions about the rule logic or threat model.
```

---

## OWASP Slack / security community post

```
Hi all -- we just open-sourced two MCP security tools that might be useful to people here.

Background: MCP is becoming the default way AI agents get tools. Developers are wiring servers into Claude Desktop, Cursor, VS Code with near-zero security review. The attack surface is real: prompt injection in tool descriptions, shell execution capability, secrets in plaintext configs, credential theft tools, persistence mechanisms.

aspex-scan is a CLI scanner that reads MCP client configs, connects to each server, enumerates tools, and scores them against 26 rules mapped to OWASP LLM Top 10 2025, MITRE ATLAS, and CWE.

aspex-trace is a CLI auditor that reads native client logs (Claude Desktop, Cursor) and produces a security-annotated event trail with 20 anomaly detection rules, including stateful detections (error bursts, cross-server data chains, mass file enumeration).

Both are offline by default, cosign-signed, Apache-2.0.

Repo: https://github.com/aspex-security/aspex

Would welcome feedback on the rule catalog from people doing AI/LLM security work. We tried to be conservative with severities but there are definitely gaps.
```
