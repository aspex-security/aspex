# MCP Client Log Formats

This document describes the log format and parsing strategy for each supported client.
Tested client versions are pinned here and should be updated when parsers are re-validated.

## Claude Desktop

**Tested version:** Claude Desktop v0.10.x (macOS)
**Log directory (macOS):** `~/Library/Logs/Claude/`
**Log directory (Windows):** `%APPDATA%\Claude\Logs\`
**Files:** `mcp*.log` (one file per server plus a general MCP log)

**Format:** newline-delimited JSON. Each line is an object:

```json
{
  "timestamp": "2026-06-25T10:31:02Z",
  "level": "info",
  "message": "[server-name] tools/call",
  "data": {
    "toolName": "read_file",
    "serverName": "filesystem-mcp",
    "arguments": { "path": "/some/path" }
  }
}
```

Parsing strategy:
- Parse `timestamp` as RFC3339.
- Infer event type from `message` string (contains "initialize", "tools/call", etc.).
- Extract server name from bracketed prefix in `message` (`[server-name]`) or from `data.serverName`.
- Tool call args come from `data.arguments` (flat string values).

## Cursor

**Tested version:** Cursor v0.48.x (macOS)
**Log directory (macOS):** `~/.cursor/logs/` or `~/Library/Application Support/Cursor/logs/`
**Log directory (Windows):** `%APPDATA%\Cursor\logs\`
**Files:** `*mcp*.log`

**Format:** newline-delimited JSON. Each line is an object:

```json
{
  "timestamp": "2026-06-25T10:31:02Z",
  "level": "info",
  "category": "mcp",
  "serverName": "filesystem-mcp",
  "method": "tools/call",
  "toolName": "read_file",
  "arguments": { "path": "/some/path" },
  "durationMs": 41
}
```

Parsing strategy:
- Parse `timestamp` as RFC3339.
- Use `method` field directly for event type mapping.
- `serverName` and `toolName` are top-level fields.
- `arguments` may be a nested object; values are stringified for the unified model.
- `durationMs` is mapped to `DurationMS`.

## Maintenance notes

- Log formats can change without warning on client updates. When a client ships a major version, re-run the fixture tests and update the tested version above.
- The `testdata/logs/` fixtures are synthetic but match the exact schema above.
- aspex-trace reads these files read-only and never modifies them.
