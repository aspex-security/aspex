# MCP Client Config Locations

This document lists the exact paths where each MCP client stores its server configuration, per OS.

## Claude Desktop

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `$XDG_CONFIG_HOME/Claude/claude_desktop_config.json` (default: `~/.config/Claude/claude_desktop_config.json`) |

Format: JSON with a top-level `mcpServers` object. Each key is the server name; value has `command`, `args`, `env`.

## Cursor

| OS | Path |
|---|---|
| macOS / Linux | `~/.cursor/mcp.json` |
| Windows | `%APPDATA%\Cursor\User\mcp.json` |

Also supports per-project `.cursor/mcp.json` in the workspace root. Format is identical to Claude Desktop.

## VS Code / GitHub Copilot

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/Code/User/settings.json` |
| Windows | `%APPDATA%\Code\User\settings.json` |
| Linux | `$XDG_CONFIG_HOME/Code/User/settings.json` |

MCP servers are nested under `"github.copilot.mcp.servers"` (or similar, pending VS Code release). Per-workspace: `.vscode/mcp.json`.

## Windsurf

| OS | Path |
|---|---|
| macOS / Linux | `~/.codeium/windsurf/mcp_config.json` |
| Windows | `%APPDATA%\Windsurf\User\mcp_config.json` |

Format mirrors Claude Desktop.

## Notes

- aspex-scan reads these paths read-only and never modifies them.
- The `env` block values are never read or reported; only key names are surfaced in findings.
- Paths were verified against client versions pinned in `testdata/configs/`.
