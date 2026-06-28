# Aspex — MCP Security Scanner for VS Code

Inline security analysis for MCP server configurations using [aspex-scan](https://github.com/aspex-security/aspex).

## Requirements

Install aspex-scan first:
```
brew install aspex-security/tap/aspex
```

## Features

- **Scan on save**: automatically runs aspex-scan when you save an MCP config file
- **Problems panel**: findings appear as VS Code diagnostics with severity levels
- **Manual scan**: `Cmd+Shift+P` → "Aspex: Scan MCP Configuration"
- **Workspace scan**: scan all MCP config files in the workspace at once

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `aspex.binaryPath` | `aspex-scan` | Path to the aspex-scan binary |
| `aspex.scanOnSave` | `true` | Auto-scan when saving MCP config files |
| `aspex.minSeverity` | `medium` | Minimum severity to show (critical/high/medium/low) |
