# aspex

See what your AI agents actually did, then scan what they could do.

```sh
npx aspex
```

Shows a 30-day snapshot of every MCP tool call your agents made (from the logs Claude Code, Claude Desktop, Cursor, Windsurf, Cline and Roo already write), how many went to servers no scan has checked, and the security score of every configured server. Then a menu.

```sh
npm install -g aspex
aspex            # snapshot + menu
aspex share      # privacy-safe card to paste anywhere
aspex-scan       # audit every configured MCP server, 140+ rules
aspex-trace      # full audit trail from your clients' logs
```

This package downloads the prebuilt binary for your platform from the matching [GitHub release](https://github.com/aspex-security/aspex/releases) and verifies its SHA-256 against the release's `checksums.txt`. It fetches nothing else. Aspex itself runs fully offline: no account, no telemetry, nothing leaves your machine.

Docs: https://aspex.mintlify.site
