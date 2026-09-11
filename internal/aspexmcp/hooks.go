package aspexmcp

import "github.com/aspex-security/aspex/internal/hooks"

func hooksFromSettings(settingsJSON string) []hooks.Hook {
	return hooks.ParseBytes([]byte(settingsJSON), ".claude/settings.json", "project")
}
