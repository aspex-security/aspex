package hook

import (
	"os"
	"path/filepath"
	"strings"
)

const hookScript = `#!/bin/sh
# BEGIN aspex-scan
MCP_FILES="claude_desktop_config.json mcp.json mcp_config.json settings.json cline_mcp_settings.json"
STAGED=$(git diff --cached --name-only 2>/dev/null)
FOUND=0
for f in $STAGED; do
  base=$(basename "$f")
  for mcp in $MCP_FILES; do
    if [ "$base" = "$mcp" ]; then
      FOUND=1
      break 2
    fi
  done
done
if [ "$FOUND" = "1" ]; then
  if command -v aspex-scan >/dev/null 2>&1; then
    aspex-scan --no-exec --fail-on high
    if [ $? -ne 0 ]; then
      echo "aspex-scan: MCP config scan failed. Commit blocked due to high severity findings." >&2
      exit 1
    fi
  else
    echo "aspex-scan: not found in PATH, skipping MCP config scan." >&2
  fi
fi
# END aspex-scan
`

const blockBegin = "# BEGIN aspex-scan"
const blockEnd = "# END aspex-scan"

func hookPath(repoPath string) string {
	return filepath.Join(repoPath, ".git", "hooks", "pre-commit")
}

// Install adds the pre-commit hook to the git repo at repoPath.
// If a hook already exists, it appends the MCP scan block rather than replacing.
func Install(repoPath string) error {
	path := hookPath(repoPath)

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	content := string(existing)

	if strings.Contains(content, blockBegin) {
		return nil
	}

	var newContent string
	if len(content) == 0 {
		newContent = hookScript
	} else {
		// Strip trailing newline to avoid double blank lines, then append block.
		trimmed := strings.TrimRight(content, "\n")
		// Extract just the block portion (without shebang) to append.
		block := extractBlock(hookScript)
		newContent = trimmed + "\n" + block + "\n"
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	if err := os.WriteFile(path, []byte(newContent), 0755); err != nil {
		return err
	}

	return nil
}

// extractBlock returns only the BEGIN/END delimited block from a hook script.
func extractBlock(script string) string {
	lines := strings.Split(script, "\n")
	var out []string
	inside := false
	for _, line := range lines {
		if strings.TrimSpace(line) == blockBegin {
			inside = true
		}
		if inside {
			out = append(out, line)
		}
		if strings.TrimSpace(line) == blockEnd {
			break
		}
	}
	return strings.Join(out, "\n")
}

// Uninstall removes the MCP scan block from the hook, or removes the file if it was the only content.
func Uninstall(repoPath string) error {
	path := hookPath(repoPath)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	content := string(data)
	if !strings.Contains(content, blockBegin) {
		return nil
	}

	lines := strings.Split(content, "\n")
	var out []string
	inside := false
	for _, line := range lines {
		if strings.TrimSpace(line) == blockBegin {
			inside = true
			// Remove trailing blank line before block if present.
			if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
				out = out[:len(out)-1]
			}
		}
		if !inside {
			out = append(out, line)
		}
		if inside && strings.TrimSpace(line) == blockEnd {
			inside = false
		}
	}

	result := strings.Join(out, "\n")
	trimmed := strings.TrimSpace(result)

	if trimmed == "" || trimmed == "#!/bin/sh" {
		return os.Remove(path)
	}

	return os.WriteFile(path, []byte(result), 0755)
}

// IsInstalled reports whether the hook is present in the repo at repoPath.
func IsInstalled(repoPath string) bool {
	data, err := os.ReadFile(hookPath(repoPath))
	if err != nil {
		return false
	}
	return strings.Contains(string(data), blockBegin)
}
