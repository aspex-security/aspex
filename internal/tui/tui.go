// Package tui implements the interactive launcher menu for the Aspex toolkit.
package tui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

// ANSI escape codes.
const (
	reset     = "\033[0m"
	bold      = "\033[1m"
	dim       = "\033[2m"
	purple    = "\033[35m"
	brPurple  = "\033[95m"
	cyan      = "\033[36m"
	brCyan    = "\033[96m"
	red       = "\033[31m"
	yellow    = "\033[33m"
	green     = "\033[32m"
	brGreen   = "\033[92m"
	white     = "\033[97m"
	hideCursor = "\033[?25l"
	showCursor = "\033[?25h"
	clearScr   = "\033[2J\033[H"
	saveCursor = "\033[s"
	restCursor = "\033[u"
)

// Option is a quick-launch action inside a tool's submenu.
type Option struct {
	Label string
	Args  []string
	Hint  string
}

// Item is a top-level menu entry (one per tool).
type Item struct {
	ID          string
	Binary      string   // the binary to exec (e.g. "aspex-scan")
	Label       string
	TagLine     string
	Description string
	Options     []Option
}

var items = []Item{
	{
		ID:          "scan",
		Binary:      "aspex-scan",
		Label:       "SCAN",
		TagLine:     "Audit MCP server configurations",
		Description: "Static analysis across 250+ rules.\nFinds prompt injection, credential exposure,\nsupply chain risks, and cross-server attack paths.",
		Options: []Option{
			{Label: "Full scan", Args: nil, Hint: "Scan all clients on this machine"},
			{Label: "With --explain", Args: []string{"--explain"}, Hint: "Show why each finding is dangerous"},
			{Label: "Static only  (fast)", Args: []string{"--no-exec"}, Hint: "Parse configs without launching servers"},
			{Label: "Attack paths", Args: []string{"attack-paths"}, Hint: "Map cross-server capability chains"},
			{Label: "Inventory", Args: []string{"inventory"}, Hint: "List every server and tool"},
			{Label: "Shadow detection", Args: []string{"shadow"}, Hint: "Find tool name collisions"},
			{Label: "Phantom detection", Args: []string{"phantom"}, Hint: "Detect clean-face attacks"},
		},
	},
	{
		ID:          "trace",
		Binary:      "aspex-trace",
		Label:       "TRACE",
		TagLine:     "Review AI agent activity logs",
		Description: "Reads native client logs. No agents.\nFinds kill chains, session anomalies,\nand instruction provenance.",
		Options: []Option{
			{Label: "Last 24 hours", Args: nil, Hint: "Default audit window"},
			{Label: "Last 7 days", Args: []string{"--since", "7d"}, Hint: "Broader history"},
			{Label: "Kill chains", Args: []string{"killchain"}, Hint: "Reconstruct multi-step attack patterns"},
			{Label: "Provenance", Args: []string{"provenance"}, Hint: "Trace findings back to injected content"},
			{Label: "Session forensics", Args: []string{"session"}, Hint: "Timeline of a specific session"},
			{Label: "Live mode", Args: []string{"live"}, Hint: "Real-time monitoring"},
			{Label: "Export to JSONL", Args: []string{"export", "--format", "jsonl"}, Hint: "For SIEM / custom analysis"},
		},
	},
	{
		ID:          "attack",
		Binary:      "aspex-attack",
		Label:       "ATTACK",
		TagLine:     "Red team your live MCP servers",
		Description: "Actively probes live tools with adversarial\npayloads. Tests prompt injection, path traversal,\nSSRF, error disclosure, and prompt leakage.",
		Options: []Option{
			{Label: "All probes", Args: nil, Hint: "Full adversarial test suite"},
			{Label: "Prompt injection", Args: []string{"--categories", "prompt-injection"}, Hint: "Injection payload battery"},
			{Label: "Path traversal", Args: []string{"--categories", "path-traversal"}, Hint: "File system escape attempts"},
			{Label: "SSRF", Args: []string{"--categories", "ssrf"}, Hint: "AWS/GCP metadata + internal endpoints"},
			{Label: "Error disclosure", Args: []string{"--categories", "error-disclosure"}, Hint: "Stack traces and internal paths"},
			{Label: "JSON output", Args: []string{"--json"}, Hint: "Machine-readable results"},
		},
	},
}

// keyEvent represents a terminal key press.
type keyEvent int

const (
	keyUp keyEvent = iota
	keyDown
	keyRight
	keyLeft
	keyEnter
	keyEsc
	keyQuit
	keyUnknown
)

func readKey(b []byte) keyEvent {
	if len(b) == 0 {
		return keyUnknown
	}
	switch {
	case b[0] == 'q' || b[0] == 'Q' || b[0] == 3: // q, Q, Ctrl-C
		return keyQuit
	case b[0] == '\r' || b[0] == '\n':
		return keyEnter
	case b[0] == 27 && len(b) == 1: // bare ESC
		return keyEsc
	case b[0] == 27 && len(b) >= 3 && b[1] == '[':
		switch b[2] {
		case 'A':
			return keyUp
		case 'B':
			return keyDown
		case 'C':
			return keyRight
		case 'D':
			return keyLeft
		}
	}
	return keyUnknown
}

// Run launches the interactive menu. Returns the command to execute (if any).
func Run(version string) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Not a TTY — just print help and exit.
		printHelp(version)
		return
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		printHelp(version)
		return
	}
	defer func() {
		term.Restore(fd, oldState)
		fmt.Print(showCursor)
	}()

	fmt.Print(hideCursor)

	sel := 0      // selected top-level item
	inSub := false // are we in the options submenu?
	subSel := 0   // selected option within submenu

	for {
		render(version, sel, inSub, subSel)

		// Read up to 8 bytes (handles multi-byte escape sequences).
		buf := make([]byte, 8)
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return
		}
		key := readKey(buf[:n])

		switch key {
		case keyQuit:
			fmt.Print(clearScr)
			return

		case keyEsc:
			if inSub {
				inSub = false
				subSel = 0
			} else {
				fmt.Print(clearScr)
				return
			}

		case keyUp:
			if inSub {
				if subSel > 0 {
					subSel--
				}
			} else {
				if sel > 0 {
					sel--
				}
			}

		case keyDown:
			if inSub {
				if subSel < len(items[sel].Options)-1 {
					subSel++
				}
			} else {
				if sel < len(items)-1 {
					sel++
				}
			}

		case keyRight:
			if !inSub {
				inSub = true
				subSel = 0
			}

		case keyLeft:
			if inSub {
				inSub = false
				subSel = 0
			}

		case keyEnter:
			item := items[sel]
			var args []string
			if inSub {
				args = item.Options[subSel].Args
			}

			// Restore terminal before running the subprocess.
			term.Restore(fd, oldState)
			fmt.Print(showCursor)
			fmt.Print(clearScr)

			launch(item.Binary, args)

			// After the tool exits, offer to return to the menu.
			fmt.Print("\r\n  \033[2mPress any key to return to menu, Q to quit\033[0m\r\n")
			newState, err := term.MakeRaw(fd)
			if err != nil {
				return
			}
			oldState = newState
			fmt.Print(hideCursor)

			var kb [8]byte
			n, _ := os.Stdin.Read(kb[:])
			if n > 0 && readKey(kb[:n]) == keyQuit {
				term.Restore(fd, oldState)
				fmt.Print(showCursor)
				fmt.Print(clearScr)
				return
			}
			inSub = false
			subSel = 0
		}
	}
}

func render(version string, sel int, inSub bool, subSel int) {
	var b strings.Builder

	b.WriteString(clearScr)

	// Header.
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s%s◆%s  %s%sASPEX%s  %s%s%s\n",
		purple, bold, reset,
		white, bold, reset,
		dim, "v"+version, reset))
	b.WriteString(fmt.Sprintf("  %sAI Security Toolkit  ·  3 tools  ·  offline  ·  free%s\n", dim, reset))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s%s%s\n", dim, strings.Repeat("─", 54), reset))
	b.WriteString("\n")

	if !inSub {
		// Main menu.
		for i, item := range items {
			isSelected := i == sel
			b.WriteString(renderTopItem(item, isSelected))
		}
		b.WriteString("\n")

		// Description panel for selected item.
		item := items[sel]
		for _, line := range strings.Split(item.Description, "\n") {
			b.WriteString(fmt.Sprintf("  %s%s%s\n", dim, line, reset))
		}
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s%s%s\n", dim, strings.Repeat("─", 54), reset))
		b.WriteString(fmt.Sprintf("  %s↑↓ move   Enter run   → options   Q quit%s\n", dim, reset))
	} else {
		// Options submenu.
		item := items[sel]
		b.WriteString(fmt.Sprintf("  %s%s%s  %soptions%s\n\n",
			purple+bold, item.Label, reset,
			dim, reset,
		))

		for i, opt := range item.Options {
			isSelected := i == subSel
			b.WriteString(renderOption(opt, isSelected))
		}
		b.WriteString("\n")

		// Hint for selected option.
		hint := item.Options[subSel].Hint
		b.WriteString(fmt.Sprintf("  %s%s%s\n", dim, hint, reset))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s%s%s\n", dim, strings.Repeat("─", 54), reset))
		b.WriteString(fmt.Sprintf("  %s↑↓ move   Enter run   ← back   Q quit%s\n", dim, reset))
	}

	// In raw terminal mode \n only moves down; \r\n is required to also
	// return to column 0. Replace all newlines before printing.
	fmt.Print(strings.ReplaceAll(b.String(), "\n", "\r\n"))
}

func renderTopItem(item Item, selected bool) string {
	indicator := "   "
	labelStyle := dim
	tagStyle := dim

	if selected {
		indicator = fmt.Sprintf(" %s▶%s ", purple+bold, reset)
		labelStyle = white + bold
		tagStyle = ""
	}

	return fmt.Sprintf("  %s%s%-7s%s  %s%s%s\n",
		indicator,
		labelStyle, item.Label, reset,
		tagStyle, item.TagLine, reset,
	)
}

func renderOption(opt Option, selected bool) string {
	indicator := "     "
	labelStyle := dim
	cmdStr := buildCmdStr(opt.Args)

	if selected {
		indicator = fmt.Sprintf("   %s▶%s ", cyan+bold, reset)
		labelStyle = white + bold
	}

	line := fmt.Sprintf("  %s%s%-22s%s", indicator, labelStyle, opt.Label, reset)
	if cmdStr != "" && selected {
		line += fmt.Sprintf("  %s%s%s", dim, cmdStr, reset)
	}
	return line + "\n"
}

func buildCmdStr(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return strings.Join(args, " ")
}

func launch(binary string, args []string) {
	path, err := exec.LookPath(binary)
	if err != nil {
		// Fall back to aspex-scan redteam if aspex-attack not found yet.
		if binary == "aspex-attack" {
			path, err = exec.LookPath("aspex-scan")
			if err == nil {
				args = append([]string{"redteam"}, args...)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s not found in PATH\n", binary)
			os.Exit(1)
		}
	}

	cmd := exec.Command(path, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
	}
}

func printHelp(version string) {
	fmt.Printf("\n  ◆ ASPEX  v%s  — AI Security Toolkit\n\n", version)
	fmt.Println("  aspex-scan    Audit MCP server configurations")
	fmt.Println("  aspex-trace   Review AI agent activity logs")
	fmt.Println("  aspex-attack  Red team your live MCP servers")
	fmt.Println()
}
