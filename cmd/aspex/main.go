// Command aspex is the unified launcher for the Aspex AI security toolkit.
// Run with no arguments for the interactive menu.
// Run with a tool name to pass through directly: aspex scan, aspex trace, aspex attack.
package main

import (
	"os"
	"os/exec"

	"github.com/aspex-security/aspex/internal/tui"
	"github.com/aspex-security/aspex/internal/version"
)

func main() {
	args := os.Args[1:]

	// Pass-through mode: aspex scan [...], aspex trace [...], aspex attack [...]
	if len(args) > 0 {
		var binary string
		var rest []string
		switch args[0] {
		case "scan":
			binary, rest = "aspex-scan", args[1:]
		case "trace":
			binary, rest = "aspex-trace", args[1:]
		case "attack":
			binary, rest = "aspex-attack", args[1:]
			if _, err := exec.LookPath(binary); err != nil {
				// aspex-attack not released yet — route to aspex-scan redteam
				binary = "aspex-scan"
				rest = append([]string{"redteam"}, rest...)
			}
		case "doctor":
			binary = "aspex-doctor"
		case "--version", "-v":
			println("aspex v" + version.Version)
			return
		default:
			// Unknown arg — fall through to TUI (it handles --help etc.)
		}
		if binary != "" {
			path, err := exec.LookPath(binary)
			if err != nil {
				os.Stderr.WriteString("error: " + binary + " not found in PATH\n")
				os.Exit(1)
			}
			cmd := exec.Command(path, rest...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				}
			}
			return
		}
	}

	// Interactive menu.
	tui.Run(version.Version)
}
