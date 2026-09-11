// Command aspex is the front door to the Aspex toolkit.
//
//	aspex            snapshot of what your agents did this week, then the menu
//	aspex share      privacy-safe card of that snapshot to paste anywhere
//	aspex snapshot   the snapshot alone (no menu; good for scripts and CI logs)
//	aspex scan|trace|attack|doctor [...]   pass straight through to the tool
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/aspex-security/aspex/internal/snapshot"
	"github.com/aspex-security/aspex/internal/tui"
	"github.com/aspex-security/aspex/internal/version"
)

// 30 days: long enough that the numbers describe how someone actually works,
// short enough to parse in well under a second.
const snapshotWindow = 30 * 24 * time.Hour

func main() {
	args := os.Args[1:]
	noColor := os.Getenv("NO_COLOR") != "" || !term.IsTerminal(int(os.Stdout.Fd()))

	if len(args) > 0 {
		switch args[0] {
		case "share":
			s := snapshot.Build(context.Background(), version.Version, snapshotWindow)
			fmt.Print(s.ShareCard())
			return
		case "snapshot", "report":
			s := snapshot.Build(context.Background(), version.Version, snapshotWindow)
			s.Render(os.Stdout, noColor)
			return
		case "--version", "-v":
			fmt.Println("aspex v" + version.Version)
			return
		case "--help", "-h", "help":
			printHelp()
			return
		}
		if binary, rest, ok := passthrough(args); ok {
			run(binary, rest)
			return
		}
		fmt.Fprintf(os.Stderr, "aspex: unknown command %q\n\n", args[0])
		printHelp()
		os.Exit(2)
	}

	// No arguments: show what happened first, then offer the tools.
	s := snapshot.Build(context.Background(), version.Version, snapshotWindow)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		s.Render(os.Stdout, noColor)
		return
	}
	var b strings.Builder
	s.Render(&b, noColor)
	tui.Banner = b.String()
	tui.Run(version.Version)
}

// passthrough maps `aspex scan ...` style invocations to the underlying binary.
func passthrough(args []string) (binary string, rest []string, ok bool) {
	switch args[0] {
	case "scan":
		return "aspex-scan", args[1:], true
	case "trace":
		return "aspex-trace", args[1:], true
	case "doctor", "lock", "verify", "diff", "hooks", "explain", "tighten", "bom", "mcp", "explore", "history", "corpus", "inventory", "attack-paths":
		// Security-debugger commands live in aspex-scan; `aspex <cmd>` is the
		// front door so users never have to know which binary owns what.
		return "aspex-scan", append([]string{args[0]}, args[1:]...), true
	case "watch":
		return "aspex-scan", append([]string{"--watch"}, args[1:]...), true
	case "attack":
		if _, err := exec.LookPath("aspex-attack"); err != nil {
			// aspex-attack not installed: route to aspex-scan redteam.
			return "aspex-scan", append([]string{"redteam"}, args[1:]...), true
		}
		return "aspex-attack", args[1:], true
	}
	return "", nil, false
}

func run(binary string, args []string) {
	path, err := exec.LookPath(binary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s not found in PATH\n", binary)
		os.Exit(1)
	}
	cmd := exec.Command(path, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Printf(`aspex v%s - local security debugger for AI agents. Know what your agents can do. Know what they actually did.

  aspex               what your agents did this week + the tool menu
  aspex share         privacy-safe card of that snapshot, ready to paste
  aspex snapshot      the snapshot alone, no menu

  aspex scan          what can my agents do? every server, hook, skill, attack path
  aspex trace         what did they actually do? from your clients' own logs
  aspex explain "…"   can external content reach my AWS credentials?  (deterministic)
  aspex lock          write .aspex.lock, the security fingerprint of this setup
  aspex verify        did anything drift from the lock? explained in security terms
  aspex diff a..b     security impact of a config change between two git revisions
  aspex tighten       least-privilege recommendations from configured vs observed use
  aspex bom           agent security bill of materials (tree or JSON)
  aspex explore       local session explorer in your browser (loopback only)
  aspex mcp           expose Aspex to your agent as a read-only MCP server
  aspex doctor        2-second pre-flight health check
  aspex attack        red-team a server you own (advanced)

Offline. No account. Nothing leaves your machine.
`, version.Version)
}
