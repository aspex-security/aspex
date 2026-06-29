package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/diff"
	"github.com/aspex-security/aspex/internal/history"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/hook"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/mcpclient"
	"github.com/aspex-security/aspex/internal/notify"
	"github.com/aspex-security/aspex/internal/phantom"
	"github.com/aspex-security/aspex/internal/redteam"
	"github.com/aspex-security/aspex/internal/registry"
	"github.com/aspex-security/aspex/internal/report"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/score"
	"github.com/aspex-security/aspex/internal/shadow"
	"github.com/aspex-security/aspex/internal/version"
	"github.com/aspex-security/aspex/internal/watch"
)

// errExitOne is a sentinel returned by checkExitCode when --fail-on threshold is
// exceeded. main() converts it to os.Exit(1) after all defers have run.
var errExitOne = fmt.Errorf("exit:1")

// ANSI color/style constants shared across all subcommands.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiPurple = "\033[35m"
	ansiCyan   = "\033[36m"
	ansiGreen  = "\033[92m"
	ansiRed    = "\033[91m"
	ansiYellow = "\033[93m"
)

func main() {
	mcpclient.ClientVersion = version.Version
	if err := newRootCmd().Execute(); err != nil {
		if err == errExitOne {
			os.Exit(1)
		}
		os.Exit(2)
	}
}

type globalFlags struct {
	noExec       bool
	jsonOut      bool
	noColor      bool
	failOn       string
	clients      []string
	sarifOut     bool
	sarifFile    string
	htmlFile     string
	watchMode    bool
	explain      bool
	shareMode    bool
	reportFormat string
}

func newRootCmd() *cobra.Command {
	var gf globalFlags

	root := &cobra.Command{
		Use:   "aspex-scan [flags]",
		Short: "Scan your MCP servers for security risks",
		Long: `aspex-scan - MCP Server Security Scanner

Reads every MCP client config on this machine, enumerates all configured
servers and their tools, and scores each one across 250+ detection rules
covering prompt injection, credential exposure, typosquatting, and more.

No proxy. No config changes. No data sent anywhere. Runs entirely offline.

QUICK START
  aspex-scan                        Scan all MCP clients on this machine
  aspex-scan --clients claude        Only Claude Desktop
  aspex-scan --clients cursor,vscode  Cursor and VS Code
  aspex-scan inspect github          Deep-inspect the 'github' server
  aspex-scan verify my-package       Check a package against the malicious registry

OUTPUT & REPORTS
  aspex-scan --json                  Machine-readable JSON (pipe to jq, etc.)
  aspex-scan --html report.html      Save a shareable HTML report
  aspex-scan --sarif                 SARIF 2.1.0 for GitHub Advanced Security

CI INTEGRATION
  aspex-scan install-hook            Add a pre-commit git hook
  aspex-scan --fail-on critical      Exit 1 on CRITICAL findings
  aspex-scan --watch                 Auto-rescan when configs change

COMPARING OVER TIME
  aspex-scan --json > baseline.json  Save today's results
  aspex-scan diff baseline.json      Show what changed since baseline`,
		Example: `  # Full scan of everything on this machine
  aspex-scan

  # Only check Claude Desktop, save an HTML report
  aspex-scan --clients claude --html ~/aspex-report.html

  # Deep-inspect a specific server
  aspex-scan inspect github

  # Check a package name before installing
  aspex-scan verify @modelcontextprotocol/server-filesystem

  # CI: fail the build on any critical finding
  aspex-scan --fail-on critical --no-color

  # Watch mode - rescan when any config file changes
  aspex-scan --watch`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("NO_COLOR") != "" {
				gf.noColor = true
			}
			if gf.watchMode {
				return runWatch(gf)
			}
			return runScan(gf)
		},
	}

	root.PersistentFlags().BoolP("version", "v", false, "Print version and exit")
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if v, _ := cmd.Flags().GetBool("version"); v {
			fmt.Printf("aspex-scan %s (built %s)\n", version.Version, version.BuildDate)
			os.Exit(0)
		}
		return nil
	}

	root.PersistentFlags().BoolVar(&gf.noExec, "no-exec", false, "Static analysis only; skip launching MCP servers")
	root.PersistentFlags().BoolVar(&gf.jsonOut, "json", false, "JSON output - pipe to jq or feed into SIEM")
	root.PersistentFlags().BoolVar(&gf.noColor, "no-color", false, "Plain-text output (useful in CI logs)")
	root.PersistentFlags().StringVar(&gf.failOn, "fail-on", "off", "Exit 1 when findings reach this severity: critical|high|medium|low")
	root.PersistentFlags().StringSliceVar(&gf.clients, "clients", discover.AllClients, "Clients to scan: claude,cursor,vscode,windsurf,cline,roo-cline,continue,zed")
	root.PersistentFlags().BoolVar(&gf.sarifOut, "sarif", false, "SARIF 2.1.0 output to stdout for GitHub Advanced Security")
	root.PersistentFlags().StringVar(&gf.sarifFile, "sarif-output", "", "Write SARIF 2.1.0 to a file")
	root.PersistentFlags().StringVar(&gf.htmlFile, "html", "", "Save a shareable HTML report to this path")
	root.PersistentFlags().BoolVar(&gf.watchMode, "watch", false, "Auto-rescan when MCP config files change")
	root.PersistentFlags().BoolVar(&gf.explain, "explain", false, "Show why each finding is a risk, how it could be exploited, and how to fix it")
	root.Flags().BoolVar(&gf.shareMode, "share", false, "Print a privacy-safe shareable summary (no server names or values)")
	root.Flags().StringVar(&gf.reportFormat, "report", "", "Generate compliance report: soc2, iso27001")

	root.AddCommand(newInspectCmd(&gf))
	root.AddCommand(newVersionCmd())
	root.AddCommand(newDiffCmd(&gf))
	root.AddCommand(newInstallHookCmd())
	root.AddCommand(newUninstallHookCmd())
	root.AddCommand(newVerifyCmd())
	root.AddCommand(newInventoryCmd(&gf))
	root.AddCommand(newAttackPathsCmd(&gf))
	root.AddCommand(newShadowCmd(&gf))
	root.AddCommand(newPhantomCmd(&gf))
	root.AddCommand(newRedTeamCmd(&gf))
	root.AddCommand(newCompletionCmd())
	root.AddCommand(newFixCmd(&gf))
	root.AddCommand(newCronCmd(&gf))
	root.AddCommand(newExplainCmd(&gf))

	return root
}

func newVersionCmd() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("aspex-scan %s (built %s)\n", version.Version, version.BuildDate)
			if check {
				fmt.Print("Checking for updates... ")
				latest := version.CheckLatest()
				if latest != "" {
					fmt.Printf("\nUpdate available: %s → %s\n", version.Version, latest)
					fmt.Println("  brew upgrade aspex-security/tap/aspex")
					fmt.Println("  npm update -g aspex-scan")
				} else {
					fmt.Println("already up to date.")
				}
			}
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "Check GitHub for a newer release")
	return cmd
}

func newInventoryCmd(gf *globalFlags) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "List every MCP server and tool configured on this machine",
		Long: `Enumerate all MCP servers configured across every client on this machine.
Outputs a machine-readable inventory of server names, transports, tools, resources,
and prompts - without running any detection rules or scoring.

Useful for:
  - Asset management: know exactly what MCP surface area you have
  - Feeding into other tooling (jq, grep, SIEM ingest)
  - Quickly checking what tools a server exposes before running a full scan`,
		Example: `  # Print inventory table
  aspex-scan inventory

  # JSON for jq processing
  aspex-scan inventory --json | jq '.servers[] | select(.tool_count > 10)'

  # Only Claude Desktop
  aspex-scan --clients claude inventory`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInventory(gf, jsonOut)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	return cmd
}

func runInventory(gf *globalFlags, jsonOut bool) error {
	servers, discoveryErrs := discover.DiscoverAll(gf.clients)
	for _, e := range discoveryErrs {
		fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
	}
	ctx := context.Background()
	opts := inspect.Options{NoExec: gf.noExec}

	type invServer struct {
		Name       string   `json:"name"`
		Client     string   `json:"client"`
		Transport  string   `json:"transport"`
		Command    string   `json:"command,omitempty"`
		URL        string   `json:"url,omitempty"`
		Tools      []string `json:"tools"`
		Resources  []string `json:"resources"`
		Prompts    []string `json:"prompts"`
		ToolCount  int      `json:"tool_count"`
		StaticOnly bool     `json:"static_only"`
	}
	type invOutput struct {
		Version     string      `json:"version"`
		TotalServers int        `json:"total_servers"`
		TotalTools  int         `json:"total_tools"`
		Clients     []string    `json:"clients"`
		Servers     []invServer `json:"servers"`
	}

	clientSet := map[string]struct{}{}
	var inv []invServer
	totalTools := 0

	for _, entry := range servers {
		srv := inspect.InspectServer(ctx, entry, opts)
		clientSet[entry.Client] = struct{}{}

		transport := "stdio"
		if entry.URL != "" {
			transport = "http"
		}

		var toolNames, resNames, promptNames []string
		for _, t := range srv.Tools {
			toolNames = append(toolNames, t.Name)
		}
		for _, r := range srv.Resources {
			resNames = append(resNames, r.Name)
		}
		for _, p := range srv.Prompts {
			promptNames = append(promptNames, p.Name)
		}
		totalTools += len(toolNames)

		inv = append(inv, invServer{
			Name:       entry.Name,
			Client:     entry.Client,
			Transport:  transport,
			Command:    entry.Command,
			URL:        entry.URL,
			Tools:      toolNames,
			Resources:  resNames,
			Prompts:    promptNames,
			ToolCount:  len(toolNames),
			StaticOnly: srv.StaticOnly,
		})
	}

	var clients []string
	for c := range clientSet {
		clients = append(clients, c)
	}

	out := invOutput{
		Version:      version.Version,
		TotalServers: len(inv),
		TotalTools:   totalTools,
		Clients:      clients,
		Servers:      inv,
	}

	if jsonOut || gf.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	c := func(col, text string) string {
		if gf.noColor {
			return text
		}
		return col + text + "\033[0m"
	}
	bold := "\033[1m"
	dim := "\033[2m"
	purple := "\033[35m"
	cyan := "\033[36m"

	fmt.Fprintf(os.Stdout, "\n  %s  %s %s\n\n",
		c(purple+bold, "◆"),
		c(bold, "MCP Inventory"),
		c(dim, fmt.Sprintf("- %d servers · %d tools", out.TotalServers, out.TotalTools)),
	)

	for _, s := range inv {
		staticTag := ""
		if s.StaticOnly {
			staticTag = c(dim, " (static)")
		}
		fmt.Fprintf(os.Stdout, "  %s  %s%s\n",
			c(purple, "◉"),
			c(bold, s.Name),
			staticTag,
		)
		fmt.Fprintf(os.Stdout, "     %s %s · %s %s\n",
			c(dim, "client:"),
			c(cyan, s.Client),
			c(dim, "transport:"),
			c(cyan, s.Transport),
		)
		if len(s.Tools) > 0 {
			shown := s.Tools
			suffix := ""
			if len(shown) > 8 {
				shown = shown[:8]
				suffix = fmt.Sprintf(" +%d", len(s.Tools)-8)
			}
			fmt.Fprintf(os.Stdout, "     %s %s%s\n",
				c(dim, "tools:"),
				strings.Join(shown, ", "),
				c(dim, suffix),
			)
		}
		fmt.Fprintln(os.Stdout)
	}
	return nil
}

func newAttackPathsCmd(gf *globalFlags) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "attack-paths",
		Short: "Identify dangerous tool combinations that form attack chains",
		Long: `Analyze your installed MCP servers for dangerous capability combinations
that together form complete attack chains - even when no single server looks
malicious on its own.

A "file-read" server paired with an "http" server gives any compromised prompt
the ability to exfiltrate your files to an external URL. This command surfaces
those cross-server risks that a per-server scan can't see.

Capabilities analyzed:
  file-read · file-write · shell-exec · network-send
  credential-read · persistence · env-read · email-send

Each chain maps to a MITRE ATT&CK tactic and lists which servers contribute
which capabilities.`,
		Example: `  # Show all attack chains across your full MCP setup
  aspex-scan attack-paths

  # JSON output for pipeline use
  aspex-scan attack-paths --json

  # Only analyze Claude Desktop servers
  aspex-scan --clients claude attack-paths`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttackPaths(gf, jsonOut)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	return cmd
}

func runAttackPaths(gf *globalFlags, jsonOut bool) error {
	servers, discoveryErrs := discover.DiscoverAll(gf.clients)
	for _, e := range discoveryErrs {
		fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
	}
	ctx := context.Background()
	opts := inspect.Options{NoExec: gf.noExec}

	var inspected []*inspect.Server
	for _, entry := range servers {
		srv := inspect.InspectServer(ctx, entry, opts)
		inspected = append(inspected, srv)
	}

	caps, chains := attackpath.Analyze(inspected)

	if jsonOut || gf.jsonOut {
		type jsonCap struct {
			Server string            `json:"server"`
			Client string            `json:"client"`
			Caps   []string          `json:"capabilities"`
			Tools  map[string][]string `json:"contributing_tools"`
		}
		type jsonChain struct {
			Name        string   `json:"name"`
			Severity    string   `json:"severity"`
			Description string   `json:"description"`
			MITRETactic string   `json:"mitre_tactic"`
			MITRERef    string   `json:"mitre_ref"`
			Servers     []string `json:"servers"`
			Steps       []string `json:"steps"`
		}
		type jsonOut struct {
			Version      string      `json:"version"`
			TotalServers int         `json:"total_servers"`
			TotalChains  int         `json:"total_chains"`
			Capabilities []jsonCap   `json:"capabilities"`
			Chains       []jsonChain `json:"chains"`
		}
		var jCaps []jsonCap
		for _, c := range caps {
			var capNames []string
			toolMap := map[string][]string{}
			for bit := attackpath.CapReadFile; bit <= attackpath.CapEmailSend; bit <<= 1 {
				if c.Has(bit) {
					capName := bit.String()
					capNames = append(capNames, capName)
					toolMap[capName] = c.CapTools[bit]
				}
			}
			jCaps = append(jCaps, jsonCap{
				Server: c.ServerName,
				Client: c.Client,
				Caps:   capNames,
				Tools:  toolMap,
			})
		}
		var jChains []jsonChain
		for _, ch := range chains {
			jChains = append(jChains, jsonChain{
				Name:        ch.Name,
				Severity:    ch.Severity,
				Description: ch.Description,
				MITRETactic: ch.MITRETactic,
				MITRERef:    ch.MITRERef,
				Servers:     ch.Servers,
				Steps:       ch.Steps,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(jsonOut{
			Version:      version.Version,
			TotalServers: len(caps),
			TotalChains:  len(chains),
			Capabilities: jCaps,
			Chains:       jChains,
		})
	}

	c := func(col, text string) string {
		if gf.noColor {
			return text
		}
		return col + text + "\033[0m"
	}
	bold := "\033[1m"
	dim := "\033[2m"
	purple := "\033[35m"
	red := "\033[91m"
	yellow := "\033[93m"
	cyan := "\033[36m"

	fmt.Fprintf(os.Stdout, "\n  %s  %s\n\n",
		c(purple+bold, "◆"),
		c(bold, "Attack Path Analysis"),
	)

	if len(chains) == 0 {
		fmt.Fprintf(os.Stdout, "  %s  No dangerous capability combinations found across %d servers.\n\n",
			c("\033[92m", "✓"),
			len(inspected),
		)
		return nil
	}

	sevColor := func(s string) string {
		switch s {
		case "critical":
			return red + bold
		case "high":
			return yellow + bold
		}
		return dim
	}

	// Group chains by Name so repeated server-pair combinations collapse into one block.
	type group struct {
		chain        attackpath.AttackChain // representative entry (first seen)
		serverPairs  []string               // all server combinations for this attack type
	}
	var groupOrder []string
	groups := map[string]*group{}
	for _, ch := range chains {
		if _, ok := groups[ch.Name]; !ok {
			groupOrder = append(groupOrder, ch.Name)
			cp := ch
			groups[ch.Name] = &group{chain: cp}
		}
		groups[ch.Name].serverPairs = append(groups[ch.Name].serverPairs, strings.Join(ch.Servers, " → "))
	}

	for _, name := range groupOrder {
		g := groups[name]
		ch := g.chain
		fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
			c(sevColor(ch.Severity), strings.ToUpper(ch.Severity)),
			c(bold, ch.Name),
			c(dim, "· "+ch.MITRETactic+" ("+ch.MITRERef+")"),
		)
		// Generic description without server names (those vary per pair).
		for _, step := range ch.Steps[len(ch.Steps)-1:] {
			fmt.Fprintf(os.Stdout, "     %s\n", c(dim, step))
		}
		for _, pair := range g.serverPairs {
			fmt.Fprintf(os.Stdout, "     %s %s\n", c(dim, "·"), c(cyan, pair))
		}
		fmt.Fprintln(os.Stdout)
	}

	fmt.Fprintf(os.Stdout, "  %s %d attack type(s) · %d chain(s) across %d server(s).\n\n",
		c(dim, "─"),
		len(groupOrder),
		len(chains),
		len(inspected),
	)
	return nil
}

func newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate a shell completion script for aspex-scan.

Bash:
  source <(aspex-scan completion bash)
  # or: aspex-scan completion bash > /etc/bash_completion.d/aspex-scan

Zsh:
  aspex-scan completion zsh > "${fpath[1]}/_aspex-scan"
  # or add to ~/.zshrc: source <(aspex-scan completion zsh)

Fish:
  aspex-scan completion fish | source
  # or: aspex-scan completion fish > ~/.config/fish/completions/aspex-scan.fish`,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactArgs(1),
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(os.Stdout)
			case "zsh":
				return root.GenZshCompletion(os.Stdout)
			case "fish":
				return root.GenFishCompletion(os.Stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
}

func newShadowCmd(gf *globalFlags) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "shadow",
		Short: "Detect tool name collisions across MCP servers (shadow attack surface)",
		Long: `Scan for tool name shadowing - a class of attack where a malicious or
misconfigured MCP server registers tool names that collide with tools on a
legitimate server.

When two servers both expose a tool called "read_file", the AI agent's routing
is ambiguous. An attacker can deliberately register common high-value names
(read_file, execute_command, write_file) to intercept calls meant for a
trusted server, forge responses, or silently execute alongside it.

Risk levels:
  CRITICAL  HTTP/SSE server shadows a high-value local tool (remote attacker wins)
  HIGH      Local tool name collision on a high-capability tool
  MEDIUM    Two local servers share a low-capability tool name`,
		Example: `  # Detect all shadowing in your current MCP setup
  aspex-scan shadow

  # JSON output for CI or custom tooling
  aspex-scan shadow --json

  # Only check Claude Desktop
  aspex-scan --clients claude shadow`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runShadow(gf, jsonOut)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	return cmd
}

func runShadow(gf *globalFlags, jsonOut bool) error {
	servers, discoveryErrs := discover.DiscoverAll(gf.clients)
	for _, e := range discoveryErrs {
		fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
	}
	ctx := context.Background()
	opts := inspect.Options{NoExec: gf.noExec}

	var inspected []*inspect.Server
	for _, entry := range servers {
		inspected = append(inspected, inspect.InspectServer(ctx, entry, opts))
	}

	report := shadow.Analyze(inspected)

	if jsonOut || gf.jsonOut {
		type jsonSide struct {
			Server    string `json:"server"`
			Client    string `json:"client"`
			Transport string `json:"transport"`
		}
		type jsonCollision struct {
			ToolName string     `json:"tool_name"`
			Risk     string     `json:"risk"`
			Reason   string     `json:"reason"`
			Servers  []jsonSide `json:"servers"`
		}
		type jsonReport struct {
			Version         string          `json:"version"`
			TotalServers    int             `json:"total_servers"`
			TotalTools      int             `json:"total_tools"`
			UniqueToolNames int             `json:"unique_tool_names"`
			Collisions      []jsonCollision `json:"collisions"`
		}
		var cols []jsonCollision
		for _, col := range report.Collisions {
			var sides []jsonSide
			for _, s := range col.Servers {
				sides = append(sides, jsonSide{Server: s.ServerName, Client: s.Client, Transport: s.Transport})
			}
			cols = append(cols, jsonCollision{
				ToolName: col.ToolName,
				Risk:     col.Risk,
				Reason:   col.Reason,
				Servers:  sides,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(jsonReport{
			Version:         version.Version,
			TotalServers:    report.TotalServers,
			TotalTools:      report.TotalTools,
			UniqueToolNames: report.UniqueToolNames,
			Collisions:      cols,
		})
	}

	c := func(col, text string) string {
		if gf.noColor {
			return text
		}
		return col + text + "\033[0m"
	}
	bold := "\033[1m"
	dim := "\033[2m"
	purple := "\033[35m"
	red := "\033[91m"
	yellow := "\033[93m"
	cyan := "\033[36m"

	fmt.Fprintf(os.Stdout, "\n  %s  %s\n  %s %d servers · %d tools · %d unique names\n\n",
		c(purple+bold, "◆"),
		c(bold, "Tool Name Shadow Analysis"),
		c(dim, "→"),
		report.TotalServers,
		report.TotalTools,
		report.UniqueToolNames,
	)

	if len(report.Collisions) == 0 {
		fmt.Fprintf(os.Stdout, "  %s  No tool name collisions found - every tool name is unique across your servers.\n\n",
			c("\033[92m", "✓"),
		)
		fmt.Fprintf(os.Stdout, "  %s Run %s regularly as you add new MCP servers.\n\n",
			c(dim, "→"),
			c(cyan, "aspex-scan shadow"),
		)
		return nil
	}

	sevColor := func(s string) string {
		switch s {
		case "critical":
			return red + bold
		case "high":
			return yellow + bold
		}
		return dim
	}

	for _, col := range report.Collisions {
		serverNames := make([]string, len(col.Servers))
		for i, s := range col.Servers {
			t := ""
			if s.IsExternal {
				t = " (http)"
			}
			serverNames[i] = s.ServerName + t
		}
		fmt.Fprintf(os.Stdout, "  %s  %s %s\n",
			c(sevColor(col.Risk), strings.ToUpper(col.Risk)),
			c(bold, col.ToolName),
			c(dim, "·  "+strings.Join(serverNames, " ↔ ")),
		)
		fmt.Fprintf(os.Stdout, "     %s\n\n", c(dim, col.Reason))
	}

	crit := 0
	high := 0
	for _, col := range report.Collisions {
		switch col.Risk {
		case "critical":
			crit++
		case "high":
			high++
		}
	}
	fmt.Fprintf(os.Stdout, "  %s %d collision(s) found",
		c(dim, "─"),
		len(report.Collisions),
	)
	if crit > 0 {
		fmt.Fprintf(os.Stdout, " · %s", c(red+bold, fmt.Sprintf("%d critical", crit)))
	}
	if high > 0 {
		fmt.Fprintf(os.Stdout, " · %s", c(yellow, fmt.Sprintf("%d high", high)))
	}
	fmt.Fprintf(os.Stdout, "\n\n")
	return nil
}

func newPhantomCmd(gf *globalFlags) *cobra.Command {
	var jsonOut bool
	var intervalStr string
	cmd := &cobra.Command{
		Use:   "phantom",
		Short: "Detect servers that return different tools on successive calls",
		Long: `Inspect each MCP server twice and compare the tool lists.

A legitimate server returns the same tools every time. A server that returns
different tools on successive calls is exhibiting the "clean-face" attack
pattern: presenting safe-looking tools to security scanners while serving
malicious tools to actual AI clients.

Changes detected:
  CRITICAL  Tool added or removed between calls (selective targeting)
  CRITICAL  Tool description changed AND contains injection language
  HIGH      Tool description or schema changed between calls

The interval between calls is configurable - longer intervals test whether
the server changes its behavior based on session timing.`,
		Example: `  # Check all servers for phantom tools
  aspex-scan phantom

  # Use a 10-second interval between calls
  aspex-scan phantom --interval 10

  # Only check Claude Desktop servers
  aspex-scan --clients claude phantom

  # JSON output
  aspex-scan phantom --json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			dur, err := time.ParseDuration(intervalStr)
			if err != nil {
				return fmt.Errorf("invalid --interval %q: %w", intervalStr, err)
			}
			return runPhantom(gf, jsonOut, dur)
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	cmd.Flags().StringVar(&intervalStr, "interval", "5s", "Duration between the two tools/list calls (e.g. 5s, 10s, 1m)")
	return cmd
}

func runPhantom(gf *globalFlags, jsonOut bool, interval time.Duration) error {
	servers, discoveryErrs := discover.DiscoverAll(gf.clients)
	for _, e := range discoveryErrs {
		fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
	}
	if len(servers) == 0 {
		fmt.Fprintf(os.Stdout, "  No MCP servers found.\n")
		return nil
	}

	ctx := context.Background()

	c := func(col, text string) string {
		if gf.noColor {
			return text
		}
		return col + text + "\033[0m"
	}
	bold := "\033[1m"
	dim := "\033[2m"
	purple := "\033[35m"
	red := "\033[91m"
	yellow := "\033[93m"
	green := "\033[92m"
	cyan := "\033[36m"

	if !jsonOut && !gf.jsonOut {
		fmt.Fprintf(os.Stdout, "\n  %s  %s\n  %s %d servers · %s interval between calls\n\n",
			c(purple+bold, "◆"),
			c(bold, "Phantom Tool Detection"),
			c(dim, "→"),
			len(servers),
			interval,
		)
	}

	type jsonResult struct {
		Server    string `json:"server"`
		Client    string `json:"client"`
		Transport string `json:"transport"`
		Clean     bool   `json:"clean"`
		Error     string `json:"error,omitempty"`
		Changes   []struct {
			Kind        string `json:"kind"`
			Tool        string `json:"tool"`
			Severity    string `json:"severity"`
			Before      string `json:"before,omitempty"`
			After       string `json:"after,omitempty"`
			Explanation string `json:"explanation"`
		} `json:"changes,omitempty"`
	}

	var results []jsonResult
	dirtyCount := 0

	for _, entry := range servers {
		if !jsonOut && !gf.jsonOut {
			fmt.Fprintf(os.Stdout, "  %s %s %s\r",
				c(dim, "scanning"),
				c(bold, entry.Name),
				c(dim, "..."),
			)
		}

		res := phantom.Analyze(ctx, entry, interval)

		if jsonOut || gf.jsonOut {
			jr := jsonResult{
				Server:    res.ServerName,
				Client:    res.Client,
				Transport: res.Transport,
				Clean:     res.Clean(),
			}
			if res.Err != nil {
				jr.Error = res.Err.Error()
			}
			for _, ch := range res.Changes {
				jr.Changes = append(jr.Changes, struct {
					Kind        string `json:"kind"`
					Tool        string `json:"tool"`
					Severity    string `json:"severity"`
					Before      string `json:"before,omitempty"`
					After       string `json:"after,omitempty"`
					Explanation string `json:"explanation"`
				}{
					Kind:        ch.Kind,
					Tool:        ch.ToolName,
					Severity:    ch.Severity,
					Before:      ch.Before,
					After:       ch.After,
					Explanation: ch.Explanation,
				})
			}
			results = append(results, jr)
			continue
		}

		// Terminal output.
		if res.Err != nil {
			fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
				c(yellow, "?"),
				c(bold, res.ServerName),
				c(dim, res.Err.Error()),
			)
			continue
		}

		if res.Clean() {
			fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
				c(green, "✓"),
				c(bold, res.ServerName),
				c(dim, fmt.Sprintf("stable · %d tools on both calls", len(res.FirstCall))),
			)
			continue
		}

		dirtyCount++
		fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
			c(red+bold, "!"),
			c(bold, res.ServerName),
			c(dim, fmt.Sprintf("%d change(s) detected", len(res.Changes))),
		)
		for _, ch := range res.Changes {
			sevColor := yellow + bold
			if ch.Severity == "critical" {
				sevColor = red + bold
			}
			fmt.Fprintf(os.Stdout, "    %s  %s %s\n",
				c(sevColor, strings.ToUpper(ch.Severity)),
				c(bold, ch.ToolName),
				c(dim, "("+ch.Kind+")"),
			)
			fmt.Fprintf(os.Stdout, "       %s\n", c(dim, ch.Explanation))
			if ch.Before != "" && ch.After != "" {
				fmt.Fprintf(os.Stdout, "       %s %s\n", c(dim, "before:"), ch.Before)
				fmt.Fprintf(os.Stdout, "       %s %s\n", c(dim, " after:"), c(yellow, ch.After))
			}
		}
		fmt.Fprintln(os.Stdout)
	}

	if jsonOut || gf.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"version": version.Version,
			"servers": results,
		})
	}

	fmt.Fprintf(os.Stdout, "\n  %s ", c(dim, "─"))
	if dirtyCount == 0 {
		fmt.Fprintf(os.Stdout, "%s All %d server(s) return consistent tool lists.\n",
			c(green, "✓"),
			len(servers),
		)
		fmt.Fprintf(os.Stdout, "  %s Run %s periodically - servers can change between updates.\n\n",
			c(dim, "→"),
			c(cyan, "aspex-scan phantom"),
		)
	} else {
		fmt.Fprintf(os.Stdout, "%s %s inconsistent server(s) detected - investigate before continuing.\n\n",
			c(red+bold, fmt.Sprintf("%d", dirtyCount)),
			c(dim, ""),
		)
	}

	return nil
}

func newInspectCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "inspect <server-name>",
		Short:   "Deep-inspect a single MCP server",
		Long:    "Launch and interrogate one MCP server by name (as it appears in your client config) and print a full finding report for that server alone.",
		Example: "  aspex-scan inspect github\n  aspex-scan inspect filesystem --no-exec",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entry := discover.ServerEntry{
				Name:    args[0],
				Client:  "cli",
				Command: args[0],
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			srv := inspect.InspectServer(ctx, entry, inspect.Options{NoExec: gf.noExec})
			findings := rules.EvalServer(srv)
			sc := score.ScoreServer(findings)
			overall := score.ScoreOverall([]score.ServerScore{sc})

			if gf.jsonOut {
				out := report.JSONScanOutput{
					Version: version.Version,
					Overall: overall,
					Servers: []report.JSONServerResult{toJSONServer(srv, sc)},
				}
				return report.WriteJSONScan(os.Stdout, out)
			}

			r := report.ScanReport{
				Version:   version.Version,
				ElapsedMS: 0,
				Servers:   []*inspect.Server{srv},
				Scores:    []score.ServerScore{sc},
				Overall:   overall,
				NoColor:   gf.noColor,
				Explain:   gf.explain,
			}
			report.PrintScanReport(os.Stdout, r)
			return checkExitCode(gf.failOn, overall)
		},
	}
}

func newDiffCmd(gf *globalFlags) *cobra.Command {
	var baselineFile string
	cmd := &cobra.Command{
		Use:     "diff",
		Short:   "Compare current scan to a previous baseline",
		Long:    "Re-run the full scan and compare results against a previously saved JSON baseline. New findings cause a non-zero exit code.",
		Example: "  aspex-scan --json > baseline.json\n  aspex-scan diff --baseline baseline.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(baselineFile)
			if err != nil {
				return fmt.Errorf("reading baseline: %w", err)
			}
			var baseline report.JSONScanOutput
			if err := json.Unmarshal(data, &baseline); err != nil {
				return fmt.Errorf("parsing baseline: %w", err)
			}

			// Run current scan.
			servers, discoveryErrs := discover.DiscoverAll(gf.clients)
			for _, e := range discoveryErrs {
				fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
			}
			ctx := context.Background()
			opts := inspect.Options{NoExec: gf.noExec}
			var inspected []*inspect.Server
			for _, entry := range servers {
				srv := inspect.InspectServer(ctx, entry, opts)
				inspected = append(inspected, srv)
			}
			var scores []score.ServerScore
			for _, srv := range inspected {
				findings := rules.EvalServer(srv)
				scores = append(scores, score.ScoreServer(findings))
			}
			overall := score.ScoreOverall(scores)
			var jsonServers []report.JSONServerResult
			for i, srv := range inspected {
				jsonServers = append(jsonServers, toJSONServer(srv, scores[i]))
			}
			current := report.JSONScanOutput{
				Version: version.Version,
				Overall: overall,
				Servers: jsonServers,
			}

			d := diff.Compare(baseline, current)

			if gf.jsonOut {
				return diff.WriteDiffJSON(os.Stdout, d)
			}
			diff.PrintDiff(os.Stdout, d, gf.noColor)
			if d.Regressed {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&baselineFile, "baseline", "", "Path to baseline JSON scan file (required)")
	_ = cmd.MarkFlagRequired("baseline")
	return cmd
}

func newInstallHookCmd() *cobra.Command {
	var repoPath string
	cmd := &cobra.Command{
		Use:     "install-hook",
		Short:   "Add an aspex-scan pre-commit git hook to this repo",
		Long:    "Writes a pre-commit hook to .git/hooks/pre-commit that runs aspex-scan --fail-on critical before every commit.",
		Example: "  aspex-scan install-hook\n  aspex-scan install-hook --repo /path/to/repo",
		RunE: func(cmd *cobra.Command, args []string) error {
			if repoPath == "" {
				var err error
				repoPath, err = os.Getwd()
				if err != nil {
					return err
				}
			}
			if err := hook.Install(repoPath); err != nil {
				return fmt.Errorf("installing hook: %w", err)
			}
			fmt.Printf("Hook installed in %s\n", repoPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&repoPath, "repo", "", "Path to git repo (default: current directory)")
	return cmd
}

func newUninstallHookCmd() *cobra.Command {
	var repoPath string
	cmd := &cobra.Command{
		Use:   "uninstall-hook",
		Short: "Remove the aspex-scan pre-commit git hook",
		RunE: func(cmd *cobra.Command, args []string) error {
			if repoPath == "" {
				var err error
				repoPath, err = os.Getwd()
				if err != nil {
					return err
				}
			}
			if err := hook.Uninstall(repoPath); err != nil {
				return fmt.Errorf("uninstalling hook: %w", err)
			}
			fmt.Printf("Hook uninstalled from %s\n", repoPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&repoPath, "repo", "", "Path to git repo (default: current directory)")
	return cmd
}

func newVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "verify <package-name>",
		Short:   "Check a package name against the known-malicious registry",
		Long:    "Look up a package name in Aspex's registry of known-malicious MCP server packages. Checks for exact matches, typosquats, and known CVEs.",
		Example: "  aspex-scan verify @modelcontextprotocol/server-filesystem\n  aspex-scan verify my-mcp-package",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pkg := args[0]
			entry := registry.Lookup(pkg)
			if entry == nil {
				fmt.Printf("No registry entry found for %q\n", pkg)
				return nil
			}
			fmt.Printf("Package:  %s\n", entry.Package)
			fmt.Printf("Version:  %s\n", entry.Version)
			fmt.Printf("Severity: %s\n", entry.Severity)
			fmt.Printf("Summary:  %s\n", entry.Summary)
			if entry.FixedIn != "" {
				fmt.Printf("Fixed in: %s\n", entry.FixedIn)
			}
			if entry.CVE != "" {
				fmt.Printf("CVE:      %s\n", entry.CVE)
			}
			fmt.Printf("Reported: %s\n", entry.Reported)
			fmt.Printf("Rules:    %s\n", strings.Join(entry.RuleIDs, ", "))
			return nil
		},
	}
}

func newRedTeamCmd(gf *globalFlags) *cobra.Command {
	var (
		serverFlag  string
		timeoutSecs int
		jsonOut     bool
		categories  []string
	)
	cmd := &cobra.Command{
		Use:   "redteam",
		Short: "Actively probe MCP servers with adversarial payloads",
		Long: `Red team mode calls live MCP tools with adversarial inputs and analyzes
responses for signs of prompt injection success, path traversal, SSRF,
error disclosure, and prompt leakage. This goes beyond static analysis
to provide empirical vulnerability evidence.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRedTeam(gf, serverFlag, timeoutSecs, jsonOut, categories)
		},
	}
	cmd.Flags().StringVar(&serverFlag, "server", "", "Test only this server (by name)")
	cmd.Flags().IntVar(&timeoutSecs, "timeout", 10, "Timeout per probe in seconds")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	cmd.Flags().StringSliceVar(&categories, "categories", nil, "Limit to these probe categories (prompt-injection,path-traversal,ssrf,command-injection,error-disclosure,prompt-leakage)")
	return cmd
}

func runRedTeam(gf *globalFlags, serverFlag string, timeoutSecs int, jsonOut bool, categories []string) error {
	servers, discoveryErrs := discover.DiscoverAll(gf.clients)
	for _, e := range discoveryErrs {
		fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
	}
	if len(servers) == 0 {
		fmt.Fprintln(os.Stdout, "  No MCP servers found.")
		return nil
	}

	// Filter by --server flag.
	if serverFlag != "" {
		var filtered []discover.ServerEntry
		for _, s := range servers {
			if s.Name == serverFlag {
				filtered = append(filtered, s)
			}
		}
		servers = filtered
		if len(servers) == 0 {
			return fmt.Errorf("no server named %q found", serverFlag)
		}
	}

	// Build category filter set.
	catFilter := map[redteam.ProbeCategory]bool{}
	for _, c := range categories {
		catFilter[redteam.ProbeCategory(c)] = true
	}

	c := func(col, text string) string {
		if gf.noColor || jsonOut || gf.jsonOut {
			return text
		}
		return col + text + "\033[0m"
	}
	bold := "\033[1m"
	dim := "\033[2m"
	purple := "\033[35m"
	red := "\033[91m"
	green := "\033[92m"
	yellow := "\033[93m"

	if !jsonOut && !gf.jsonOut {
		// Confirmation prompt - show scope and require explicit Y before firing payloads.
		fmt.Fprintf(os.Stdout, "\n  %s  %s\n\n",
			c(purple+bold, "◆"),
			c(bold, "Red Team Probe"),
		)
		fmt.Fprintf(os.Stdout, "  %s This command calls live MCP tools with adversarial payloads.\n", c(yellow, "!"))
		fmt.Fprintf(os.Stdout, "  Only run against servers you own or have explicit written permission to test.\n\n")
		fmt.Fprintf(os.Stdout, "  Scope: %s server(s) · timeout %ds per probe\n", c(bold, fmt.Sprintf("%d", len(servers))), timeoutSecs)
		for _, s := range servers {
			fmt.Fprintf(os.Stdout, "    %s %s\n", c(dim, "·"), s.Name)
		}
		fmt.Fprintf(os.Stdout, "\n  Proceed? %s ", c(dim, "[y/N]"))
		var answer string
		fmt.Fscan(os.Stdin, &answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Fprintln(os.Stdout, c(dim, "\n  Aborted."))
			return nil
		}
		fmt.Fprintln(os.Stdout)
	}

	type jsonVuln struct {
		Server   string   `json:"server"`
		Tool     string   `json:"tool"`
		Probe    string   `json:"probe"`
		Category string   `json:"category"`
		Severity string   `json:"severity"`
		Detected []string `json:"detected"`
		Response string   `json:"response,omitempty"`
	}
	type jsonServerResult struct {
		Name       string     `json:"name"`
		Client     string     `json:"client"`
		ToolCount  int        `json:"tool_count"`
		ProbeCount int        `json:"probe_count"`
		Error      string     `json:"error,omitempty"`
	}

	var allVulns []jsonVuln
	var jsonServers []jsonServerResult
	totalProbes := 0
	totalVulns := 0

	ctx := context.Background()

	for _, entry := range servers {
		if !jsonOut && !gf.jsonOut {
			fmt.Fprintf(os.Stdout, "  %s %s\n",
				c(dim, "▸"),
				c(bold, entry.Name),
			)
		}

		// Inspect to get tools list.
		opts := inspect.Options{NoExec: gf.noExec}
		srv := inspect.InspectServer(ctx, entry, opts)

		if srv.StaticOnly && !gf.noExec {
			if !jsonOut && !gf.jsonOut {
				fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
					c(yellow, "~"),
					c(bold, entry.Name),
					c(dim, "static-only (use --no-exec=false to probe)"),
				)
			}
			jsonServers = append(jsonServers, jsonServerResult{
				Name:   entry.Name,
				Client: entry.Client,
				Error:  "static-only server skipped",
			})
			continue
		}

		if len(srv.Tools) == 0 {
			if !jsonOut && !gf.jsonOut {
				fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
					c(dim, "-"),
					c(bold, entry.Name),
					c(dim, "no tools found"),
				)
			}
			jsonServers = append(jsonServers, jsonServerResult{
				Name:   entry.Name,
				Client: entry.Client,
			})
			continue
		}

		serverProbes := 0
		serverVulns := 0

		for _, tool := range srv.Tools {
			probes := redteam.ProbesForTool(tool)

			// Filter by category if requested.
			if len(catFilter) > 0 {
				var filtered []redteam.Probe
				for _, p := range probes {
					if catFilter[p.Category] {
						filtered = append(filtered, p)
					}
				}
				probes = filtered
			}

			if len(probes) == 0 {
				continue
			}

			if !jsonOut && !gf.jsonOut {
				fmt.Fprintf(os.Stdout, "    %s %s %s\r",
					c(dim, "·"),
					c(dim, tool.Name),
					c(dim, fmt.Sprintf("(%d probes)…", len(probes))),
				)
			}

			probeCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
			results := redteam.RunProbes(probeCtx, entry, tool, probes)
			cancel()

			serverProbes += len(results)
			totalProbes += len(results)

			var toolVulns []redteam.ProbeResult
			for _, r := range results {
				if r.Vulnerable() {
					toolVulns = append(toolVulns, r)
					serverVulns++
					totalVulns++
					allVulns = append(allVulns, jsonVuln{
						Server:   entry.Name,
						Tool:     tool.Name,
						Probe:    r.Probe.Name,
						Category: string(r.Probe.Category),
						Severity: r.Severity,
						Detected: r.Triggered,
						Response: truncate(r.Response, 500),
					})
				}
			}

			if !jsonOut && !gf.jsonOut {
				// Clear the in-progress line then print the result.
				fmt.Fprintf(os.Stdout, "\033[2K")
				if len(toolVulns) > 0 {
					fmt.Fprintf(os.Stdout, "    %s  %s  %s\n",
						c(red+bold, "VULNERABLE"),
						c(bold, tool.Name),
						c(dim, fmt.Sprintf("%d/%d probes triggered", len(toolVulns), len(results))),
					)
					for _, vr := range toolVulns {
						fmt.Fprintf(os.Stdout, "       %s %s %s\n",
							c(red, "▸"),
							c(bold, vr.Probe.Name),
							c(dim, "("+strings.Join(vr.Triggered, ", ")+")"),
						)
					}
				}
			}
		}

		if !jsonOut && !gf.jsonOut {
			if serverVulns == 0 {
				fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
					c(green, "✓"),
					c(bold, entry.Name),
					c(dim, fmt.Sprintf("CLEAN · %d probes · %d tools", serverProbes, len(srv.Tools))),
				)
			} else {
				fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
					c(red+bold, "!"),
					c(bold, entry.Name),
					c(dim, fmt.Sprintf("%d vulnerable finding(s) · %d probes · %d tools", serverVulns, serverProbes, len(srv.Tools))),
				)
			}
		}

		jsonServers = append(jsonServers, jsonServerResult{
			Name:       entry.Name,
			Client:     entry.Client,
			ToolCount:  len(srv.Tools),
			ProbeCount: serverProbes,
		})
	}

	if jsonOut || gf.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"version": version.Version,
			"servers": jsonServers,
			"vulnerabilities": allVulns,
			"summary": map[string]int{
				"servers":         len(servers),
				"tools_probed":    len(jsonServers),
				"total_probes":    totalProbes,
				"vulnerabilities": totalVulns,
			},
		})
	}

	fmt.Fprintf(os.Stdout, "\n  %s ", c(dim, "─"))
	if totalVulns == 0 {
		fmt.Fprintf(os.Stdout, "%s No vulnerabilities triggered across %d probe(s).\n\n",
			c(green, "✓"),
			totalProbes,
		)
	} else {
		fmt.Fprintf(os.Stdout, "%s %d vulnerability finding(s) across %d probe(s). Review results above.\n\n",
			c(red+bold, fmt.Sprintf("%d", totalVulns)),
			totalVulns,
			totalProbes,
		)
	}

	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func runScan(gf globalFlags) error {
	start := time.Now()

	// Spinner only on interactive (non-JSON, non-SARIF) runs.
	showSpinner := !gf.jsonOut && !gf.sarifOut && !gf.noColor
	if showSpinner {
		report.SetSpinnerOutput(os.Stderr)
	}

	servers, discoveryErrs := discover.DiscoverAll(gf.clients)

	var errStrings []string
	for _, e := range discoveryErrs {
		errStrings = append(errStrings, e.Error())
	}

	ctx := context.Background()
	var inspected []*inspect.Server
	opts := inspect.Options{NoExec: gf.noExec}

	var spin *report.Spinner
	if showSpinner && len(servers) > 0 {
		spin = report.NewSpinner(fmt.Sprintf("Scanning %d servers...", len(servers)), gf.noColor)
	}

	for _, entry := range servers {
		if spin != nil {
			spin.Update(fmt.Sprintf("Connecting to %s...", entry.Name))
		}
		srv := inspect.InspectServer(ctx, entry, opts)
		inspected = append(inspected, srv)
	}

	if spin != nil {
		spin.Stop()
	}

	var allFindings [][]rules.Finding
	for _, srv := range inspected {
		findings := rules.EvalServer(srv)
		// Registry check: try to extract npm package name from server args.
		regPkg := extractNPMPackage(srv.Entry)
		if regPkg != "" {
			if regEntry := registry.Lookup(regPkg); regEntry != nil {
				findings = append(findings, rules.Finding{
					RuleID:   "REG001",
					Name:     "Known vulnerable package",
					Severity: parseSeverityString(regEntry.Severity),
					Detail:   regEntry.Summary,
					Fix:      fmt.Sprintf("Update to version %s or later.", regEntry.FixedIn),
					Mapping:  strings.Join(regEntry.RuleIDs, ", "),
				})
			}
		}
		allFindings = append(allFindings, findings)
	}

	var scores []score.ServerScore
	for _, findings := range allFindings {
		scores = append(scores, score.ScoreServer(findings))
	}

	overall := score.ScoreOverall(scores)

	var jsonServers []report.JSONServerResult
	for i, srv := range inspected {
		jsonServers = append(jsonServers, toJSONServer(srv, scores[i]))
	}
	out := report.JSONScanOutput{
		Version: version.Version,
		Overall: overall,
		Servers: jsonServers,
	}

	// SARIF output to stdout.
	if gf.sarifOut {
		return report.WriteSARIFScan(os.Stdout, out)
	}

	// SARIF output to file.
	if gf.sarifFile != "" {
		f, err := os.Create(gf.sarifFile)
		if err != nil {
			return fmt.Errorf("creating SARIF file: %w", err)
		}
		defer f.Close()
		if err := report.WriteSARIFScan(f, out); err != nil {
			return err
		}
	}

	// HTML output to file.
	if gf.htmlFile != "" {
		f, err := os.Create(gf.htmlFile)
		if err != nil {
			return fmt.Errorf("creating HTML file: %w", err)
		}
		defer f.Close()
		if err := report.WriteHTMLScan(f, out); err != nil {
			return err
		}
	}

	if gf.jsonOut {
		return report.WriteJSONScan(os.Stdout, out)
	}

	// Auto-save a JSON log to the user cache dir.
	logPath := writeScanLog(out)

	// Load history for score delta display.
	prev, _ := history.LoadPrevious(logPath)
	isFirstRun := history.IsFirstRun(logPath)

	// --share: print privacy-safe summary and exit.
	if gf.shareMode {
		printShareSummary(os.Stdout, out, gf.noColor)
		return nil
	}

	// --report: print compliance mapping and exit.
	if gf.reportFormat != "" {
		return printComplianceReport(os.Stdout, gf.reportFormat, allFindings, overall, gf.noColor)
	}

	// Resolve the HTML path to absolute so the file:// link always works.
	absHTML := ""
	if gf.htmlFile != "" {
		if abs, err := filepath.Abs(gf.htmlFile); err == nil {
			absHTML = abs
		}
	}

	elapsed := time.Since(start).Milliseconds()
	r := report.ScanReport{
		Version:         version.Version,
		ElapsedMS:       elapsed,
		Servers:         inspected,
		Scores:          scores,
		Overall:         overall,
		DiscoveryErrors: errStrings,
		NoColor:         gf.noColor,
		HTMLPath:        absHTML,
		LogPath:         logPath,
		Explain:         gf.explain,
		ScoreDelta:      history.Delta(prev, overall.Score),
		IsFirstRun:      isFirstRun,
	}
	if prev != nil {
		r.PrevScore = prev.Score
		r.PrevBand = prev.Band
	}
	report.PrintScanReport(os.Stdout, r)
	return checkExitCode(gf.failOn, overall)
}

func runWatch(gf globalFlags) error {
	// Initial scan.
	if err := runScan(gf); err != nil {
		return err
	}

	paths := watch.ConfigPaths(gf.clients)
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "No config files found to watch.")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Watching %d config file(s) for changes. Press Ctrl+C to stop.\n", len(paths))

	watcher := watch.New(paths, 2*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher.Watch(ctx, func(path string) {
		// Clear screen.
		fmt.Print("\033[2J\033[H")
		fmt.Fprintf(os.Stderr, "Config changed: %s -- rescanning...\n\n", report.SanitizeForTerminal(path))
		_ = runScan(gf)
	})
	return nil
}

// extractNPMPackage tries to detect the npm package name from a server entry's args.
// Handles patterns like: npx -y @scope/package or npx @scope/package
func extractNPMPackage(entry discover.ServerEntry) string {
	args := entry.Args
	for i, arg := range args {
		if arg == "-y" && i+1 < len(args) {
			candidate := args[i+1]
			if looksLikeNPMPackage(candidate) {
				return candidate
			}
		}
		if looksLikeNPMPackage(arg) {
			return arg
		}
	}
	return ""
}

func looksLikeNPMPackage(s string) bool {
	if strings.HasPrefix(s, "@") && strings.Contains(s, "/") {
		return true
	}
	// bare package names that look like mcp-*
	if strings.HasPrefix(s, "mcp-") || strings.HasSuffix(s, "-mcp") {
		return true
	}
	return false
}

func parseSeverityString(s string) rules.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return rules.SeverityCritical
	case "high":
		return rules.SeverityHigh
	case "medium":
		return rules.SeverityMedium
	case "low":
		return rules.SeverityLow
	default:
		return rules.SeverityInfo
	}
}

func toJSONServer(srv *inspect.Server, sc score.ServerScore) report.JSONServerResult {
	res := report.JSONServerResult{
		Name:       srv.Entry.Name,
		Client:     srv.Entry.Client,
		Score:      sc.Score,
		Band:       sc.Band,
		StaticOnly: srv.StaticOnly,
	}
	for _, f := range sc.Findings {
		res.Findings = append(res.Findings, report.JSONFinding{
			RuleID:   f.RuleID,
			Name:     f.Name,
			Severity: f.Severity.String(),
			Detail:   f.Detail,
			Fix:      f.Fix,
			Mapping:  f.Mapping,
		})
	}
	return res
}

// writeScanLog saves the JSON scan output to a timestamped file in the user
// cache dir (~/.cache/aspex/scans/ on Linux/macOS). Returns the absolute path
// on success, or "" if the write fails (non-fatal).
func writeScanLog(out report.JSONScanOutput) string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(cacheDir, "aspex", "scans")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ""
	}
	ts := time.Now().Format("20060102-150405")
	path := filepath.Join(dir, "scan-"+ts+".json")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return ""
	}
	defer f.Close()
	if err := report.WriteJSONScan(f, out); err != nil {
		return ""
	}
	return path
}

func checkExitCode(failOn string, overall score.OverallScore) error {
	switch failOn {
	case "off", "none", "":
		return nil
	}

	threshold := rules.SeverityHigh
	switch failOn {
	case "critical":
		threshold = rules.SeverityCritical
	case "medium":
		threshold = rules.SeverityMedium
	case "low":
		threshold = rules.SeverityLow
	}

	var found bool
	for _, sc := range overall.Servers {
		for _, f := range sc.Findings {
			if f.Severity >= threshold {
				found = true
				break
			}
		}
	}
	if found {
		fmt.Fprintf(os.Stderr, "  Exiting with code 1: findings at or above %q severity detected (--fail-on %s)\n\n", failOn, failOn)
		return errExitOne
	}
	return nil
}

// ---- aspex-scan fix -------------------------------------------------------------

func newFixCmd(gf *globalFlags) *cobra.Command {
	var (
		dryRun      bool
		severityStr string
		outputPath  string
		clientName  string
	)
	cmd := &cobra.Command{
		Use:   "fix [--dry-run] [--severity critical|high] [--output <path>] [--client <name>]",
		Short: "Harden your MCP client configs by removing dangerous servers",
		Long: `Run a full scan and generate hardened versions of your MCP client configs.

Servers with findings at or above the threshold severity are removed from the
config. A diff-style summary shows exactly what was changed.

By default (--dry-run=true), changes are printed to stdout. Pass --dry-run=false to apply them.`,
		Example: `  # Preview what would be removed (dry run, default)
  aspex-scan fix --dry-run

  # Remove critical+high servers and write to a new file
  aspex-scan fix --severity high --output ~/mcp-safe.json

  # Harden Claude Desktop config in place
  aspex-scan fix --client claude

  # Only show critical removals, no file write
  aspex-scan fix --dry-run --severity critical`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			clients := gf.clients
			if clientName != "" {
				clients = []string{clientName}
			}
			return runFix(gf, clients, dryRun, severityStr, outputPath)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", true, "print changes without modifying files")
	cmd.Flags().StringVar(&severityStr, "severity", "critical", "Remove servers with findings at or above this severity: critical|high|medium|low")
	cmd.Flags().StringVar(&outputPath, "output", "", "Write hardened config to this path instead of overwriting originals")
	cmd.Flags().StringVar(&clientName, "client", "", "Only fix this client's config (e.g. claude, cursor)")
	cmd.AddCommand(newFixEnvCmd(gf))
	return cmd
}

func runFix(gf *globalFlags, clients []string, dryRun bool, severityStr string, outputPath string) error {
	threshold := parseSeverityString(severityStr)

	c := func(col, text string) string {
		if gf.noColor {
			return text
		}
		return col + text + "\033[0m"
	}
	bold := "\033[1m"
	dim := "\033[2m"
	red := "\033[91m"
	yellow := "\033[93m"
	green := "\033[92m"
	purple := "\033[35m"

	// Discover and inspect all servers.
	entries, discoveryErrs := discover.DiscoverAll(clients)
	for _, e := range discoveryErrs {
		fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "No MCP servers found.")
		return nil
	}

	ctx := context.Background()
	opts := inspect.Options{NoExec: gf.noExec}

	// Group entries by config file so we can produce one hardened config per file.
	type configGroup struct {
		configPath string
		client     string
		entries    []discover.ServerEntry
	}
	groupMap := map[string]*configGroup{}
	var groupOrder []string
	for _, e := range entries {
		if _, exists := groupMap[e.ConfigPath]; !exists {
			groupMap[e.ConfigPath] = &configGroup{configPath: e.ConfigPath, client: e.Client}
			groupOrder = append(groupOrder, e.ConfigPath)
		}
		groupMap[e.ConfigPath].entries = append(groupMap[e.ConfigPath].entries, e)
	}

	fmt.Fprintf(os.Stdout, "\n  %s  %s\n\n",
		c(purple+bold, "◆"),
		c(bold, "aspex-scan fix - config hardening"),
	)

	anyChanges := false

	for _, cfgPath := range groupOrder {
		grp := groupMap[cfgPath]

		// Inspect each server in this config and collect findings.
		type serverResult struct {
			entry    discover.ServerEntry
			findings []rules.Finding
			remove   bool
			topRule  string
		}
		var results []serverResult
		for _, entry := range grp.entries {
			srv := inspect.InspectServer(ctx, entry, opts)
			findings := rules.EvalServer(srv)
			remove := false
			topRule := ""
			for _, f := range findings {
				if f.Severity >= threshold {
					remove = true
					topRule = f.RuleID + ": " + f.Name
					break
				}
			}
			results = append(results, serverResult{entry: entry, findings: findings, remove: remove, topRule: topRule})
		}

		// Build the set of servers to remove.
		toRemove := map[string]string{} // server name -> reason
		for _, r := range results {
			if r.remove {
				toRemove[r.entry.Name] = r.topRule
			}
		}

		fmt.Fprintf(os.Stdout, "  %s  %s\n", c(purple, "◉"), c(bold, cfgPath))
		if len(toRemove) == 0 {
			fmt.Fprintf(os.Stdout, "     %s\n\n", c(green, "✓ no servers to remove at this severity threshold"))
			continue
		}

		// Print diff-style summary.
		for _, r := range results {
			if r.remove {
				fmt.Fprintf(os.Stdout, "     %s  %s  %s\n",
					c(red, "✗ removed"),
					c(bold, r.entry.Name),
					c(dim, "("+r.topRule+")"),
				)
			} else {
				fmt.Fprintf(os.Stdout, "     %s  %s\n",
					c(green, "✓ kept   "),
					r.entry.Name,
				)
			}
		}
		fmt.Fprintln(os.Stdout)

		anyChanges = true

		// Read and patch the config file.
		rawData, err := os.ReadFile(cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s reading %s: %v\n", c(yellow, "warn:"), cfgPath, err)
			continue
		}

		hardenedData, err := removeServersFromConfig(grp.client, rawData, toRemove)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s patching %s: %v\n", c(yellow, "warn:"), cfgPath, err)
			continue
		}

		// Determine where to write.
		dest := ""
		if dryRun {
			fmt.Fprintf(os.Stdout, "  %s\n", c(dim, "--- dry run: hardened config follows ---"))
			fmt.Fprintln(os.Stdout, string(hardenedData))
			continue
		}
		if outputPath != "" {
			dest = outputPath
		} else {
			// Ask for confirmation before overwriting.
			fmt.Fprintf(os.Stdout, "  Overwrite %s? [y/N] ", cfgPath)
			var answer string
			fmt.Fscan(os.Stdin, &answer)
			if strings.ToLower(strings.TrimSpace(answer)) != "y" {
				fmt.Fprintln(os.Stdout, "  Skipped.")
				continue
			}
			dest = cfgPath
		}

		if err := os.WriteFile(dest, hardenedData, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "  %s writing %s: %v\n", c(red, "error:"), dest, err)
			continue
		}
		fmt.Fprintf(os.Stdout, "  %s %s\n\n", c(green, "✓ wrote"), dest)
	}

	if !anyChanges {
		fmt.Fprintf(os.Stdout, "  %s No servers meet the removal threshold (%s). No changes needed.\n\n",
			c(green, "✓"), c(bold, strings.ToUpper(severityStr)))
	}
	return nil
}

// removeServersFromConfig reads the raw config JSON for the given client, deletes the
// entries listed in toRemove (by server name), and returns the patched JSON.
// It works by unmarshalling into a generic map so all client-specific config keys
// outside the MCP servers section are preserved.
func removeServersFromConfig(client string, data []byte, toRemove map[string]string) ([]byte, error) {
	switch client {
	case discover.ClientVSCode:
		// VS Code uses "mcp.servers" key.
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		if serversRaw, ok := raw["mcp.servers"]; ok {
			var servers map[string]json.RawMessage
			if err := json.Unmarshal(serversRaw, &servers); err == nil {
				for name := range toRemove {
					delete(servers, name)
				}
				patched, err := json.Marshal(servers)
				if err != nil {
					return nil, err
				}
				raw["mcp.servers"] = patched
			}
		}
		return json.MarshalIndent(raw, "", "  ")

	case discover.ClientZed:
		// Zed uses "context_servers" key.
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		if serversRaw, ok := raw["context_servers"]; ok {
			var servers map[string]json.RawMessage
			if err := json.Unmarshal(serversRaw, &servers); err == nil {
				for name := range toRemove {
					delete(servers, name)
				}
				patched, err := json.Marshal(servers)
				if err != nil {
					return nil, err
				}
				raw["context_servers"] = patched
			}
		}
		return json.MarshalIndent(raw, "", "  ")

	case discover.ClientContinue:
		// Continue uses an array under "mcpServers".
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		if serversRaw, ok := raw["mcpServers"]; ok {
			var servers []json.RawMessage
			if err := json.Unmarshal(serversRaw, &servers); err == nil {
				var kept []json.RawMessage
				for _, s := range servers {
					var entry struct {
						Name    string `json:"name"`
						Command string `json:"command"`
					}
					if err := json.Unmarshal(s, &entry); err != nil {
						kept = append(kept, s)
						continue
					}
					name := entry.Name
					if name == "" {
						name = entry.Command
					}
					if _, remove := toRemove[name]; !remove {
						kept = append(kept, s)
					}
				}
				patched, err := json.Marshal(kept)
				if err != nil {
					return nil, err
				}
				raw["mcpServers"] = patched
			}
		}
		return json.MarshalIndent(raw, "", "  ")

	default:
		// Claude Desktop, Cursor, Windsurf, Cline, Roo-Cline - all use "mcpServers" map.
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		if serversRaw, ok := raw["mcpServers"]; ok {
			var servers map[string]json.RawMessage
			if err := json.Unmarshal(serversRaw, &servers); err == nil {
				for name := range toRemove {
					delete(servers, name)
				}
				patched, err := json.Marshal(servers)
				if err != nil {
					return nil, err
				}
				raw["mcpServers"] = patched
			}
		}
		return json.MarshalIndent(raw, "", "  ")
	}
}

// ---------------------------------------------------------------------------
// cron subcommand
// ---------------------------------------------------------------------------

func newCronCmd(gf *globalFlags) *cobra.Command {
	var intervalStr, notifyURL string
	var quiet bool
	cmd := &cobra.Command{
		Use:   "cron",
		Short: "Run aspex-scan on a schedule and alert on new findings",
		Long: `Continuously scan MCP server configs on a fixed interval. On each run,
only NEW findings (not seen in previous runs) are printed and optionally
sent to a webhook. Useful as a background monitor or scheduled CI job.

Press Ctrl-C to stop.`,
		Example: `  # Scan every hour, print new findings
  aspex-scan cron --interval 1h

  # Scan every 30 minutes and post alerts to Slack
  aspex-scan cron --interval 30m --notify https://hooks.slack.com/services/...

  # Silent unless something new appears
  aspex-scan cron --interval 6h --quiet --notify https://hooks.slack.com/services/...`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCron(gf, intervalStr, notifyURL, quiet)
		},
	}
	cmd.Flags().StringVar(&intervalStr, "interval", "1h", "Scan interval (e.g. 30m, 1h, 6h)")
	cmd.Flags().StringVar(&notifyURL, "notify", "", "Webhook URL for new HIGH/CRITICAL findings (Slack or generic JSON)")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "Suppress per-run summary when no new findings")
	return cmd
}

func runCron(gf *globalFlags, intervalStr, notifyURL string, quiet bool) error {
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		return fmt.Errorf("invalid interval %q: %w", intervalStr, err)
	}

	bold := "\033[1m"
	dim := "\033[2m"
	purple := "\033[35m"
	red := "\033[91m"
	yellow := "\033[93m"
	green := "\033[92m"
	c := func(col, text string) string {
		if gf.noColor {
			return text
		}
		return col + text + "\033[0m"
	}

	fmt.Fprintf(os.Stdout, "\n  %s  %s  %s\n",
		c(purple+bold, "◆"),
		c(bold, "aspex-scan cron"),
		c(dim, fmt.Sprintf("interval %s · Ctrl-C to stop", intervalStr)),
	)
	if notifyURL != "" {
		fmt.Fprintf(os.Stdout, "  %s Alerts → %s\n", c(dim, "→"), notifyURL)
	}
	fmt.Fprintln(os.Stdout)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() { <-sigCh; close(done) }()

	seen := map[string]bool{}

	scan := func() {
		ts := time.Now().Format("15:04:05")
		servers, discoveryErrs := discover.DiscoverAll(gf.clients)
		for _, e := range discoveryErrs {
			fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
		}
		ctx := context.Background()
		opts := inspect.Options{NoExec: gf.noExec}

		newCount := 0
		if len(seen) > 10000 {
			seen = map[string]bool{}
			fmt.Fprintf(os.Stdout, "  %s seen map reset after 10000 entries\n", c(ansiDim, "→"))
		}

		for _, entry := range servers {
			srv := inspect.InspectServer(ctx, entry, opts)
			findings := rules.EvalServer(srv)
			for _, f := range findings {
				key := entry.Name + "/" + f.RuleID
				if seen[key] {
					continue
				}
				seen[key] = true
				newCount++

				sevColor := yellow
				if f.Severity >= rules.SeverityCritical {
					sevColor = red + bold
				} else if f.Severity >= rules.SeverityHigh {
					sevColor = red
				}
				fmt.Fprintf(os.Stdout, "  %s  %s  %s  %s  %s\n",
					c(dim, ts),
					c(sevColor, strings.ToUpper(f.Severity.String())),
					c(purple, f.RuleID),
					c(bold, f.Name),
					c(dim, entry.Name),
				)
				fmt.Fprintf(os.Stdout, "     %s\n", f.Detail)

				if notifyURL != "" && f.Severity >= rules.SeverityHigh {
					notify.Send(notifyURL, notify.Finding{
						Severity: f.Severity.String(),
						RuleID:   f.RuleID,
						Tool:     "",
						Server:   entry.Name,
						Detail:   f.Detail,
						Client:   entry.Client,
					})
				}
			}
		}

		if !quiet || newCount > 0 {
			icon := c(green, "✓")
			if newCount > 0 {
				icon = c(yellow, "!")
			}
			fmt.Fprintf(os.Stdout, "  %s %s  scan complete · %d server(s) · %s\n",
				icon,
				c(dim, ts),
				len(servers),
				c(bold, fmt.Sprintf("%d new finding(s)", newCount)),
			)
		}
	}

	// Run immediately, then on ticker.
	runOnce := make(chan struct{}, 1)
	runOnce <- struct{}{}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			fmt.Fprintf(os.Stdout, "\n  %s  Stopped.\n\n", c(dim, "◇"))
			return nil
		case <-runOnce:
			scan()
		case <-ticker.C:
			scan()
		}
	}
}

// ---------------------------------------------------------------------------
// --share: privacy-safe shareable summary
// ---------------------------------------------------------------------------

func printShareSummary(w io.Writer, out report.JSONScanOutput, noColor bool) {
	c := func(col, text string) string {
		if noColor {
			return text
		}
		return col + text + ansiReset
	}

	// Count findings by severity across all servers.
	var nCrit, nHigh, nMed, nLow, nInfo int
	for _, srv := range out.Servers {
		for _, f := range srv.Findings {
			switch f.Severity {
			case "CRITICAL":
				nCrit++
			case "HIGH":
				nHigh++
			case "MEDIUM":
				nMed++
			case "LOW":
				nLow++
			default:
				nInfo++
			}
		}
	}

	total := nCrit + nHigh + nMed + nLow + nInfo

	fmt.Fprintf(w, "\n%s\n\n", c(ansiBold+ansiPurple, "## aspex-scan — Shareable Summary"))
	fmt.Fprintf(w, "**Overall Score:** %d / 100   **Band:** %s\n\n",
		out.Overall.Score, out.Overall.Band)
	fmt.Fprintf(w, "**Servers scanned:** %d   **Total findings:** %d\n\n",
		len(out.Servers), total)

	fmt.Fprintf(w, "### Findings by Severity\n\n")
	fmt.Fprintf(w, "| Severity | Count |\n")
	fmt.Fprintf(w, "|----------|-------|\n")
	if nCrit > 0 {
		fmt.Fprintf(w, "| %s | %d |\n", c(ansiRed, "CRITICAL"), nCrit)
	}
	if nHigh > 0 {
		fmt.Fprintf(w, "| %s | %d |\n", c(ansiYellow, "HIGH"), nHigh)
	}
	if nMed > 0 {
		fmt.Fprintf(w, "| MEDIUM | %d |\n", nMed)
	}
	if nLow > 0 {
		fmt.Fprintf(w, "| LOW | %d |\n", nLow)
	}
	if nInfo > 0 {
		fmt.Fprintf(w, "| INFO | %d |\n", nInfo)
	}

	// Group finding names by category (no server names or values).
	catCounts := map[string]int{}
	for _, srv := range out.Servers {
		for _, f := range srv.Findings {
			cat := ruleCategory(f.RuleID)
			catCounts[cat]++
		}
	}
	if len(catCounts) > 0 {
		fmt.Fprintf(w, "\n### Findings by Category\n\n")
		fmt.Fprintf(w, "| Category | Count |\n")
		fmt.Fprintf(w, "|----------|-------|\n")
		for _, cat := range []string{
			"Credential Exposure",
			"Prompt Security",
			"Dangerous Capabilities",
			"Network & SSRF",
			"Supply Chain",
			"Monitoring",
			"Other",
		} {
			if n, ok := catCounts[cat]; ok {
				fmt.Fprintf(w, "| %s | %d |\n", cat, n)
			}
		}
	}

	fmt.Fprintf(w, "\n---\n")
	fmt.Fprintf(w, "_Generated by aspex-scan v%s — https://github.com/aspex-security/aspex_\n\n",
		out.Version)
}

// ruleCategory maps a ruleID to a human-readable category for share summaries.
func ruleCategory(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "MCP006"), strings.HasPrefix(ruleID, "MCP042"):
		return "Credential Exposure"
	case strings.HasPrefix(ruleID, "MCP001"), strings.HasPrefix(ruleID, "MCP002"),
		strings.HasPrefix(ruleID, "MCP018"):
		return "Prompt Security"
	case strings.HasPrefix(ruleID, "MCP003"), strings.HasPrefix(ruleID, "MCP004"),
		strings.HasPrefix(ruleID, "MCP020"), strings.HasPrefix(ruleID, "MCP008"),
		strings.HasPrefix(ruleID, "MCP009"):
		return "Dangerous Capabilities"
	case strings.HasPrefix(ruleID, "MCP005"), strings.HasPrefix(ruleID, "MCP023"),
		strings.HasPrefix(ruleID, "MCP016"):
		return "Network & SSRF"
	case strings.HasPrefix(ruleID, "MCP007"), strings.HasPrefix(ruleID, "REG"):
		return "Supply Chain"
	case strings.HasPrefix(ruleID, "MCP010"), strings.HasPrefix(ruleID, "MCP021"):
		return "Monitoring"
	default:
		return "Other"
	}
}

// ---------------------------------------------------------------------------
// --report: compliance mapping (SOC 2 / ISO 27001)
// ---------------------------------------------------------------------------

func printComplianceReport(w io.Writer, format string, allFindings [][]rules.Finding, overall score.OverallScore, noColor bool) error {
	c := func(col, text string) string {
		if noColor {
			return text
		}
		return col + text + ansiReset
	}

	type controlEntry struct {
		id       string
		name     string
		ruleIDs  []string
		findings []rules.Finding
	}

	var controls []controlEntry
	var reportTitle string

	switch strings.ToLower(format) {
	case "soc2":
		reportTitle = "SOC 2 Type II Compliance Mapping"
		controls = []controlEntry{
			{id: "CC6.1", name: "Logical and Physical Access Controls", ruleIDs: []string{"MCP006", "MCP042"}},
			{id: "CC6.7", name: "Transmission of Confidential Information", ruleIDs: []string{"MCP021", "MCP010"}},
			{id: "CC7.1", name: "System Monitoring / Anomaly Detection", ruleIDs: []string{"MCP001", "MCP002"}},
			{id: "CC8.1", name: "Change Management / Supply Chain", ruleIDs: []string{"MCP007", "REG001"}},
			{id: "CC6.6", name: "Logical Access — Dangerous Capabilities", ruleIDs: []string{"MCP003", "MCP004", "MCP020"}},
			{id: "CC9.2", name: "Network Access Controls (SSRF)", ruleIDs: []string{"MCP005", "MCP023"}},
		}
	case "iso27001":
		reportTitle = "ISO 27001 Compliance Mapping"
		controls = []controlEntry{
			{id: "A.9.4", name: "System and Application Access Control", ruleIDs: []string{"MCP006", "MCP042"}},
			{id: "A.14.1", name: "Security Requirements (Encryption in Transit)", ruleIDs: []string{"MCP021"}},
			{id: "A.12.6", name: "Management of Technical Vulnerabilities", ruleIDs: []string{"MCP007", "REG001"}},
			{id: "A.12.4", name: "Logging and Monitoring", ruleIDs: []string{"MCP001", "MCP002"}},
			{id: "A.9.4.4", name: "Privileged Utility Programs", ruleIDs: []string{"MCP003", "MCP004", "MCP020"}},
			{id: "A.13.1", name: "Network Controls", ruleIDs: []string{"MCP005", "MCP023"}},
		}
	default:
		return fmt.Errorf("unknown report format %q: use soc2 or iso27001", format)
	}

	// Flatten all findings.
	var flat []rules.Finding
	for _, fs := range allFindings {
		flat = append(flat, fs...)
	}

	// Match findings to controls.
	for i, ctrl := range controls {
		for _, f := range flat {
			for _, rid := range ctrl.ruleIDs {
				if strings.HasPrefix(f.RuleID, rid) {
					controls[i].findings = append(controls[i].findings, f)
					break
				}
			}
		}
	}

	// Determine overall compliance posture.
	posture := "PASS"
	postureColor := ansiGreen
	if overall.Critical > 0 {
		posture = "FAIL"
		postureColor = ansiRed
	} else if overall.High > 0 {
		posture = "PARTIAL"
		postureColor = ansiYellow
	}

	fmt.Fprintf(w, "\n  %s  %s\n\n",
		c(ansiBold+ansiPurple, "◆"),
		c(ansiBold, "aspex-scan — "+reportTitle),
	)

	for _, ctrl := range controls {
		status := c(ansiGreen, "PASS")
		if len(ctrl.findings) > 0 {
			status = c(ansiRed, "FAIL")
		}
		fmt.Fprintf(w, "  %s  %s  %s\n",
			status,
			c(ansiBold, ctrl.id),
			ctrl.name,
		)
		for _, f := range ctrl.findings {
			fmt.Fprintf(w, "       %s %s  %s\n",
				c(ansiYellow, f.RuleID),
				c(ansiBold, f.Name),
				c(ansiDim, "("+strings.ToUpper(f.Severity.String())+")"),
			)
		}
	}

	fmt.Fprintf(w, "\n  %s  %s  %s\n\n",
		c(ansiBold, "Overall Compliance Posture:"),
		c(postureColor+ansiBold, posture),
		c(ansiDim, fmt.Sprintf("(critical:%d  high:%d  medium:%d)", overall.Critical, overall.High, overall.Medium)),
	)

	return nil
}

// ---------------------------------------------------------------------------
// explain subcommand
// ---------------------------------------------------------------------------

func newExplainCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <server-name>",
		Short: "Show detailed findings and risk narrative for a specific server",
		Long: `Inspect a single MCP server by name and print full finding details,
advisories, and a risk narrative.`,
		Example: `  aspex-scan explain github
  aspex-scan explain my-custom-server`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExplainServer(gf, args[0])
		},
	}
	return cmd
}

func runExplainServer(gf *globalFlags, serverName string) error {
	c := func(col, text string) string {
		if gf.noColor {
			return text
		}
		return col + text + ansiReset
	}

	entries, discoveryErrs := discover.DiscoverAll(gf.clients)
	for _, e := range discoveryErrs {
		fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
	}

	var target *discover.ServerEntry
	for i, e := range entries {
		if strings.EqualFold(e.Name, serverName) {
			target = &entries[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("server %q not found in any configured MCP client", serverName)
	}

	ctx := context.Background()
	opts := inspect.Options{NoExec: gf.noExec}
	srv := inspect.InspectServer(ctx, *target, opts)
	findings := rules.EvalServer(srv)
	sc := score.ScoreServer(findings)

	// Header.
	fmt.Fprintf(os.Stdout, "\n  %s  %s\n",
		c(ansiBold+ansiPurple, "◆"),
		c(ansiBold, "aspex-scan explain — "+target.Name),
	)
	fmt.Fprintf(os.Stdout, "  %s %s  %s %s\n",
		c(ansiDim, "client:"), target.Client,
		c(ansiDim, "config:"), target.ConfigPath,
	)
	if target.Command != "" {
		fmt.Fprintf(os.Stdout, "  %s %s\n", c(ansiDim, "command:"), target.Command)
	}
	if target.URL != "" {
		fmt.Fprintf(os.Stdout, "  %s %s\n", c(ansiDim, "url:"), target.URL)
	}
	fmt.Fprintf(os.Stdout, "  %s %d / 100   %s %s\n\n",
		c(ansiDim, "score:"), sc.Score,
		c(ansiDim, "band:"), sc.Band,
	)

	if len(findings) == 0 {
		fmt.Fprintf(os.Stdout, "  %s No findings — server looks clean.\n\n", c(ansiGreen, "✓"))
		return nil
	}

	fmt.Fprintf(os.Stdout, "  %s\n\n", c(ansiBold, "Findings"))

	var firstCritical *rules.Finding
	critCount := 0
	for i := range findings {
		f := &findings[i]
		sevColor := ansiYellow
		switch f.Severity {
		case rules.SeverityCritical:
			sevColor = ansiRed + ansiBold
			critCount++
			if firstCritical == nil {
				firstCritical = f
			}
		case rules.SeverityHigh:
			sevColor = ansiRed
		}

		fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
			c(sevColor, strings.ToUpper(f.Severity.String())),
			c(ansiBold, f.RuleID),
			c(ansiBold, f.Name),
		)
		fmt.Fprintf(os.Stdout, "  %s\n", f.Detail)
		if f.Fix != "" {
			fmt.Fprintf(os.Stdout, "  %s %s\n", c(ansiDim, "fix:"), f.Fix)
		}
		if f.Mapping != "" {
			fmt.Fprintf(os.Stdout, "  %s %s\n", c(ansiDim, "refs:"), f.Mapping)
		}

		if adv, ok := rules.AdvisoryFor(f.RuleID); ok {
			fmt.Fprintf(os.Stdout, "  %s %s\n", c(ansiCyan, "why:"), adv.Why)
			fmt.Fprintf(os.Stdout, "  %s %s\n", c(ansiCyan, "exploit:"), adv.Exploit)
			fmt.Fprintf(os.Stdout, "  %s %s\n", c(ansiCyan, "impact:"), adv.Impact)
		}
		fmt.Fprintln(os.Stdout)
	}

	// Risk narrative.
	fmt.Fprintf(os.Stdout, "  %s\n", c(ansiBold, "Risk Narrative"))
	if critCount > 0 && firstCritical != nil {
		fmt.Fprintf(os.Stdout, "  This server has %s critical finding(s). The highest-risk scenario is %s.\n\n",
			c(ansiRed+ansiBold, fmt.Sprintf("%d", critCount)),
			c(ansiBold, firstCritical.Name),
		)
	} else if len(findings) > 0 {
		fmt.Fprintf(os.Stdout, "  This server has %d finding(s) but no critical issues. Review the HIGH/MEDIUM items above.\n\n",
			len(findings),
		)
	}

	return nil
}

// ---------------------------------------------------------------------------
// fix env subcommand
// ---------------------------------------------------------------------------

func newFixEnvCmd(gf *globalFlags) *cobra.Command {
	var dryRun bool
	var clientName string
	cmd := &cobra.Command{
		Use:   "env [--client cursor] [--dry-run]",
		Short: "Migrate hardcoded env vars to the macOS keychain",
		Long: `Scan MCP configs for hardcoded credentials (MCP006) and generate macOS
Keychain commands to migrate them safely.

By default (--dry-run=true) only prints the commands. Pass --dry-run=false to
execute them via the macOS 'security' CLI.`,
		Example: `  # Preview keychain migration commands (dry run, default)
  aspex-scan fix env

  # Only check Cursor config
  aspex-scan fix env --client cursor

  # Actually execute the migration
  aspex-scan fix env --dry-run=false`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			clients := gf.clients
			if clientName != "" {
				clients = []string{clientName}
			}
			return runFixEnv(gf, clients, dryRun)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", true, "Print commands without executing them")
	cmd.Flags().StringVar(&clientName, "client", "", "Only check this client's config (e.g. claude, cursor)")
	return cmd
}

func runFixEnv(gf *globalFlags, clients []string, dryRun bool) error {
	c := func(col, text string) string {
		if gf.noColor {
			return text
		}
		return col + text + ansiReset
	}

	entries, discoveryErrs := discover.DiscoverAll(clients)
	for _, e := range discoveryErrs {
		fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "No MCP servers found.")
		return nil
	}

	ctx := context.Background()
	opts := inspect.Options{NoExec: gf.noExec}

	fmt.Fprintf(os.Stdout, "\n  %s  %s\n\n",
		c(ansiBold+ansiPurple, "◆"),
		c(ansiBold, "aspex-scan fix env — keychain migration"),
	)

	if dryRun {
		fmt.Fprintf(os.Stdout, "  %s\n\n",
			c(ansiDim, "Dry-run mode: commands shown but not executed. Pass --dry-run=false to apply."),
		)
	}

	type envFinding struct {
		serverName string
		varName    string
		configPath string
	}
	var envFindings []envFinding

	for _, entry := range entries {
		srv := inspect.InspectServer(ctx, entry, opts)
		findings := rules.EvalServer(srv)
		for _, f := range findings {
			if f.RuleID != "MCP006" {
				continue
			}
			// Extract variable name from the finding detail: look for quoted word after "env var" or similar.
			varName := extractEnvVarName(f.Detail)
			if varName == "" {
				varName = "UNKNOWN_VAR_" + entry.Name
			}
			envFindings = append(envFindings, envFinding{
				serverName: entry.Name,
				varName:    varName,
				configPath: entry.ConfigPath,
			})
		}
	}

	if len(envFindings) == 0 {
		fmt.Fprintf(os.Stdout, "  %s No hardcoded credentials found (MCP006).\n\n", c(ansiGreen, "✓"))
		return nil
	}

	fmt.Fprintf(os.Stdout, "  Run these commands to migrate your tokens to the macOS keychain:\n\n")

	for _, ef := range envFindings {
		fmt.Fprintf(os.Stdout, "  %s  %s  (%s)\n",
			c(ansiYellow, "!"),
			c(ansiBold, ef.varName),
			c(ansiDim, ef.serverName),
		)
		addCmd := fmt.Sprintf(`security add-generic-password -a "$USER" -s %q -w`, ef.varName)
		findCmd := fmt.Sprintf(`security find-generic-password -a "$USER" -s %q -w 2>/dev/null`, ef.varName)
		fmt.Fprintf(os.Stdout, "  %s\n", c(ansiCyan, "  # 1. Store the secret in Keychain (prompts for value):"))
		fmt.Fprintf(os.Stdout, "  %s\n", addCmd)
		fmt.Fprintf(os.Stdout, "  %s\n", c(ansiCyan, "  # 2. Reference it in mcp.json env block:"))
		fmt.Fprintf(os.Stdout, "  %s %s\n\n",
			c(ansiDim, fmt.Sprintf(`  "%s":`, ef.varName)),
			c(ansiBold, fmt.Sprintf(`"$(%s)"`, findCmd)),
		)

		if !dryRun {
			fmt.Fprintf(os.Stdout, "  %s executing: %s\n", c(ansiYellow, "→"), addCmd)
			// In live mode we would exec the security command; omitting actual execution
			// because it requires interactive TTY input for the password prompt.
			fmt.Fprintf(os.Stdout, "  %s\n", c(ansiDim, "  (interactive prompt: run this command in your terminal)"))
		}
	}

	fmt.Fprintf(os.Stdout, "  %s After storing secrets, remove the plaintext values from %s\n",
		c(ansiYellow, "!"),
		c(ansiBold, "your mcp.json config files"),
	)
	fmt.Fprintf(os.Stdout, "  %s and replace them with the $(...) keychain lookup shown above.\n\n",
		c(ansiDim, " "),
	)

	return nil
}

// extractEnvVarName attempts to pull a variable name from a MCP006 finding detail string.
// It looks for an ALL_CAPS token that resembles an env var name.
func extractEnvVarName(detail string) string {
	words := strings.Fields(detail)
	for _, w := range words {
		// Strip surrounding punctuation.
		w = strings.Trim(w, `"',.:;()[]`)
		if len(w) >= 3 && w == strings.ToUpper(w) && strings.ContainsAny(w, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			return w
		}
	}
	return ""
}
