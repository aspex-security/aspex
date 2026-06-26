package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/diff"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/hook"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/mcpclient"
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
	noExec     bool
	jsonOut    bool
	noColor    bool
	failOn     string
	clients    []string
	sarifOut   bool
	sarifFile  string
	htmlFile   string
	watchMode  bool
}

func newRootCmd() *cobra.Command {
	var gf globalFlags

	root := &cobra.Command{
		Use:   "aspex-scan [flags]",
		Short: "Scan your MCP servers for security risks",
		Long: `aspex-scan — MCP Server Security Scanner

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

  # Watch mode — rescan when any config file changes
  aspex-scan --watch`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
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
	root.PersistentFlags().BoolVar(&gf.jsonOut, "json", false, "JSON output — pipe to jq or feed into SIEM")
	root.PersistentFlags().BoolVar(&gf.noColor, "no-color", false, "Plain-text output (useful in CI logs)")
	root.PersistentFlags().StringVar(&gf.failOn, "fail-on", "off", "Exit 1 when findings reach this severity: critical|high|medium|low")
	root.PersistentFlags().StringSliceVar(&gf.clients, "clients", discover.AllClients, "Clients to scan: claude,cursor,vscode,windsurf,cline,roo-cline,continue,zed")
	root.PersistentFlags().BoolVar(&gf.sarifOut, "sarif", false, "SARIF 2.1.0 output to stdout for GitHub Advanced Security")
	root.PersistentFlags().StringVar(&gf.sarifFile, "sarif-output", "", "Write SARIF 2.1.0 to a file")
	root.PersistentFlags().StringVar(&gf.htmlFile, "html", "", "Save a shareable HTML report to this path")
	root.PersistentFlags().BoolVar(&gf.watchMode, "watch", false, "Auto-rescan when MCP config files change")

	root.AddCommand(newInspectCmd(&gf))
	root.AddCommand(newVersionCmd())
	root.AddCommand(newDiffCmd(&gf))
	root.AddCommand(newInstallHookCmd())
	root.AddCommand(newUninstallHookCmd())
	root.AddCommand(newVerifyCmd())
	root.AddCommand(newInventoryCmd(&gf))
	root.AddCommand(newAttackPathsCmd(&gf))
	root.AddCommand(newShadowCmd(&gf))
	root.AddCommand(newCompletionCmd())

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
and prompts — without running any detection rules or scoring.

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
	servers, _ := discover.DiscoverAll(gf.clients)
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
		c(dim, fmt.Sprintf("— %d servers · %d tools", out.TotalServers, out.TotalTools)),
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
that together form complete attack chains — even when no single server looks
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
	servers, _ := discover.DiscoverAll(gf.clients)
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

	for _, ch := range chains {
		fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
			c(sevColor(ch.Severity), strings.ToUpper(ch.Severity)),
			c(bold, ch.Name),
			c(dim, "· "+ch.MITRETactic+" ("+ch.MITRERef+")"),
		)
		fmt.Fprintf(os.Stdout, "     %s\n", c(dim, ch.Description))
		fmt.Fprintf(os.Stdout, "     %s %s\n", c(dim, "servers:"), c(cyan, strings.Join(ch.Servers, " → ")))
		for _, step := range ch.Steps {
			fmt.Fprintf(os.Stdout, "     %s %s\n", c(dim, "│"), step)
		}
		fmt.Fprintln(os.Stdout)
	}

	fmt.Fprintf(os.Stdout, "  %s %d attack chain(s) found across %d server(s).\n\n",
		c(dim, "─"),
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
		Long: `Scan for tool name shadowing — a class of attack where a malicious or
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
	servers, _ := discover.DiscoverAll(gf.clients)
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
		fmt.Fprintf(os.Stdout, "  %s  No tool name collisions found — every tool name is unique across your servers.\n\n",
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
			servers, _ := discover.DiscoverAll(gf.clients)
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
