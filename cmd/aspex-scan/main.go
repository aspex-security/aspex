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

	"github.com/aspex-security/aspex/internal/diff"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/hook"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/registry"
	"github.com/aspex-security/aspex/internal/report"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/score"
	"github.com/aspex-security/aspex/internal/version"
	"github.com/aspex-security/aspex/internal/watch"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
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
		Use:   "aspex-scan",
		Short: "Scan your MCP servers for security risks",
		Long: `aspex-scan reads every MCP client config on this machine,
enumerates all servers and tools, and produces a scored risk report.

No data is sent anywhere. This tool is offline by default.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if gf.watchMode {
				return runWatch(gf)
			}
			return runScan(gf)
		},
	}

	root.PersistentFlags().BoolVar(&gf.noExec, "no-exec", false, "Static analysis only; do not launch MCP servers")
	root.PersistentFlags().BoolVar(&gf.jsonOut, "json", false, "Machine-readable JSON output")
	root.PersistentFlags().BoolVar(&gf.noColor, "no-color", false, "Disable color output")
	root.PersistentFlags().StringVar(&gf.failOn, "fail-on", "off", "Exit 1 if findings at/above this severity: critical, high, medium, low (default off)")
	root.PersistentFlags().StringSliceVar(&gf.clients, "clients", discover.AllClients, "Clients to scan (comma-separated)")
	root.PersistentFlags().BoolVar(&gf.sarifOut, "sarif", false, "Output SARIF to stdout")
	root.PersistentFlags().StringVar(&gf.sarifFile, "sarif-output", "", "Write SARIF to file")
	root.PersistentFlags().StringVar(&gf.htmlFile, "html", "", "Write HTML report to file")
	root.PersistentFlags().BoolVar(&gf.watchMode, "watch", false, "Watch config files for changes and rescan automatically")

	root.AddCommand(newInspectCmd(&gf))
	root.AddCommand(newVersionCmd())
	root.AddCommand(newDiffCmd(&gf))
	root.AddCommand(newInstallHookCmd())
	root.AddCommand(newUninstallHookCmd())
	root.AddCommand(newVerifyCmd())

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("aspex-scan %s (built %s)\n", version.Version, version.BuildDate)
		},
	}
}

func newInspectCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <server-command-or-url>",
		Short: "Inspect a single MCP server",
		Args:  cobra.ExactArgs(1),
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
		Use:   "diff",
		Short: "Compare current scan results to a baseline JSON file",
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
		Use:   "install-hook",
		Short: "Install a git pre-commit hook that runs aspex-scan",
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
		Short: "Remove the aspex-scan git pre-commit hook",
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
		Use:   "verify <package-name>",
		Short: "Check a package name against the known-bad registry",
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
		fmt.Fprintf(os.Stderr, "Config changed: %s -- rescanning...\n\n", path)
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
		os.Exit(1)
	}
	return nil
}
