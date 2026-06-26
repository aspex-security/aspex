package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/aspex-security/aspex/internal/baseline"
	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/report"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/trace"
	"github.com/aspex-security/aspex/internal/version"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(2)
	}
}

type traceFlags struct {
	client   string
	server   string
	since    string
	jsonOut  bool
	noColor  bool
	failOn   string
	follow   bool
	sarifOut bool
	baseline string
}

func newRootCmd() *cobra.Command {
	var tf traceFlags

	root := &cobra.Command{
		Use:   "aspex-trace",
		Short: "Audit what your MCP agents actually did",
		Long: `aspex-trace reads the native log files that Claude Desktop, Claude Code,
Cursor, and other MCP clients already write to disk, parses them into a
unified audit trail, and flags anomalous or sensitive tool call activity.

No proxy, no config modification, no data sent anywhere.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrace(tf)
		},
	}

	root.Flags().StringVar(&tf.client, "client", "", "Filter to one client (claude, claude-code, cursor)")
	root.Flags().StringVar(&tf.server, "server", "", "Filter to one MCP server name")
	root.Flags().StringVar(&tf.since, "since", "24h", "How far back to look (e.g. 24h, 7d)")
	root.Flags().BoolVar(&tf.jsonOut, "json", false, "Machine-readable JSON output")
	root.Flags().BoolVar(&tf.noColor, "no-color", false, "Disable color output")
	root.Flags().StringVar(&tf.failOn, "fail-on", "high", "Exit 1 if flagged events at/above severity (critical, high, medium, low)")
	root.Flags().BoolVar(&tf.follow, "follow", false, "Tail mode: stream new events as they arrive (not yet implemented)")
	root.Flags().BoolVar(&tf.sarifOut, "sarif", false, "Output SARIF 2.1.0 instead of default format")
	root.Flags().StringVar(&tf.baseline, "baseline", "", "Path to baseline file; deviations are merged into findings")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newBaselineCmd())

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("aspex-trace %s (built %s)\n", version.Version, version.BuildDate)
		},
	}
}

type baselineFlags struct {
	learn  bool
	output string
	since  string
	client string
}

func defaultBaselinePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "aspex-trace-baseline.json"
	}
	return filepath.Join(home, ".config", "aspex", "aspex-trace-baseline.json")
}

func newBaselineCmd() *cobra.Command {
	var bf baselineFlags

	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Learn or manage behavioral baselines",
		Long: `Learn normal MCP agent behavior from recent logs and save a baseline profile.
The baseline can later be used with --baseline to detect deviations.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBaseline(bf)
		},
	}

	cmd.Flags().BoolVar(&bf.learn, "learn", false, "Learn a baseline from recent logs")
	cmd.Flags().StringVar(&bf.output, "output", "", "Output file path (default: ~/.config/aspex/aspex-trace-baseline.json)")
	cmd.Flags().StringVar(&bf.since, "since", "7d", "How far back to learn from (e.g. 24h, 7d)")
	cmd.Flags().StringVar(&bf.client, "client", "", "Filter to one client (claude, cursor)")

	return cmd
}

func runBaseline(bf baselineFlags) error {
	if !bf.learn {
		return fmt.Errorf("specify --learn to build a baseline")
	}

	sinceDur, err := parseSince(bf.since)
	if err != nil {
		return fmt.Errorf("invalid --since value: %w", err)
	}
	since := time.Now().Add(-sinceDur)

	var allEvents []logparse.Event

	clients := []string{"claude", "claude-code", "cursor", "windsurf"}
	if bf.client != "" {
		clients = []string{bf.client}
	}

	for _, cl := range clients {
		var dirs []string
		switch cl {
		case "claude":
			dirs = logparse.ClaudeLogPaths()
		case "claude-code":
			dirs = logparse.ClaudeCodeLogPaths()
		case "cursor":
			dirs = logparse.CursorLogPaths()
		case "windsurf":
			dirs = logparse.WindsurfLogPaths()
		}
		for _, dir := range dirs {
			var evs []logparse.Event
			var parseErr error
			switch cl {
			case "claude":
				evs, parseErr = logparse.ParseClaudeLogsDir(dir, since)
			case "claude-code":
				evs, parseErr = logparse.ParseClaudeCodeProjectsDir(dir, since)
			case "cursor":
				evs, parseErr = logparse.ParseCursorLogsDir(dir, since)
			case "windsurf":
				evs, parseErr = logparse.ParseWindsurfLogsDir(dir, since)
			}
			if parseErr != nil {
				fmt.Fprintf(os.Stderr, "warning: %s logs (%s): %v\n", cl, dir, parseErr)
				continue
			}
			allEvents = append(allEvents, evs...)
		}
	}

	clientLabel := bf.client
	if clientLabel == "" {
		clientLabel = "all"
	}

	b := baseline.Learn(clientLabel, allEvents)

	outPath := bf.output
	if outPath == "" {
		outPath = defaultBaselinePath()
	}

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	if err := baseline.Save(b, outPath); err != nil {
		return fmt.Errorf("saving baseline: %w", err)
	}

	fmt.Printf("Baseline saved: %d events, %d servers profiled.\n", len(allEvents), len(b.Profiles))
	return nil
}

func runTrace(tf traceFlags) error {
	sinceDur, err := parseSince(tf.since)
	if err != nil {
		return fmt.Errorf("invalid --since value: %w", err)
	}
	since := time.Now().Add(-sinceDur)

	var allEvents []logparse.Event
	var clientsFound []string
	serverSet := map[string]struct{}{}

	clients := []string{"claude", "claude-code", "cursor", "windsurf"}
	if tf.client != "" {
		clients = []string{tf.client}
	}

	for _, cl := range clients {
		var dirs []string
		switch cl {
		case "claude":
			dirs = logparse.ClaudeLogPaths()
		case "claude-code":
			dirs = logparse.ClaudeCodeLogPaths()
		case "cursor":
			dirs = logparse.CursorLogPaths()
		case "windsurf":
			dirs = logparse.WindsurfLogPaths()
		}
		found := false
		for _, dir := range dirs {
			var evs []logparse.Event
			var parseErr error
			switch cl {
			case "claude":
				evs, parseErr = logparse.ParseClaudeLogsDir(dir, since)
			case "claude-code":
				evs, parseErr = logparse.ParseClaudeCodeProjectsDir(dir, since)
			case "cursor":
				evs, parseErr = logparse.ParseCursorLogsDir(dir, since)
			case "windsurf":
				evs, parseErr = logparse.ParseWindsurfLogsDir(dir, since)
			}
			if parseErr != nil {
				fmt.Fprintf(os.Stderr, "warning: %s logs (%s): %v\n", cl, dir, parseErr)
				continue
			}
			if len(evs) > 0 {
				found = true
			}
			allEvents = append(allEvents, evs...)
		}
		if found {
			clientsFound = append(clientsFound, cl)
		}
	}

	// Apply server filter.
	if tf.server != "" {
		filtered := allEvents[:0]
		for _, ev := range allEvents {
			if ev.Server == tf.server {
				filtered = append(filtered, ev)
			}
		}
		allEvents = filtered
	}

	// Collect server names.
	for _, ev := range allEvents {
		if ev.Server != "" {
			serverSet[ev.Server] = struct{}{}
		}
	}
	servers := make([]string, 0, len(serverSet))
	for s := range serverSet {
		servers = append(servers, s)
	}

	flagged := trace.AnalyzeEvents(allEvents)

	// If a baseline file is provided, compare and merge deviations as additional findings.
	if tf.baseline != "" {
		b, err := baseline.Load(tf.baseline)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not load baseline %s: %v\n", tf.baseline, err)
		} else {
			deviations := baseline.Compare(b, allEvents)
			for _, dev := range deviations {
				// Find or create a synthetic FlaggedEvent for this deviation.
				sev := deviationSeverity(dev.Severity)
				finding := rules.Finding{
					RuleID:   "baseline-" + dev.Kind,
					Name:     "Baseline deviation: " + dev.Kind,
					Severity: sev,
					Detail:   dev.Detail,
				}
				// Attach the finding to the first matching event for this server,
				// or create a synthetic FlaggedEvent.
				merged := false
				for i := range flagged {
					if flagged[i].Event.Server == dev.ServerName {
						flagged[i].Findings = append(flagged[i].Findings, finding)
						merged = true
						break
					}
				}
				if !merged {
					// Create a synthetic event reference for the deviation.
					syntheticEvent := logparse.Event{
						Server: dev.ServerName,
						Client: b.ClientName,
					}
					flagged = append(flagged, trace.FlaggedEvent{
						Event:    syntheticEvent,
						Findings: []rules.Finding{finding},
					})
				}
			}
		}
	}

	if tf.sarifOut {
		return report.WriteSARIFTrace(os.Stdout, version.Version, flagged)
	}

	if tf.jsonOut {
		return report.WriteJSONTrace(os.Stdout, version.Version, flagged, len(allEvents))
	}

	r := report.TraceReport{
		Version:     version.Version,
		Since:       sinceDur,
		TotalEvents: len(allEvents),
		Sessions:    countSessions(allEvents),
		Servers:     servers,
		Clients:     clientsFound,
		Flagged:     flagged,
		NoColor:     tf.noColor,
	}
	report.PrintTraceReport(os.Stdout, r)
	return checkTraceExitCode(tf.failOn, flagged)
}

// deviationSeverity maps a baseline severity string to a rules.Severity.
func deviationSeverity(s string) rules.Severity {
	switch s {
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

func parseSince(s string) (time.Duration, error) {
	// Support "7d" shorthand as well as standard Go durations.
	if len(s) > 1 && s[len(s)-1] == 'd' {
		days := s[:len(s)-1]
		var d int
		if _, err := fmt.Sscanf(days, "%d", &d); err != nil {
			return 0, fmt.Errorf("cannot parse %q", s)
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func countSessions(events []logparse.Event) int {
	sessions := map[string]struct{}{}
	for _, ev := range events {
		if ev.Event == logparse.EventInitialize {
			key := ev.Client + "/" + ev.Server + "/" + ev.Timestamp.Format("2006-01-02T15")
			sessions[key] = struct{}{}
		}
	}
	if len(sessions) == 0 && len(events) > 0 {
		return 1
	}
	return len(sessions)
}

func checkTraceExitCode(failOn string, flagged []trace.FlaggedEvent) error {
	threshold := parseTraceSeverity(failOn)
	for _, fe := range flagged {
		for _, f := range fe.Findings {
			if f.Severity >= threshold {
				os.Exit(1)
			}
		}
	}
	return nil
}

func parseTraceSeverity(s string) rules.Severity {
	switch s {
	case "critical":
		return rules.SeverityCritical
	case "high":
		return rules.SeverityHigh
	case "medium":
		return rules.SeverityMedium
	case "low":
		return rules.SeverityLow
	}
	return rules.SeverityHigh
}
