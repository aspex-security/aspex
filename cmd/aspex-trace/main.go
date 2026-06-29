package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/aspex-security/aspex/internal/baseline"
	"github.com/aspex-security/aspex/internal/notify"
	"github.com/aspex-security/aspex/internal/killchain"
	"github.com/aspex-security/aspex/internal/provenance"
	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/report"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/trace"
	"github.com/aspex-security/aspex/internal/version"
)

// errTraceExitOne is returned by checkTraceExitCode when --fail-on threshold is
// met. main() converts it to os.Exit(1) after all defers have run.
var errTraceExitOne = fmt.Errorf("exit:1")

func main() {
	if err := newRootCmd().Execute(); err != nil {
		if err == errTraceExitOne {
			os.Exit(1)
		}
		os.Exit(2)
	}
}

type traceFlags struct {
	client        string
	server        string
	since         string
	jsonOut       bool
	noColor       bool
	failOn        string
	sarifOut      bool
	baseline      string
	suppressNoise bool
	summary       bool
}

var supportedClients = []string{"claude", "claude-code", "cursor", "windsurf", "cline", "roo-cline"}

func newRootCmd() *cobra.Command {
	var tf traceFlags

	root := &cobra.Command{
		Use:   "aspex-trace [flags]",
		Short: "Audit what your AI agents actually did",
		Long: `aspex-trace - AI Agent Activity Auditor

Reads the logs that Claude Desktop, Claude Code, Cursor, Windsurf, Cline,
Roo Code and other MCP clients already write to disk. Parses them into a
unified audit trail and flags suspicious or sensitive tool call activity
using 85+ detection rules.

No proxy. No config changes. No data sent anywhere. Runs entirely offline.

QUICK START
  aspex-trace                        Scan the last 24 h of all agent activity
  aspex-trace --since 7d             Scan the last 7 days
  aspex-trace --client claude-code   Only Claude Code sessions
  aspex-trace --suppress-noise       Hide low-signal alerts for coding sessions
  aspex-trace --summary              Compact stats view, no per-event breakdown

FILTERING
  aspex-trace --server filesystem    Focus on one MCP server
  aspex-trace --client cursor        Focus on one client (claude|claude-code|cursor|windsurf|cline|roo-cline)

OUTPUT & INTEGRATION
  aspex-trace --json                 Machine-readable JSON (pipe to jq, etc.)
  aspex-trace --sarif                SARIF 2.1.0 for GitHub Advanced Security
  aspex-trace --fail-on high         Exit 1 on HIGH or CRITICAL findings (CI)
  aspex-trace --no-color             Plain text (for logging / scripts)

SUBCOMMANDS
  aspex-trace stats                  Activity dashboard without rule evaluation
  aspex-trace session <id>           Forensic timeline for one session
  aspex-trace export                 Export all events to CSV or JSONL
  aspex-trace live                   Real-time monitoring - tails logs as they grow
  aspex-trace baseline --learn       Learn normal behavior from recent logs

BASELINES
  aspex-trace baseline --learn --since 7d --output ~/my-baseline.json
  aspex-trace --baseline ~/my-baseline.json   Flag deviations from baseline`,
		Example: `  # Everyday audit
  aspex-trace

  # Investigate the last week, only Cursor sessions
  aspex-trace --since 7d --client cursor

  # CI gate - fail the build on any high-severity finding
  aspex-trace --fail-on high --json | jq '.flagged | length'

  # Build a normal-behavior baseline, then detect deviations
  aspex-trace baseline --learn --since 7d
  aspex-trace --baseline ~/.config/aspex/aspex-trace-baseline.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("NO_COLOR") != "" {
				tf.noColor = true
			}
			return runTrace(tf)
		},
	}

	root.Flags().StringVar(&tf.client, "client", "", "Limit to one client: "+strings.Join(supportedClients, "|"))
	root.Flags().StringVar(&tf.server, "server", "", "Limit to one MCP server name (e.g. filesystem, github)")
	root.Flags().StringVar(&tf.since, "since", "24h", "How far back to scan (e.g. 1h, 24h, 7d, 30d)")
	root.Flags().BoolVar(&tf.jsonOut, "json", false, "JSON output - pipe to jq or feed into SIEM")
	root.Flags().BoolVar(&tf.noColor, "no-color", false, "Plain-text output (useful in CI logs)")
	root.Flags().StringVar(&tf.failOn, "fail-on", "high", "Exit 1 when findings reach this severity: critical|high|medium|low")
	root.Flags().BoolVar(&tf.sarifOut, "sarif", false, "SARIF 2.1.0 output for GitHub Advanced Security / Semgrep")
	root.Flags().StringVar(&tf.baseline, "baseline", "", "Compare against a saved baseline; flag deviations as additional findings")
	root.Flags().BoolVar(&tf.suppressNoise, "suppress-noise", false, "Suppress expected alerts for coding-agent sessions (after-hours, etc.)")
	root.Flags().BoolVar(&tf.summary, "summary", false, "Compact view: stats + finding count only, no per-event detail")

	root.PersistentFlags().BoolP("version", "v", false, "Print version and exit")
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if v, _ := cmd.Flags().GetBool("version"); v {
			fmt.Printf("aspex-trace %s (built %s)\n", version.Version, version.BuildDate)
			os.Exit(0)
		}
		return nil
	}

	root.AddCommand(newVersionCmd())
	root.AddCommand(newBaselineCmd())
	root.AddCommand(newStatsCmd())
	root.AddCommand(newSessionCmd())
	root.AddCommand(newExportCmd())
	root.AddCommand(newLiveCmd())
	root.AddCommand(newKillChainCmd())
	root.AddCommand(newProvenanceCmd())
	root.AddCommand(newCompletionCmd())

	return root
}

func newVersionCmd() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("aspex-trace %s (built %s)\n", version.Version, version.BuildDate)
			if check {
				fmt.Print("Checking for updates... ")
				latest := version.CheckLatest()
				if latest != "" {
					fmt.Printf("\nUpdate available: %s → %s\n", version.Version, latest)
					fmt.Println("  brew upgrade aspex-security/tap/aspex")
					fmt.Println("  npm update -g aspex-agent-trace")
				} else {
					fmt.Println("already up to date.")
				}
			}
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "Check GitHub for a newer release")
	return cmd
}

// ---------------------------------------------------------------------------
// stats subcommand
// ---------------------------------------------------------------------------

func newStatsCmd() *cobra.Command {
	var since, client string
	var noColor bool
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show activity dashboard without running detection rules",
		Long: `Print a concise activity summary for your AI agents: total events, per-client
and per-server breakdowns, most-called tools, and an hourly heatmap.

Unlike the default command, no detection rules are evaluated - this is purely
informational and is much faster on large log sets.`,
		Example: `  # Last 24 hours dashboard
  aspex-trace stats

  # 7-day breakdown for Cursor only
  aspex-trace stats --since 7d --client cursor`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStats(since, client, noColor)
		},
	}
	cmd.Flags().StringVar(&since, "since", "24h", "How far back to look")
	cmd.Flags().StringVar(&client, "client", "", "Filter to one client")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Plain-text output")
	return cmd
}

func runStats(since, clientFilter string, noColor bool) error {
	sinceDur, err := parseSince(since)
	if err != nil {
		return fmt.Errorf("invalid --since value: %w", err)
	}
	_ = sinceDur
	sinceTime := time.Now().Add(-sinceDur)

	allEvents, _ := collectEvents(clientFilter, sinceTime)
	act := report.ComputeActivity(allEvents)

	c := colorFunc(noColor)
	bold := "\033[1m"
	dim := "\033[2m"
	purple := "\033[35m"
	cyan := "\033[36m"

	fmt.Fprintf(os.Stdout, "\n  %s  %s  %s\n\n",
		c(purple+bold, "◆"),
		c(bold, "Agent Activity"),
		c(dim, fmt.Sprintf("last %s · %d events", since, len(allEvents))),
	)

	// Per-client breakdown
	clientCounts := map[string]int{}
	serverCounts := map[string]int{}
	toolCounts := map[string]int{}
	for _, ev := range allEvents {
		clientCounts[ev.Client]++
		if ev.Server != "" {
			serverCounts[ev.Server]++
		}
		if ev.Tool != "" {
			toolCounts[ev.Tool]++
		}
	}

	fmt.Fprintf(os.Stdout, "  %s\n", c(bold, "Clients"))
	for _, cl := range sortedByCount(clientCounts) {
		fmt.Fprintf(os.Stdout, "    %s %s %s\n",
			c(cyan, fmt.Sprintf("%-18s", cl)),
			bar(clientCounts[cl], len(allEvents), 20, noColor),
			c(dim, fmt.Sprintf("%d", clientCounts[cl])),
		)
	}

	fmt.Fprintf(os.Stdout, "\n  %s\n", c(bold, "Servers"))
	for i, sv := range sortedByCount(serverCounts) {
		if i >= 10 {
			break
		}
		fmt.Fprintf(os.Stdout, "    %s %s %s\n",
			c(cyan, fmt.Sprintf("%-18s", sv)),
			bar(serverCounts[sv], len(allEvents), 20, noColor),
			c(dim, fmt.Sprintf("%d", serverCounts[sv])),
		)
	}

	fmt.Fprintf(os.Stdout, "\n  %s\n", c(bold, "Top Tools"))
	for i, t := range sortedByCount(toolCounts) {
		if i >= 8 {
			break
		}
		fmt.Fprintf(os.Stdout, "    %s %s %s\n",
			c(cyan, fmt.Sprintf("%-18s", t)),
			bar(toolCounts[t], len(allEvents), 20, noColor),
			c(dim, fmt.Sprintf("%d", toolCounts[t])),
		)
	}

	// Top paths heatmap
	if len(act.TopPaths) > 0 {
		fmt.Fprintf(os.Stdout, "\n  %s\n", c(bold, "Active Paths"))
		for i, p := range act.TopPaths {
			if i >= 5 {
				break
			}
			fmt.Fprintf(os.Stdout, "    %s %s\n",
				c(dim, fmt.Sprintf("%-4d", p.Count)),
				p.Name,
			)
		}
	}
	fmt.Fprintln(os.Stdout)
	return nil
}

// ---------------------------------------------------------------------------
// session subcommand (novel forensics capability)
// ---------------------------------------------------------------------------

func newSessionCmd() *cobra.Command {
	var since, client, server string
	var noColor, jsonOut bool
	cmd := &cobra.Command{
		Use:   "session [session-id]",
		Short: "Reconstruct a forensic timeline for a single agent session",
		Long: `Reconstruct a complete, chronologically-ordered timeline for one AI agent
session. Shows every MCP tool call, the arguments passed, and all detection
rule findings - in the order they happened.

This is the single-session "what exactly did the agent do?" view. It is
especially useful after an incident: given a session ID from the main report,
you can drill down into the exact sequence of actions.

If no session-id is provided, lists recent sessions so you can pick one.

SESSION IDs are derived from the client, date, and server: client/YYYY-MM-DD/server
or you can pass a substring and aspex-trace will fuzzy-match against recent sessions.`,
		Example: `  # List recent sessions
  aspex-trace session

  # Forensic timeline for a specific session
  aspex-trace session claude-code/2024-01-15/filesystem

  # Any session matching "filesystem" in the last 7 days
  aspex-trace session filesystem --since 7d

  # JSON for pipeline processing
  aspex-trace session filesystem --json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			query := ""
			if len(args) > 0 {
				query = args[0]
			}
			return runSession(query, since, client, server, noColor, jsonOut)
		},
	}
	cmd.Flags().StringVar(&since, "since", "7d", "How far back to look")
	cmd.Flags().StringVar(&client, "client", "", "Filter to one client")
	cmd.Flags().StringVar(&server, "server", "", "Filter to one server")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Plain-text output")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	return cmd
}

type sessionSummary struct {
	ID         string    `json:"id"`
	Client     string    `json:"client"`
	Server     string    `json:"server"`
	StartTime  time.Time `json:"start_time"`
	EventCount int       `json:"event_count"`
}

func buildSessionID(ev logparse.Event) string {
	day := ev.Timestamp.Format("2006-01-02")
	return ev.Client + "/" + day + "/" + ev.Server
}

func runSession(query, since, clientFilter, serverFilter string, noColor, jsonOut bool) error {
	sinceDur, err := parseSince(since)
	if err != nil {
		return fmt.Errorf("invalid --since value: %w", err)
	}
	sinceTime := time.Now().Add(-sinceDur)

	allEvents, _ := collectEvents(clientFilter, sinceTime)

	// Group events into sessions keyed by client/day/server
	sessionMap := map[string][]logparse.Event{}
	for _, ev := range allEvents {
		if ev.Server == "" {
			continue
		}
		if serverFilter != "" && ev.Server != serverFilter {
			continue
		}
		sid := buildSessionID(ev)
		sessionMap[sid] = append(sessionMap[sid], ev)
	}

	// If no query, list sessions
	if query == "" {
		var sessions []sessionSummary
		for sid, evs := range sessionMap {
			if len(evs) == 0 {
				continue
			}
			start := evs[0].Timestamp
			for _, ev := range evs {
				if !ev.Timestamp.IsZero() && ev.Timestamp.Before(start) {
					start = ev.Timestamp
				}
			}
			sessions = append(sessions, sessionSummary{
				ID:         sid,
				Client:     evs[0].Client,
				Server:     evs[0].Server,
				StartTime:  start,
				EventCount: len(evs),
			})
		}
		sort.Slice(sessions, func(i, j int) bool {
			return sessions[i].StartTime.After(sessions[j].StartTime)
		})

		if jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(sessions)
		}

		c := colorFunc(noColor)
		bold := "\033[1m"
		dim := "\033[2m"
		purple := "\033[35m"
		cyan := "\033[36m"

		fmt.Fprintf(os.Stdout, "\n  %s  %s  %s\n\n",
			c(purple+bold, "◆"),
			c(bold, "Recent Sessions"),
			c(dim, fmt.Sprintf("last %s · %d sessions", since, len(sessions))),
		)
		for i, s := range sessions {
			if i >= 20 {
				fmt.Fprintf(os.Stdout, "  %s\n", c(dim, fmt.Sprintf("  … and %d more", len(sessions)-20)))
				break
			}
			fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
				c(cyan, fmt.Sprintf("%-40s", s.ID)),
				c(dim, s.StartTime.Format("Jan 02 15:04")),
				c(dim, fmt.Sprintf("%d events", s.EventCount)),
			)
		}
		fmt.Fprintf(os.Stdout, "\n  %s aspex-trace session <id>\n\n", c(dim, "→ drill into a session:"))
		return nil
	}

	// Find sessions matching the query
	var matchedSID string
	var matchedEvents []logparse.Event
	for sid, evs := range sessionMap {
		if strings.Contains(sid, query) {
			if len(evs) > len(matchedEvents) {
				matchedSID = sid
				matchedEvents = evs
			}
		}
	}
	if len(matchedEvents) == 0 {
		return fmt.Errorf("no session matching %q found in the last %s", query, since)
	}

	// Sort chronologically
	sort.Slice(matchedEvents, func(i, j int) bool {
		return matchedEvents[i].Timestamp.Before(matchedEvents[j].Timestamp)
	})

	// Evaluate detection rules on these events
	flagged := trace.AnalyzeEvents(matchedEvents)
	findingsByEventIndex := map[int][]rules.Finding{}
	for _, fe := range flagged {
		for i, ev := range matchedEvents {
			if ev.Timestamp.Equal(fe.Event.Timestamp) && ev.Tool == fe.Event.Tool {
				findingsByEventIndex[i] = append(findingsByEventIndex[i], fe.Findings...)
			}
		}
	}

	if jsonOut {
		type jsonEvent struct {
			Index     int             `json:"index"`
			Timestamp time.Time       `json:"timestamp"`
			Client    string          `json:"client"`
			Server    string          `json:"server"`
			Tool      string          `json:"tool"`
			Args      json.RawMessage `json:"args,omitempty"`
			Findings  []rules.Finding `json:"findings,omitempty"`
		}
		type jsonSession struct {
			ID         string      `json:"session_id"`
			EventCount int         `json:"event_count"`
			Events     []jsonEvent `json:"events"`
		}
		var evs []jsonEvent
		for i, ev := range matchedEvents {
			var rawArgs json.RawMessage
			if ev.Args != nil {
				rawArgs, _ = json.Marshal(ev.Args)
			}
			evs = append(evs, jsonEvent{
				Index:     i,
				Timestamp: ev.Timestamp,
				Client:    ev.Client,
				Server:    ev.Server,
				Tool:      ev.Tool,
				Args:      rawArgs,
				Findings:  findingsByEventIndex[i],
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(jsonSession{
			ID:         matchedSID,
			EventCount: len(matchedEvents),
			Events:     evs,
		})
	}

	c := colorFunc(noColor)
	bold := "\033[1m"
	dim := "\033[2m"
	purple := "\033[35m"
	cyan := "\033[36m"
	red := "\033[91m"
	yellow := "\033[93m"

	fmt.Fprintf(os.Stdout, "\n  %s  %s\n  %s %s\n\n",
		c(purple+bold, "◆"),
		c(bold, "Session Timeline: "+matchedSID),
		c(dim, "events:"),
		c(cyan, fmt.Sprintf("%d", len(matchedEvents))),
	)

	for i, ev := range matchedEvents {
		ts := "-"
		if !ev.Timestamp.IsZero() {
			ts = ev.Timestamp.Format("15:04:05")
		}
		findings := findingsByEventIndex[i]
		marker := c(dim, "│")
		if len(findings) > 0 {
			maxSev := findings[0].Severity
			for _, f := range findings {
				if f.Severity > maxSev {
					maxSev = f.Severity
				}
			}
			switch {
			case maxSev >= rules.SeverityCritical:
				marker = c(red+bold, "█")
			case maxSev >= rules.SeverityHigh:
				marker = c(red, "▶")
			case maxSev >= rules.SeverityMedium:
				marker = c(yellow, "▷")
			}
		}
		fmt.Fprintf(os.Stdout, "  %s %s  %s  %s\n",
			marker,
			c(dim, ts),
			c(bold, ev.Tool),
			c(dim, ev.Server),
		)
		for _, f := range findings {
			sevStr := strings.ToUpper(f.Severity.String()[:1])
			fmt.Fprintf(os.Stdout, "       %s %s %s\n",
				c(yellow, "["+sevStr+"]"),
				c(bold, f.RuleID+":"),
				f.Detail,
			)
		}
	}
	fmt.Fprintln(os.Stdout)
	return nil
}

// ---------------------------------------------------------------------------
// export subcommand
// ---------------------------------------------------------------------------

func newExportCmd() *cobra.Command {
	var since, client, format, output string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export all agent events to CSV or JSONL for external analysis",
		Long: `Export every parsed MCP tool call event to a flat file. Useful for feeding
into a SIEM, running custom analysis in Python/R, or archiving audit logs.

Formats:
  csv    - spreadsheet-compatible, one row per event
  jsonl  - one JSON object per line (NDJSON), easy to stream into jq`,
		Example: `  # Export last 7 days to CSV
  aspex-trace export --since 7d --format csv --output events.csv

  # JSONL to stdout, pipe to jq
  aspex-trace export --format jsonl | jq 'select(.severity=="critical")'

  # Only Cursor events
  aspex-trace export --client cursor --format csv`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExport(since, client, format, output)
		},
	}
	cmd.Flags().StringVar(&since, "since", "7d", "How far back to export")
	cmd.Flags().StringVar(&client, "client", "", "Filter to one client")
	cmd.Flags().StringVar(&format, "format", "jsonl", "Output format: csv|jsonl")
	cmd.Flags().StringVar(&output, "output", "", "Write to file instead of stdout")
	return cmd
}

func runExport(since, clientFilter, format, outputPath string) error {
	sinceDur, err := parseSince(since)
	if err != nil {
		return fmt.Errorf("invalid --since value: %w", err)
	}
	sinceTime := time.Now().Add(-sinceDur)

	allEvents, _ := collectEvents(clientFilter, sinceTime)

	// Sort chronologically
	sort.Slice(allEvents, func(i, j int) bool {
		return allEvents[i].Timestamp.Before(allEvents[j].Timestamp)
	})

	flagged := trace.AnalyzeEvents(allEvents)
	findingsMap := map[string][]rules.Finding{}
	for _, fe := range flagged {
		key := fe.Event.Timestamp.Format(time.RFC3339Nano) + "/" + fe.Event.Tool
		findingsMap[key] = append(findingsMap[key], fe.Findings...)
	}

	out := os.Stdout
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	switch format {
	case "csv":
		w := csv.NewWriter(out)
		_ = w.Write([]string{"timestamp", "client", "server", "tool", "args", "rule_ids", "max_severity"})
		for _, ev := range allEvents {
			key := ev.Timestamp.Format(time.RFC3339Nano) + "/" + ev.Tool
			findings := findingsMap[key]
			ruleIDs := ""
			maxSev := ""
			if len(findings) > 0 {
				ids := make([]string, len(findings))
				maxS := findings[0].Severity
				for i, f := range findings {
					ids[i] = f.RuleID
					if f.Severity > maxS {
						maxS = f.Severity
					}
				}
				ruleIDs = strings.Join(ids, " ")
				maxSev = maxS.String()
			}
			argsStr := ""
			if ev.Args != nil {
				b, _ := json.Marshal(ev.Args)
				argsStr = string(b)
			}
			_ = w.Write([]string{
				ev.Timestamp.Format(time.RFC3339),
				ev.Client,
				ev.Server,
				ev.Tool,
				argsStr,
				ruleIDs,
				maxSev,
			})
		}
		w.Flush()
		return w.Error()

	case "jsonl":
		type jsonlEvent struct {
			Timestamp  string          `json:"timestamp"`
			Client     string          `json:"client"`
			Server     string          `json:"server"`
			Tool       string          `json:"tool"`
			Args       json.RawMessage `json:"args,omitempty"`
			RuleIDs    []string        `json:"rule_ids,omitempty"`
			MaxSeverity string         `json:"max_severity,omitempty"`
		}
		enc := json.NewEncoder(out)
		for _, ev := range allEvents {
			key := ev.Timestamp.Format(time.RFC3339Nano) + "/" + ev.Tool
			findings := findingsMap[key]
			var ruleIDs []string
			maxSev := ""
			if len(findings) > 0 {
				maxS := findings[0].Severity
				for _, f := range findings {
					ruleIDs = append(ruleIDs, f.RuleID)
					if f.Severity > maxS {
						maxS = f.Severity
					}
				}
				maxSev = maxS.String()
			}
			var rawArgs json.RawMessage
			if ev.Args != nil {
				rawArgs, _ = json.Marshal(ev.Args)
			}
			if err := enc.Encode(jsonlEvent{
				Timestamp:   ev.Timestamp.Format(time.RFC3339),
				Client:      ev.Client,
				Server:      ev.Server,
				Tool:        ev.Tool,
				Args:        rawArgs,
				RuleIDs:     ruleIDs,
				MaxSeverity: maxSev,
			}); err != nil {
				return err
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown format %q - use csv or jsonl", format)
	}
}

// ---------------------------------------------------------------------------
// live subcommand
// ---------------------------------------------------------------------------

func newLiveCmd() *cobra.Command {
	var client, server string
	var noColor bool
	var interval int
	var notifyURL string
	cmd := &cobra.Command{
		Use:   "live",
		Short: "Real-time monitoring - tails agent logs and prints new findings as they arrive",
		Long: `Poll agent logs every N seconds and print any new flagged events as they
appear. Useful during an active session to watch for suspicious activity in
real time.

Press Ctrl-C to stop. Findings already shown are not repeated.`,
		Example: `  # Watch all clients, refresh every 5 seconds
  aspex-trace live

  # Watch only Claude Code, refresh every 2 seconds
  aspex-trace live --client claude-code --interval 2

  # Send HIGH/CRITICAL findings to a Slack webhook
  aspex-trace live --notify https://hooks.slack.com/services/...`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLive(client, server, noColor, interval, notifyURL)
		},
	}
	cmd.Flags().StringVar(&client, "client", "", "Filter to one client")
	cmd.Flags().StringVar(&server, "server", "", "Filter to one server")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Plain-text output")
	cmd.Flags().IntVar(&interval, "interval", 5, "Polling interval in seconds")
	cmd.Flags().StringVar(&notifyURL, "notify", "", "Webhook URL for HIGH/CRITICAL findings (Slack or generic JSON)")
	return cmd
}

func runLive(clientFilter, serverFilter string, noColor bool, intervalSecs int, notifyURL string) error {
	c := colorFunc(noColor)
	bold := "\033[1m"
	dim := "\033[2m"
	purple := "\033[35m"
	red := "\033[91m"
	yellow := "\033[93m"
	green := "\033[92m"

	fmt.Fprintf(os.Stdout, "\n  %s  %s  %s\n\n",
		c(purple+bold, "◆"),
		c(bold, "aspex-trace live"),
		c(dim, fmt.Sprintf("polling every %ds · Ctrl-C to stop", intervalSecs)),
	)

	if notifyURL != "" {
		fmt.Fprintf(os.Stdout, "  %s Alerts %s %s\n\n",
			c(dim, "→"),
			c(dim, "→"),
			c(dim, notifyURL),
		)
	}

	// Handle Ctrl-C cleanly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		<-sigCh
		close(done)
	}()

	seen := map[string]bool{}
	interval := time.Duration(intervalSecs) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	findingCount := 0

	for {
		select {
		case <-done:
			fmt.Fprintf(os.Stdout, "\n  %s  Stopped. %s %d finding(s) in this session.\n\n",
				c(dim, "◇"),
				c(dim, "→"),
				findingCount,
			)
			if findingCount > 0 {
				fmt.Fprintf(os.Stdout, "  %s Run %s for a full analysis.\n\n",
					c(dim, "→"),
					c(bold, "aspex-trace --since 1h"),
				)
			} else {
				fmt.Fprintf(os.Stdout, "  %s %s\n\n",
					c(green, "✓"),
					c(dim, "No anomalies detected while watching."),
				)
			}
			return nil

		case <-ticker.C:
			sinceTime := time.Now().Add(-2 * interval)
			allEvents, _ := collectEvents(clientFilter, sinceTime)

			if serverFilter != "" {
				filtered := allEvents[:0]
				for _, ev := range allEvents {
					if ev.Server == serverFilter {
						filtered = append(filtered, ev)
					}
				}
				allEvents = filtered
			}

			flagged := trace.AnalyzeEvents(allEvents)
			for _, fe := range flagged {
				key := fe.Event.Timestamp.Format(time.RFC3339Nano) + "/" + fe.Event.Tool + "/" + fe.Event.Server
				if seen[key] {
					continue
				}
				seen[key] = true

				ts := fe.Event.Timestamp.Format("15:04:05")
				for _, f := range fe.Findings {
					sevColor := yellow
					if f.Severity >= rules.SeverityCritical {
						sevColor = red + bold
					} else if f.Severity >= rules.SeverityHigh {
						sevColor = red
					}
					fmt.Fprintf(os.Stdout, "  %s  %s  %s  %s  %s\n",
						c(dim, ts),
						c(sevColor, strings.ToUpper(f.Severity.String())),
						c(bold, f.RuleID),
						c(bold, fe.Event.Tool),
						c(dim, fe.Event.Server),
					)
					fmt.Fprintf(os.Stdout, "     %s\n", f.Detail)
					findingCount++

					if notifyURL != "" && (f.Severity >= rules.SeverityHigh) {
						notify.Send(notifyURL, notify.Finding{
							Severity: strings.ToUpper(f.Severity.String()),
							RuleID:   f.RuleID,
							Tool:     fe.Event.Tool,
							Server:   fe.Event.Server,
							Detail:   f.Detail,
							Client:   fe.Event.Client,
						})
					}
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// provenance subcommand
// ---------------------------------------------------------------------------

func newProvenanceCmd() *cobra.Command {
	var since, client string
	var noColor, jsonOut bool
	cmd := &cobra.Command{
		Use:   "provenance",
		Short: "Trace the likely source of suspicious tool calls back to ingested content",
		Long: `For every high-severity finding, identify the content-ingestion event that
most likely delivered the injected instruction.

When an AI agent reads a file or fetches a URL and then immediately executes
a suspicious command or exfiltrates data, the content it consumed is the
most probable source of the injected instruction. This command makes that
link explicit - turning "something suspicious happened" into "the agent read
X, then did Y: here is the likely injection vector."

Ingestion events tracked:
  file_read     read_file, get_file_contents, read_multiple_files, …
  web_fetch     fetch, http_get, web_fetch, http_request, …
  browser_load  browser_navigate, navigate_to, open_url, …
  resource_read get_resource, load_resource, use_prompt, …

Confidence levels:
  HIGH    < 30 seconds and ≤ 3 events between ingestion and suspicious call
  MEDIUM  < 2 minutes and ≤ 8 events
  LOW     within the lookback window (10 minutes / 20 events)`,
		Example: `  # Trace injection sources in the last 7 days
  aspex-trace provenance --since 7d

  # JSON for SIEM ingest or custom analysis
  aspex-trace provenance --json

  # Focus on a specific client
  aspex-trace provenance --client cursor --since 30d`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProvenance(since, client, noColor, jsonOut)
		},
	}
	cmd.Flags().StringVar(&since, "since", "7d", "How far back to analyze")
	cmd.Flags().StringVar(&client, "client", "", "Filter to one client")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Plain-text output")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	return cmd
}

func runProvenance(since, clientFilter string, noColor, jsonOut bool) error {
	sinceDur, err := parseSince(since)
	if err != nil {
		return fmt.Errorf("invalid --since value: %w", err)
	}
	sinceTime := time.Now().Add(-sinceDur)

	allEvents, _ := collectEvents(clientFilter, sinceTime)
	flagged := trace.AnalyzeEvents(allEvents)
	report := provenance.Analyze(allEvents, flagged)

	if jsonOut {
		type jsonFinding struct {
			RuleID   string `json:"rule_id"`
			Name     string `json:"name"`
			Severity string `json:"severity"`
			Detail   string `json:"detail"`
		}
		type jsonAttr struct {
			SuspiciousTimestamp string        `json:"suspicious_timestamp"`
			SuspiciousTool      string        `json:"suspicious_tool"`
			SuspiciousServer    string        `json:"suspicious_server"`
			Findings            []jsonFinding `json:"findings"`
			IngestionTimestamp  string        `json:"ingestion_timestamp"`
			IngestionTool       string        `json:"ingestion_tool"`
			IngestionKind       string        `json:"ingestion_kind"`
			IngestionSource     string        `json:"ingestion_source"`
			DeltaSeconds        float64       `json:"delta_seconds"`
			EventsApart         int           `json:"events_apart"`
			Confidence          string        `json:"confidence"`
			Explanation         string        `json:"explanation"`
		}
		type jsonReport struct {
			Version        string     `json:"version"`
			Since          string     `json:"since"`
			TotalEvents    int        `json:"total_events"`
			TotalFlagged   int        `json:"total_flagged"`
			WithProvenance int        `json:"with_provenance"`
			Attributions   []jsonAttr `json:"attributions"`
		}
		var attrs []jsonAttr
		for _, a := range report.Attributions {
			var jf []jsonFinding
			for _, f := range a.Findings {
				jf = append(jf, jsonFinding{
					RuleID:   f.RuleID,
					Name:     f.Name,
					Severity: f.Severity.String(),
					Detail:   f.Detail,
				})
			}
			attrs = append(attrs, jsonAttr{
				SuspiciousTimestamp: a.SuspiciousEvent.Timestamp.Format(time.RFC3339),
				SuspiciousTool:      a.SuspiciousEvent.Tool,
				SuspiciousServer:    a.SuspiciousEvent.Server,
				Findings:            jf,
				IngestionTimestamp:  a.IngestionEvent.Timestamp.Format(time.RFC3339),
				IngestionTool:       a.IngestionEvent.Tool,
				IngestionKind:       a.IngestionKind,
				IngestionSource:     a.IngestionSource,
				DeltaSeconds:        a.Delta.Seconds(),
				EventsApart:         a.EventsApart,
				Confidence:          a.Confidence,
				Explanation:         a.Explanation,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(jsonReport{
			Version:        version.Version,
			Since:          since,
			TotalEvents:    report.TotalEvents,
			TotalFlagged:   report.TotalFlagged,
			WithProvenance: report.WithProvenance,
			Attributions:   attrs,
		})
	}

	c := colorFunc(noColor)
	bold := "\033[1m"
	dim := "\033[2m"
	purple := "\033[35m"
	red := "\033[91m"
	yellow := "\033[93m"
	cyan := "\033[36m"
	green := "\033[92m"

	fmt.Fprintf(os.Stdout, "\n  %s  %s  %s\n\n",
		c(purple+bold, "◆"),
		c(bold, "Instruction Provenance"),
		c(dim, fmt.Sprintf("last %s · %d events · %d findings · %d with provenance",
			since, report.TotalEvents, report.TotalFlagged, report.WithProvenance)),
	)

	if len(report.Attributions) == 0 {
		fmt.Fprintf(os.Stdout, "  %s  No suspicious calls preceded by content ingestion.\n\n",
			c(green, "✓"),
		)
		if report.TotalFlagged > 0 {
			fmt.Fprintf(os.Stdout, "  %s %d findings exist but none follow an identifiable ingestion event.\n",
				c(dim, "→"),
				report.TotalFlagged,
			)
			fmt.Fprintf(os.Stdout, "  %s They may have been triggered by direct user instruction.\n\n",
				c(dim, " "),
			)
		}
		return nil
	}

	confColor := func(conf string) string {
		switch conf {
		case "high":
			return red + bold
		case "medium":
			return yellow + bold
		default:
			return dim
		}
	}

	for _, attr := range report.Attributions {
		ts := attr.SuspiciousEvent.Timestamp.Format("Jan 02 15:04:05")
		fmt.Fprintf(os.Stdout, "  %s  %s %s  %s\n",
			c(confColor(attr.Confidence), strings.ToUpper(attr.Confidence)+" CONFIDENCE"),
			c(bold, attr.SuspiciousEvent.Tool),
			c(dim, "via "+attr.SuspiciousEvent.Server),
			c(dim, ts),
		)

		// Show top findings.
		for _, f := range attr.Findings {
			if f.Severity >= rules.SeverityHigh {
				fmt.Fprintf(os.Stdout, "     %s %s  %s\n",
					c(yellow, f.RuleID+":"),
					c(bold, f.Name),
					c(dim, f.Detail),
				)
			}
		}

		// The provenance link.
		deltaStr := attr.Delta.Truncate(time.Second).String()
		ingestTs := attr.IngestionEvent.Timestamp.Format("15:04:05")
		fmt.Fprintf(os.Stdout, "\n     %s  %s %s\n",
			c(dim, "⬆ injection source"),
			c(cyan, attr.IngestionKind),
			c(dim, "@ "+ingestTs),
		)
		fmt.Fprintf(os.Stdout, "        %s %s %s %s\n",
			c(dim, "tool:"),
			c(bold, attr.IngestionEvent.Tool),
			c(dim, "· source:"),
			c(cyan, attr.IngestionSource),
		)
		fmt.Fprintf(os.Stdout, "        %s %s earlier · %d event(s) apart\n",
			c(dim, "→"),
			c(dim, deltaStr),
			attr.EventsApart,
		)
		fmt.Fprintf(os.Stdout, "        %s\n\n", c(dim, attr.Explanation))
	}

	fmt.Fprintf(os.Stdout, "  %s %d attribution(s). Run %s to drill into a session.\n\n",
		c(dim, "─"),
		len(report.Attributions),
		c(bold, "aspex-trace session"),
	)
	return nil
}

// ---------------------------------------------------------------------------
// killchain subcommand
// ---------------------------------------------------------------------------

func newKillChainCmd() *cobra.Command {
	var since, client string
	var noColor, jsonOut bool
	cmd := &cobra.Command{
		Use:   "killchain",
		Short: "Reconstruct multi-step attack kill chains from agent event logs",
		Long: `Analyze agent event logs for multi-event sequences that together form a
complete attack kill chain - not just individual suspicious events, but the
orchestrated sequence that proves an attack was attempted or succeeded.

Patterns detected:
  Credential Exfiltration   sensitive file read → outbound network call (< 5 min)
  Persistence Establishment shell exec → write to startup location
  Recon to Credential Theft enumeration / recon → credential file access
  Cross-Server Data Chain   credential read via server A → outbound call via server B
  Prompt Injection Signature server becomes active with high-risk calls in unexpected context

This is the difference between "something looked suspicious" and "here is the
evidence that an attack happened."`,
		Example: `  # Detect kill chains in the last 7 days
  aspex-trace killchain --since 7d

  # JSON output for SIEM ingest
  aspex-trace killchain --json

  # Only Cursor sessions
  aspex-trace killchain --client cursor`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKillChain(since, client, noColor, jsonOut)
		},
	}
	cmd.Flags().StringVar(&since, "since", "7d", "How far back to analyze")
	cmd.Flags().StringVar(&client, "client", "", "Filter to one client")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Plain-text output")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	return cmd
}

func runKillChain(since, clientFilter string, noColor, jsonOut bool) error {
	sinceDur, err := parseSince(since)
	if err != nil {
		return fmt.Errorf("invalid --since value: %w", err)
	}
	sinceTime := time.Now().Add(-sinceDur)

	allEvents, _ := collectEvents(clientFilter, sinceTime)
	flagged := trace.AnalyzeEvents(allEvents)
	chains := killchain.Analyze(allEvents, flagged)

	if jsonOut {
		type jsonStep struct {
			Timestamp string   `json:"timestamp"`
			Tool      string   `json:"tool"`
			Server    string   `json:"server"`
			RuleIDs   []string `json:"rule_ids"`
			Detail    string   `json:"detail"`
		}
		type jsonChain struct {
			Name        string     `json:"name"`
			Severity    string     `json:"severity"`
			Description string     `json:"description"`
			MITRETactic string     `json:"mitre_tactic"`
			MITRERef    string     `json:"mitre_ref"`
			WindowStart string     `json:"window_start"`
			WindowEnd   string     `json:"window_end"`
			Client      string     `json:"client"`
			Server      string     `json:"server"`
			Steps       []jsonStep `json:"steps"`
		}
		type jsonOut struct {
			Version     string      `json:"version"`
			Since       string      `json:"since"`
			TotalEvents int         `json:"total_events"`
			Chains      []jsonChain `json:"chains"`
		}
		var jChains []jsonChain
		for _, ch := range chains {
			var steps []jsonStep
			for _, s := range ch.Steps {
				steps = append(steps, jsonStep{
					Timestamp: s.Timestamp.Format(time.RFC3339),
					Tool:      s.Tool,
					Server:    s.Server,
					RuleIDs:   s.RuleIDs,
					Detail:    s.Detail,
				})
			}
			jChains = append(jChains, jsonChain{
				Name:        ch.Name,
				Severity:    ch.Severity,
				Description: ch.Description,
				MITRETactic: ch.MITRETactic,
				MITRERef:    ch.MITRERef,
				WindowStart: ch.WindowStart.Format(time.RFC3339),
				WindowEnd:   ch.WindowEnd.Format(time.RFC3339),
				Client:      ch.Client,
				Server:      ch.Server,
				Steps:       steps,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(jsonOut{
			Version:     version.Version,
			Since:       since,
			TotalEvents: len(allEvents),
			Chains:      jChains,
		})
	}

	c := colorFunc(noColor)
	bold := "\033[1m"
	dim := "\033[2m"
	purple := "\033[35m"
	red := "\033[91m"
	yellow := "\033[93m"
	cyan := "\033[36m"
	green := "\033[92m"

	fmt.Fprintf(os.Stdout, "\n  %s  %s  %s\n\n",
		c(purple+bold, "◆"),
		c(bold, "Kill Chain Analysis"),
		c(dim, fmt.Sprintf("last %s · %d events analyzed", since, len(allEvents))),
	)

	if len(chains) == 0 {
		fmt.Fprintf(os.Stdout, "  %s  No multi-step attack patterns detected.\n\n",
			c(green, "✓"),
		)
		fmt.Fprintf(os.Stdout, "  %s %d events analyzed. Individual findings: run %s\n\n",
			c(dim, "→"),
			len(allEvents),
			c(bold, "aspex-trace --since "+since),
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
		ts := ""
		if !ch.WindowStart.IsZero() {
			ts = ch.WindowStart.Format("Jan 02 15:04:05")
		}
		fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
			c(sevColor(ch.Severity), strings.ToUpper(ch.Severity)),
			c(bold, ch.Name),
			c(dim, "· "+ts),
		)
		fmt.Fprintf(os.Stdout, "     %s\n", ch.Description)
		fmt.Fprintf(os.Stdout, "     %s %s\n",
			c(dim, "tactic:"),
			c(cyan, ch.MITRETactic+" ("+ch.MITRERef+")"),
		)
		for i, step := range ch.Steps {
			connector := "├"
			if i == len(ch.Steps)-1 {
				connector = "╰"
			}
			stepTs := ""
			if !step.Timestamp.IsZero() {
				stepTs = step.Timestamp.Format("15:04:05") + "  "
			}
			fmt.Fprintf(os.Stdout, "     %s %s%s  %s\n",
				c(dim, connector),
				c(dim, stepTs),
				c(bold, step.Tool),
				c(dim, step.Detail),
			)
		}
		fmt.Fprintln(os.Stdout)
	}

	fmt.Fprintf(os.Stdout, "  %s %d kill chain(s) detected. Run %s to drill into a session.\n\n",
		c(dim, "─"),
		len(chains),
		c(bold, "aspex-trace session"),
	)
	return nil
}

// ---------------------------------------------------------------------------
// completion subcommand
// ---------------------------------------------------------------------------

func newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate a shell completion script for aspex-trace.

Bash:
  source <(aspex-trace completion bash)
  # or: aspex-trace completion bash > /etc/bash_completion.d/aspex-trace

Zsh:
  aspex-trace completion zsh > "${fpath[1]}/_aspex-trace"

Fish:
  aspex-trace completion fish | source`,
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

// ---------------------------------------------------------------------------
// baseline subcommand
// ---------------------------------------------------------------------------

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
		Short: "Learn normal agent behavior and detect deviations",
		Long: `Learn normal MCP agent behavior from recent logs and save a baseline profile.

The baseline captures which MCP servers are typically used, what tools are called,
and at what frequency. Run aspex-trace with --baseline to surface anything that
deviates from that normal pattern - new servers, unusual tools, or spikes in activity.`,
		Example: `  # Learn from the last 7 days of activity
  aspex-trace baseline --learn --since 7d

  # Save to a custom location
  aspex-trace baseline --learn --output ~/aspex-baseline.json

  # Now use it to flag deviations
  aspex-trace --baseline ~/aspex-baseline.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBaseline(bf)
		},
	}

	cmd.Flags().BoolVar(&bf.learn, "learn", false, "Learn a baseline from recent logs")
	cmd.Flags().StringVar(&bf.output, "output", "", "Output file path (default: ~/.config/aspex/aspex-trace-baseline.json)")
	cmd.Flags().StringVar(&bf.since, "since", "7d", "How far back to learn from (e.g. 24h, 7d)")
	cmd.Flags().StringVar(&bf.client, "client", "", "Filter to one client (claude, cursor, cline, …)")

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
	sinceTime := time.Now().Add(-sinceDur)

	allEvents, _ := collectEvents(bf.client, sinceTime)

	clientLabel := bf.client
	if clientLabel == "" {
		clientLabel = "all"
	}

	b := baseline.Learn(clientLabel, allEvents)

	outPath := bf.output
	if outPath == "" {
		outPath = defaultBaselinePath()
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	if err := baseline.Save(b, outPath); err != nil {
		return fmt.Errorf("saving baseline: %w", err)
	}

	fmt.Printf("Baseline saved: %d events, %d servers profiled.\n", len(allEvents), len(b.Profiles))
	return nil
}

// ---------------------------------------------------------------------------
// runTrace (root command)
// ---------------------------------------------------------------------------

func runTrace(tf traceFlags) error {
	sinceDur, err := parseSince(tf.since)
	if err != nil {
		return fmt.Errorf("invalid --since value: %w", err)
	}
	sinceTime := time.Now().Add(-sinceDur)

	allEvents, clientsFound := collectEvents(tf.client, sinceTime)

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
	serverSet := map[string]struct{}{}
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
				sev := deviationSeverity(dev.Severity)
				finding := rules.Finding{
					RuleID:   "baseline-" + dev.Kind,
					Name:     "Baseline deviation: " + dev.Kind,
					Severity: sev,
					Detail:   dev.Detail,
				}
				merged := false
				for i := range flagged {
					if flagged[i].Event.Server == dev.ServerName {
						flagged[i].Findings = append(flagged[i].Findings, finding)
						merged = true
						break
					}
				}
				if !merged {
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

	// Suppress low-signal rules for known coding-agent clients.
	codingAgents := map[string]bool{"claude-code": true, "cursor": true, "windsurf": true, "cline": true, "roo-cline": true}
	allCodingAgents := len(clientsFound) > 0
	for _, cl := range clientsFound {
		if !codingAgents[cl] {
			allCodingAgents = false
			break
		}
	}
	if tf.suppressNoise || allCodingAgents {
		flagged = suppressCodingAgentNoise(flagged)
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
		Activity:    report.ComputeActivity(allEvents),
		NoColor:     tf.noColor,
		SummaryOnly: tf.summary,
	}
	report.PrintTraceReport(os.Stdout, r)
	return checkTraceExitCode(tf.failOn, flagged)
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// collectEvents loads events from all supported clients, optionally filtered.
func collectEvents(clientFilter string, since time.Time) ([]logparse.Event, []string) {
	clients := supportedClients
	if clientFilter != "" {
		clients = []string{clientFilter}
	}

	var allEvents []logparse.Event
	var clientsFound []string

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
		case "cline":
			dirs = logparse.ClineLogPaths()
		case "roo-cline":
			dirs = logparse.RooCodeLogPaths()
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
			case "cline":
				evs, parseErr = logparse.ParseClineTasksDir(dir, since)
			case "roo-cline":
				evs, parseErr = logparse.ParseRooCodeTasksDir(dir, since)
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
	return allEvents, clientsFound
}

func suppressCodingAgentNoise(flagged []trace.FlaggedEvent) []trace.FlaggedEvent {
	suppressRules := map[string]bool{
		"AT005": true,
		"AT004": true,
	}
	var out []trace.FlaggedEvent
	for _, fe := range flagged {
		var keep []rules.Finding
		for _, f := range fe.Findings {
			if !suppressRules[f.RuleID] {
				keep = append(keep, f)
			}
		}
		if len(keep) > 0 {
			fe.Findings = keep
			out = append(out, fe)
		}
	}
	return out
}

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
				return errTraceExitOne
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

// ---------------------------------------------------------------------------
// display helpers
// ---------------------------------------------------------------------------

func colorFunc(noColor bool) func(string, string) string {
	return func(col, text string) string {
		if noColor {
			return text
		}
		return col + text + "\033[0m"
	}
}

func sortedByCount(m map[string]int) []string {
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.k
	}
	return out
}

func bar(val, total, width int, noColor bool) string {
	if total == 0 {
		return strings.Repeat(" ", width)
	}
	filled := (val * width) / total
	if filled < 1 && val > 0 {
		filled = 1
	}
	b := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	if noColor {
		return b
	}
	return "\033[36m" + b + "\033[0m"
}
