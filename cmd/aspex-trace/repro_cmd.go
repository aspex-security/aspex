package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/repro"
	"github.com/aspex-security/aspex/internal/version"
)

func newReproCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "repro",
		Short: "Package an investigation for offline reproduction (redacted; nothing is executed)",
		Long: `A reproduction bundle holds the redacted trace events of a window or one
session, the environment model (servers, capabilities, hooks, skills, attack
paths; never secret values), and the findings, kill chains and provenance at
export time. Anyone can replay the analysis with aspex-trace replay; nothing
recorded is ever executed.

Secret-shaped values (tokens, keys, Authorization headers, PEM blocks) are
redacted, content-bearing arguments are dropped, and credential-file contents
never leave. Review events.json before sharing; paths, URLs, server and tool
names are kept because the analysis reasons about them.`,
	}
	var since, session, client string
	create := &cobra.Command{
		Use:           "create <dir>",
		Short:         "Write a reproduction bundle to <dir>",
		Example:       "  aspex-trace repro create ./repro --since 24h\n  aspex-trace repro create ./repro --session claude-code/3f2a1b",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			window, err := parseSince(since)
			if err != nil {
				return err
			}
			events, _ := collectEvents(client, time.Now().Add(-window))
			if session != "" {
				var keep []logparse.Event
				for _, ev := range events {
					if buildSessionID(ev) == session || ev.Session == session || strings.HasSuffix(buildSessionID(ev), "/"+session) || strings.HasPrefix(ev.Session, session) {
						keep = append(keep, ev)
					}
				}
				events = keep
			}
			if len(events) == 0 {
				return fmt.Errorf("no events matched (window %s, session %q)", since, session)
			}
			// Environment: configs only; a bundle must never launch servers.
			entries, _ := discover.DiscoverAll(discover.AllClients)
			inspected := inspect.InspectAll(cmd.Context(), entries, inspect.Options{NoExec: true}, nil)
			cwd, _ := os.Getwd()
			env := agentenv.Build(inspected, agentenv.Options{Cwd: cwd})
			m, err := repro.Create(args[0], repro.Inputs{Events: events, Env: env, Session: session, Window: since, Version: version.Version})
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "\n  ◆  Reproduction bundle written to %s\n\n", args[0])
			fmt.Fprintf(os.Stdout, "     %d events · %d findings · %d kill chains · %d attack paths\n", m.Redaction.Events, m.Findings, m.KillChains, m.AttackPaths)
			fmt.Fprintf(os.Stdout, "     redacted: %d secret-shaped values, %d content arguments dropped, %d credential-file contents dropped\n\n", m.Redaction.SecretsRedacted, m.Redaction.ContentDropped, m.Redaction.CredentialContent)
			fmt.Fprintf(os.Stdout, "  Review %s/events.json before sharing. Replay: aspex-trace replay %s\n\n", args[0], args[0])
			return nil
		},
	}
	create.Flags().StringVar(&since, "since", "24h", "Window to export (e.g. 24h, 7d)")
	create.Flags().StringVar(&session, "session", "", "Only this session (id or prefix, as shown by aspex-trace session)")
	create.Flags().StringVar(&client, "client", "", "Only this client")
	root.AddCommand(create)
	return root
}

func newReplayCmd() *cobra.Command {
	var jsonOut, noColor bool
	cmd := &cobra.Command{
		Use:   "replay <dir>",
		Short: "Re-run Aspex's analysis over a reproduction bundle (executes nothing)",
		Long: `Reads a bundle written by aspex-trace repro create and regenerates findings,
kill chains and provenance from its redacted events, and lists the attack
paths of its environment. Compares with what the bundle recorded at export
time so you can see whether current rules still agree.

This is an analysis replay. No recorded tool, command or network call runs.
Bundles are read with fixed file names only; symlinks, traversal and oversized
files are refused.`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := repro.Load(args[0])
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					Version string `json:"version"`
					Bundle  string `json:"bundle"`
					repro.Replay
				}{version.Version, args[0], r})
			}
			c := func(col, s string) string {
				if noColor || os.Getenv("NO_COLOR") != "" {
					return s
				}
				return col + s + rReset
			}
			fmt.Fprintf(os.Stdout, "\n  %s  %s  %s\n\n", c(rPurple+rBold, "◆"), c(rBold, "Replay"), c(rDim, args[0]+" · created "+r.Manifest.Created.Format("2006-01-02 15:04")+" by "+r.Manifest.Generator))
			delta := func(n int) string {
				switch {
				case n > 0:
					return c(rYellow, fmt.Sprintf(" (+%d vs export)", n))
				case n < 0:
					return c(rYellow, fmt.Sprintf(" (%d vs export)", n))
				}
				return c(rDim, " (same as export)")
			}
			fmt.Fprintf(os.Stdout, "  %d events replayed · %d findings%s · %d kill chains%s · %d attack paths%s\n\n",
				len(r.Events), len(r.Flagged), delta(r.FindingsDelta), len(r.KillChains), delta(r.KillChainsDelta), len(r.AttackPaths), delta(r.PathsDelta))
			for _, fe := range r.Flagged {
				for _, f := range fe.Findings {
					fmt.Fprintf(os.Stdout, "  %s  %s  %s.%s  %s\n", c(sevColor(f.Severity.String()), fmt.Sprintf("%-8s", f.Severity.String())), f.RuleID, fe.Event.Server, fe.Event.Tool, c(rDim, truncateStr(f.Detail, 80)))
				}
			}
			if len(r.KillChains) > 0 {
				fmt.Fprintln(os.Stdout)
				for _, ch := range r.KillChains {
					fmt.Fprintf(os.Stdout, "  %s  %s\n", c(sevColor(ch.Severity), strings.ToUpper(ch.Severity)), ch.Name)
					for _, e := range ch.Evidence {
						fmt.Fprintf(os.Stdout, "     %-9s %s\n", c(rDim, e.Level), e.Text)
					}
				}
			}
			fmt.Fprintf(os.Stdout, "\n  %s\n\n", c(rDim, "Analysis replay only: nothing recorded was executed."))
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Plain text")
	return cmd
}

const (
	rReset  = "\033[0m"
	rBold   = "\033[1m"
	rDim    = "\033[2m"
	rRed    = "\033[31m"
	rYellow = "\033[33m"
	rPurple = "\033[35m"
)

func sevColor(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return rRed + rBold
	case "high":
		return rYellow + rBold
	}
	return rDim
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
