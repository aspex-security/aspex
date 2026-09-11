package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/history"
	"github.com/aspex-security/aspex/internal/version"
)

func newHistoryCmd(gf *globalFlags) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Security posture over time: capabilities, attack paths, blast radius per scan",
		Long: `Every aspex-scan run records an environment snapshot (a lockfile, no secret
values) in the user cache when something changed. history replays them and
shows, for each point, the tool count, attack paths and blast radius, and the
security-relevant changes since the previous point.`,
		Example:       "  aspex-scan history\n  aspex-scan history --limit 5 --json",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			snaps, err := history.LoadSnapshots()
			if err != nil {
				return err
			}
			if limit > 0 && len(snaps) > limit {
				snaps = snaps[len(snaps)-limit:]
			}
			type point struct {
				Time         string            `json:"time"`
				Servers      int               `json:"servers"`
				Tools        int               `json:"tools"`
				Hooks        int               `json:"hooks"`
				Skills       int               `json:"skills"`
				AttackPaths  int               `json:"attack_paths"`
				Worst        string            `json:"worst_path_severity,omitempty"`
				Blast        string            `json:"blast_radius"`
				Changes      []agentenv.Change `json:"changes_since_previous,omitempty"`
				PathsAdded   int               `json:"paths_added"`
				PathsRemoved int               `json:"paths_removed"`
			}
			var points []point
			for i, s := range snaps {
				p := point{Time: s.Time.Local().Format("2006-01-02 15:04"), Servers: len(s.Env.Servers), Hooks: len(s.Env.Hooks), Skills: len(s.Env.Skills), AttackPaths: len(s.Env.AttackPaths), Blast: s.Env.BlastRadius.Level}
				for _, sv := range s.Env.Servers {
					p.Tools += len(sv.Tools)
				}
				for _, ap := range s.Env.AttackPaths {
					if sevRankStr(ap.Severity) > sevRankStr(p.Worst) {
						p.Worst = ap.Severity
					}
				}
				if i > 0 {
					d := agentenv.Compare(snaps[i-1].Env, s.Env)
					p.Changes = d.SecurityRelevant()
					p.PathsAdded, p.PathsRemoved = len(d.PathsAdded), len(d.PathsRemoved)
				}
				points = append(points, p)
			}
			if gf.jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					Version string  `json:"version"`
					Points  []point `json:"points"`
				}{version.Version, points})
			}
			c := func(col, s string) string {
				if gf.noColor {
					return s
				}
				return col + s + ansiReset
			}
			fmt.Fprintf(os.Stdout, "\n  %s  %s  %s\n\n", c(ansiPurple+ansiBold, "◆"), c(ansiBold, "Security posture over time"), c(ansiDim, fmt.Sprintf("%d snapshot(s)", len(points))))
			if len(points) == 0 {
				fmt.Fprintf(os.Stdout, "  %s\n\n", c(ansiDim, "No snapshots yet. Run aspex-scan; a snapshot is recorded whenever the environment changes."))
				return nil
			}
			for _, p := range points {
				fmt.Fprintf(os.Stdout, "  %s\n", c(ansiBold, p.Time))
				fmt.Fprintf(os.Stdout, "    %d servers · %d tools · %d hooks · %d skills\n", p.Servers, p.Tools, p.Hooks, p.Skills)
				worst := ""
				if p.Worst != "" {
					worst = " (worst " + strings.ToUpper(p.Worst) + ")"
				}
				fmt.Fprintf(os.Stdout, "    %d attack path(s)%s · blast radius %s\n", p.AttackPaths, worst, c(blastColor(p.Blast), p.Blast))
				for _, ch := range p.Changes {
					fmt.Fprintf(os.Stdout, "    %s %s %s\n", c(ansiYellow, "•"), ch.Kind, c(ansiCyan, ch.Entity))
				}
				if p.PathsAdded > 0 {
					fmt.Fprintf(os.Stdout, "    %s +%d attack path(s)\n", c(ansiRed, "•"), p.PathsAdded)
				}
				if p.PathsRemoved > 0 {
					fmt.Fprintf(os.Stdout, "    %s -%d attack path(s)\n", c(ansiGreen, "•"), p.PathsRemoved)
				}
				fmt.Fprintln(os.Stdout)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Show only the last N snapshots")
	return cmd
}

func sevRankStr(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func blastColor(level string) string {
	switch level {
	case "HIGH":
		return ansiRed + ansiBold
	case "MEDIUM":
		return ansiYellow + ansiBold
	case "LOW":
		return ansiGreen
	}
	return ansiDim
}
