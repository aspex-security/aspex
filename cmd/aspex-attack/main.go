// aspex-attack — dedicated red team tool for MCP servers.
// Probes live MCP servers with adversarial payloads and reports findings.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/redteam"
	"github.com/aspex-security/aspex/internal/version"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var (
		serverFlag  string
		timeoutSecs int
		categories  []string
		jsonOut     bool
		noColor     bool
		clients     []string
		failOn      string
	)

	cmd := &cobra.Command{
		Use:   "aspex-attack",
		Short: "Red team MCP servers with adversarial payloads",
		Long: `aspex-attack actively probes live MCP servers with adversarial inputs and
analyzes responses for prompt injection, path traversal, SSRF, error
disclosure, and prompt leakage.

This tool calls real tools with malicious payloads. Only run against
servers you own or have explicit written permission to test.`,
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("NO_COLOR") != "" {
				noColor = true
			}
			return run(serverFlag, timeoutSecs, categories, jsonOut, noColor, clients, failOn)
		},
	}

	cmd.Flags().StringVar(&serverFlag, "server", "", "Probe only this server (by name)")
	cmd.Flags().IntVar(&timeoutSecs, "timeout", 10, "Timeout per probe in seconds")
	cmd.Flags().StringSliceVar(&categories, "categories", nil,
		"Limit to these probe categories (prompt-injection,path-traversal,ssrf,command-injection,error-disclosure,prompt-leakage)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "JSON output")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Plain-text output (useful in CI)")
	cmd.Flags().StringSliceVar(&clients, "clients", discover.AllClients,
		"Clients to scan: claude,cursor,vscode,windsurf,cline,roo-cline,continue,zed")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Exit 1 when findings reach this severity: critical|high|medium|low|off")

	return cmd
}

// color/style helpers

func colorFunc(noColor, jsonOut bool) func(col, text string) string {
	return func(col, text string) string {
		if noColor || jsonOut {
			return text
		}
		return col + text + "\033[0m"
	}
}

const (
	bold   = "\033[1m"
	dim    = "\033[2m"
	purple = "\033[35m"
	red    = "\033[91m"
	green  = "\033[92m"
	yellow = "\033[93m"
)

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// progressBar renders a filled/unfilled bar of given width.
// e.g. progressBar(6, 10, 20) → "████████████░░░░░░░░"
func progressBar(done, total, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}
	filled := done * width / total
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func run(serverFlag string, timeoutSecs int, categories []string, jsonOut, noColor bool, clients []string, failOn string) error {
	c := colorFunc(noColor, jsonOut)

	// Discover servers.
	servers, _ := discover.DiscoverAll(clients)
	if len(servers) == 0 {
		fmt.Fprintln(os.Stdout, "  No MCP servers found.")
		return nil
	}

	// Filter by --server.
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

	// Build category filter.
	catFilter := map[redteam.ProbeCategory]bool{}
	for _, cat := range categories {
		catFilter[redteam.ProbeCategory(cat)] = true
	}

	if !jsonOut {
		fmt.Fprintf(os.Stdout, "\n  %s  %s  %s\n\n",
			c(purple+bold, "◆"),
			c(bold, "aspex-attack"),
			c(dim, "v"+version.Version),
		)
		fmt.Fprintf(os.Stdout, "  %s This command calls live MCP tools with adversarial payloads.\n", c(yellow, "!"))
		fmt.Fprintf(os.Stdout, "  Only run against servers you own or have explicit written permission to test.\n\n")

		scopeStr := fmt.Sprintf("%d", len(servers))
		fmt.Fprintf(os.Stdout, "  Scope: %s server(s) · timeout %ds per probe\n",
			c(bold, scopeStr), timeoutSecs)
		for _, s := range servers {
			fmt.Fprintf(os.Stdout, "    %s %s\n", c(dim, "·"), s.Name)
		}
		if len(catFilter) > 0 {
			cats := make([]string, 0, len(catFilter))
			for cat := range catFilter {
				cats = append(cats, string(cat))
			}
			fmt.Fprintf(os.Stdout, "  Categories: %s\n", strings.Join(cats, ", "))
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

	// JSON output types.
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
		Name       string `json:"name"`
		Client     string `json:"client"`
		ToolCount  int    `json:"tool_count"`
		ProbeCount int    `json:"probe_count"`
		VulnCount  int    `json:"vuln_count"`
		Verdict    string `json:"verdict"` // CLEAN | VULNERABLE | PARTIAL
		Error      string `json:"error,omitempty"`
	}

	var allVulns []jsonVuln
	var jsonServers []jsonServerResult
	totalProbes := 0
	totalVulns := 0

	// Per-server summary for the final table (human mode).
	type serverSummary struct {
		name       string
		toolCount  int
		probeCount int
		vulnCount  int
		verdict    string
	}
	var summaries []serverSummary

	ctx := context.Background()

	for _, entry := range servers {
		if !jsonOut {
			fmt.Fprintf(os.Stdout, "  %s %s\n",
				c(dim, "▸"),
				c(bold, entry.Name),
			)
		}

		opts := inspect.Options{NoExec: false}
		srv := inspect.InspectServer(ctx, entry, opts)

		if srv.StaticOnly {
			if !jsonOut {
				fmt.Fprintf(os.Stdout, "    %s %s\n",
					c(yellow, "~"),
					c(dim, "static-only server, skipping probes"),
				)
			}
			jsonServers = append(jsonServers, jsonServerResult{
				Name:    entry.Name,
				Client:  entry.Client,
				Verdict: "SKIPPED",
				Error:   "static-only server",
			})
			summaries = append(summaries, serverSummary{name: entry.Name, verdict: "SKIPPED"})
			continue
		}

		if len(srv.Tools) == 0 {
			if !jsonOut {
				fmt.Fprintf(os.Stdout, "    %s %s\n",
					c(dim, "-"),
					c(dim, "no tools found"),
				)
			}
			jsonServers = append(jsonServers, jsonServerResult{
				Name:    entry.Name,
				Client:  entry.Client,
				Verdict: "CLEAN",
			})
			summaries = append(summaries, serverSummary{name: entry.Name, verdict: "CLEAN"})
			continue
		}

		serverProbes := 0
		serverVulns := 0

		// Count total probes for this server upfront (for the progress bar).
		totalProbesForServer := 0
		// We'll iterate tools and track progress as we go.
		probesDone := 0
		// Pre-count probes for progress bar.
		for _, tool := range srv.Tools {
			ps := redteam.ProbesForTool(tool)
			if len(catFilter) > 0 {
				var f []redteam.Probe
				for _, p := range ps {
					if catFilter[p.Category] {
						f = append(f, p)
					}
				}
				ps = f
			}
			totalProbesForServer += len(ps)
		}

		for _, tool := range srv.Tools {
			probes := redteam.ProbesForTool(tool)

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

			// Show per-probe progress with a bar, overwriting the line.
			if !jsonOut {
				pct := 0
				if totalProbesForServer > 0 {
					pct = probesDone * 100 / totalProbesForServer
				}
				bar := progressBar(probesDone, totalProbesForServer, 10)
				probeName := ""
				if len(probes) > 0 {
					probeName = probes[0].Name
				}
				fmt.Fprintf(os.Stdout, "\r    %s %s%s%s %d%% %s %s %s",
					c(dim, "["),
					c(purple, bar),
					c(dim, "]"),
					"",
					pct,
					c(dim, "·"),
					c(dim, tool.Name),
					c(dim, "· "+probeName),
				)
			}

			probeCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
			results := redteam.RunProbes(probeCtx, entry, tool, probes)
			cancel()

			probesDone += len(results)
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

			if !jsonOut && len(toolVulns) > 0 {
				// Clear in-progress line.
				fmt.Fprintf(os.Stdout, "\r\033[2K")
				fmt.Fprintf(os.Stdout, "    %s  %s  %s\n",
					c(red+bold, "VULNERABLE"),
					c(bold, tool.Name),
					c(dim, fmt.Sprintf("%d/%d probes triggered", len(toolVulns), len(results))),
				)
				for _, vr := range toolVulns {
					fmt.Fprintf(os.Stdout, "       %s %s  %s  %s\n",
						c(red, "▸"),
						c(bold, vr.Probe.Name),
						c(dim, "("+strings.Join(vr.Triggered, ", ")+")"),
						c(dim, "["+vr.Severity+"]"),
					)
				}
			}
		}

		// Clear progress line.
		if !jsonOut {
			fmt.Fprintf(os.Stdout, "\r\033[2K")
		}

		verdict := "CLEAN"
		if serverVulns > 0 {
			verdict = "VULNERABLE"
		}

		if !jsonOut {
			if serverVulns == 0 {
				fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
					c(dim, "·"),
					c(bold, entry.Name),
					c(dim, fmt.Sprintf("No findings triggered by these %d probes — this does not mean the server is secure", serverProbes)),
				)
			} else {
				fmt.Fprintf(os.Stdout, "  %s  %s  %s\n",
					c(red+bold, "✗"),
					c(bold, entry.Name),
					c(dim, fmt.Sprintf("%d finding(s) · %d probes · %d tools", serverVulns, serverProbes, len(srv.Tools))),
				)
			}
		}

		jsonServers = append(jsonServers, jsonServerResult{
			Name:       entry.Name,
			Client:     entry.Client,
			ToolCount:  len(srv.Tools),
			ProbeCount: serverProbes,
			VulnCount:  serverVulns,
			Verdict:    verdict,
		})
		summaries = append(summaries, serverSummary{
			name:       entry.Name,
			toolCount:  len(srv.Tools),
			probeCount: serverProbes,
			vulnCount:  serverVulns,
			verdict:    verdict,
		})
	}

	if jsonOut {
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

	// Summary table.
	fmt.Fprintf(os.Stdout, "\n  %s\n", c(dim, strings.Repeat("─", 60)))
	fmt.Fprintf(os.Stdout, "  %s\n\n", c(bold, "Summary"))

	// Column widths.
	colServer := 24
	colProbes := 8
	colFindings := 10
	colVerdict := 12

	header := fmt.Sprintf("  %-*s  %*s  %*s  %-*s",
		colServer, "Server",
		colProbes, "Probes",
		colFindings, "Findings",
		colVerdict, "Verdict",
	)
	fmt.Fprintln(os.Stdout, c(dim, header))
	fmt.Fprintln(os.Stdout, c(dim, "  "+strings.Repeat("─", colServer+colProbes+colFindings+colVerdict+8)))

	for _, s := range summaries {
		name := s.name
		if len(name) > colServer {
			name = name[:colServer-1] + "…"
		}

		verdictStr := s.verdict
		var verdictColor string
		switch s.verdict {
		case "CLEAN":
			verdictColor = dim
		case "VULNERABLE":
			verdictColor = red + bold
		case "SKIPPED":
			verdictColor = dim
		default:
			verdictColor = dim
		}

		row := fmt.Sprintf("  %-*s  %*d  %*d  %s",
			colServer, name,
			colProbes, s.probeCount,
			colFindings, s.vulnCount,
			c(verdictColor, verdictStr),
		)
		fmt.Fprintln(os.Stdout, row)
	}

	fmt.Fprintln(os.Stdout)

	// Overall verdict line.
	fmt.Fprintf(os.Stdout, "  %s ", c(dim, "─"))
	if totalVulns == 0 {
		fmt.Fprintf(os.Stdout, "No findings triggered by these %d probes — this does not mean the server is secure\n\n",
			totalProbes)
	} else {
		fmt.Fprintf(os.Stdout, "%s %d finding(s) across %d probe(s) — review results above.\n\n",
			c(red+bold, fmt.Sprintf("%d", totalVulns)),
			totalVulns, totalProbes)
	}

	// --fail-on exit code.
	if failOn != "" && failOn != "off" && totalVulns > 0 {
		sevOrder := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
		threshold := sevOrder[failOn]
		if threshold == 0 {
			threshold = sevOrder["high"]
		}
		for _, v := range allVulns {
			if sevOrder[v.Severity] >= threshold {
				os.Exit(1)
			}
		}
	}

	return nil
}
