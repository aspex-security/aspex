package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/trace"
)

// ActivitySummary holds session-level activity counts for the summary section.
type ActivitySummary struct {
	FileWrites   int
	FileReads    int
	BashCmds     int
	NetworkCalls int
	GitCommits   int
	TopTools     []ToolCount // top 5 by call count
	TopServers   []ToolCount // top 5 servers by tool-call count
	TopPaths     []ToolCount // top 10 accessed file paths (for heatmap)
}

// ToolCount is a name+count pair for ranked lists.
type ToolCount struct {
	Name  string
	Count int
}

// ComputeActivity derives an ActivitySummary from a slice of events.
func ComputeActivity(events []logparse.Event) ActivitySummary {
	toolCounts := map[string]int{}
	serverCounts := map[string]int{}
	pathCounts := map[string]int{}

	var a ActivitySummary
	for _, ev := range events {
		if ev.Event != logparse.EventToolsCall {
			continue
		}
		tl := strings.ToLower(ev.Tool)
		toolCounts[ev.Tool]++
		if ev.Server != "" {
			serverCounts[ev.Server]++
		}

		// Classify by tool name.
		switch {
		case tl == "write" || tl == "edit" || tl == "multiedit" ||
			strings.Contains(tl, "write_file") || strings.Contains(tl, "edit_file"):
			a.FileWrites++
		case tl == "read" || strings.Contains(tl, "read_file") || strings.Contains(tl, "get_file"):
			a.FileReads++
		case tl == "bash" || tl == "shell" || tl == "run_command" || tl == "execute_command":
			a.BashCmds++
			// Count git commits inside Bash calls.
			if cmd := ev.Args["command"]; strings.Contains(cmd, "git commit") {
				a.GitCommits++
			}
		case strings.Contains(tl, "fetch") || strings.Contains(tl, "http") ||
			strings.Contains(tl, "curl") || strings.Contains(tl, "browse") ||
			strings.Contains(tl, "open_url") || strings.Contains(tl, "navigate"):
			a.NetworkCalls++
		}

		// Track accessed paths from path-like args.
		for k, v := range ev.Args {
			kl := strings.ToLower(k)
			if kl == "path" || kl == "file_path" || kl == "filepath" || kl == "file" {
				if v != "" && (strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~")) {
					pathCounts[v]++
				}
			}
		}
	}

	a.TopTools = topN(toolCounts, 5)
	a.TopServers = topN(serverCounts, 5)
	a.TopPaths = topN(pathCounts, 10)
	return a
}

func topN(counts map[string]int, n int) []ToolCount {
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range counts {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	if len(pairs) > n {
		pairs = pairs[:n]
	}
	out := make([]ToolCount, len(pairs))
	for i, p := range pairs {
		out[i] = ToolCount{Name: p.k, Count: p.v}
	}
	return out
}

// TraceReport is the data for an aspex-trace terminal render.
type TraceReport struct {
	Version     string
	Since       time.Duration
	TotalEvents int
	Sessions    int
	Servers     []string
	Clients     []string
	Flagged     []trace.FlaggedEvent
	Activity    ActivitySummary
	NoColor     bool
	SummaryOnly bool // --summary: print compact stats + finding count, no per-event detail
}

// PrintTraceReport writes the aspex-trace terminal report to w.
func PrintTraceReport(w io.Writer, r TraceReport) {
	c := newColorizer(r.NoColor)

	clientStr := strings.Join(r.Clients, ", ")
	if clientStr == "" {
		clientStr = "none found"
	}

	if r.SummaryOnly {
		printSummaryOnly(w, r, c, clientStr)
		return
	}

	fmt.Fprintf(w, "\n  %s Aspex%s  v%s\n\n", c(colorPurple+colorBold, "◆"), c(colorReset, ""), r.Version)

	fmt.Fprintf(w, "  Clients scanned: %s\n", clientStr)
	fmt.Fprintf(w, "  Sessions found:  %d  (last %s)\n", r.Sessions, r.Since)
	fmt.Fprintf(w, "  Tool calls:      %d across %d server(s)\n\n", r.TotalEvents, len(r.Servers))

	printActivityBlock(w, r, c)

	if len(r.Flagged) == 0 {
		fmt.Fprintf(w, "  %s No anomalies found in %d tool calls.\n\n", c(colorGreen+colorBold, "OK"), r.TotalEvents)
	} else {
		var crits, highs, meds, lows []trace.FlaggedEvent
		for _, fe := range r.Flagged {
			maxSev := rules.SeverityInfo
			for _, f := range fe.Findings {
				if f.Severity > maxSev {
					maxSev = f.Severity
				}
			}
			switch maxSev {
			case rules.SeverityCritical:
				crits = append(crits, fe)
			case rules.SeverityHigh:
				highs = append(highs, fe)
			case rules.SeverityMedium:
				meds = append(meds, fe)
			default:
				lows = append(lows, fe)
			}
		}

		printTraceSeveritySection(w, c, "CRITICAL", crits)
		printTraceSeveritySection(w, c, "HIGH", highs)
		printTraceSeveritySection(w, c, "MEDIUM", meds)
		printTraceSeveritySection(w, c, "LOW", lows)

		clean := r.TotalEvents - len(r.Flagged)
		if clean > 0 {
			fmt.Fprintf(w, "  %s: %d tool call(s) showed no anomalies.\n\n", c(colorGreen, "OK"), clean)
		}
	}

	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 48))
	fmt.Fprintf(w, "  %sThis traced 1 machine. See continuous agent activity across your%s\n", c(colorDim, ""), c(colorReset, ""))
	fmt.Fprintf(w, "  %sorg: https://onyx.security  (this tool is and will remain free)%s\n\n", c(colorDim, ""), c(colorReset, ""))
}

// printSummaryOnly renders the compact --summary view.
func printSummaryOnly(w io.Writer, r TraceReport, c colorFn, clientStr string) {
	fmt.Fprintf(w, "\n  %s Aspex%s  v%s\n\n", c(colorPurple+colorBold, "◆"), c(colorReset, ""), r.Version)

	fmt.Fprintf(w, "  %s\n", c(colorBold, "Session summary")+"  "+c(colorDim, fmt.Sprintf("(last %s, %s)", r.Since, clientStr)))
	fmt.Fprintf(w, "  %d tool calls  ·  %d server(s)  ·  %d session(s)\n\n",
		r.TotalEvents, len(r.Servers), r.Sessions)

	printActivityBlock(w, r, c)

	// Findings summary line.
	if len(r.Flagged) == 0 {
		fmt.Fprintf(w, "  %s No anomalies found.\n\n", c(colorGreen+colorBold, "✓"))
	} else {
		counts := map[string]int{}
		for _, fe := range r.Flagged {
			for _, f := range fe.Findings {
				switch f.Severity {
				case rules.SeverityCritical:
					counts["critical"]++
				case rules.SeverityHigh:
					counts["high"]++
				case rules.SeverityMedium:
					counts["medium"]++
				default:
					counts["low"]++
				}
			}
		}
		var parts []string
		if n := counts["critical"]; n > 0 {
			parts = append(parts, c(colorRed+colorBold, fmt.Sprintf("%d CRITICAL", n)))
		}
		if n := counts["high"]; n > 0 {
			parts = append(parts, c(colorRed, fmt.Sprintf("%d HIGH", n)))
		}
		if n := counts["medium"]; n > 0 {
			parts = append(parts, c(colorYellow, fmt.Sprintf("%d MEDIUM", n)))
		}
		if n := counts["low"]; n > 0 {
			parts = append(parts, c(colorYellow, fmt.Sprintf("%d LOW", n)))
		}
		fmt.Fprintf(w, "  %s  %s  — run %s for details\n\n",
			c(colorRed+colorBold, "⚠"),
			strings.Join(parts, "  "),
			c(colorBold, "aspex-trace"),
		)
	}
}

// printActivityBlock renders the Activity section (shared by full and summary modes).
func printActivityBlock(w io.Writer, r TraceReport, c colorFn) {
	a := r.Activity
	if r.TotalEvents == 0 {
		return
	}
	fmt.Fprintf(w, "  %s\n", c(colorDim+colorBold, "Activity"))

	// Activity counts line.
	actParts := []string{
		fmt.Sprintf("%d file write(s)", a.FileWrites),
		fmt.Sprintf("%d file read(s)", a.FileReads),
		fmt.Sprintf("%d shell cmd(s)", a.BashCmds),
	}
	if a.NetworkCalls > 0 {
		actParts = append(actParts, fmt.Sprintf("%d network call(s)", a.NetworkCalls))
	}
	if a.GitCommits > 0 {
		actParts = append(actParts, fmt.Sprintf("%d commit(s)", a.GitCommits))
	}
	fmt.Fprintf(w, "  %s\n", strings.Join(actParts, "  ·  "))

	if len(a.TopTools) > 0 {
		parts := make([]string, len(a.TopTools))
		for i, t := range a.TopTools {
			parts[i] = fmt.Sprintf("%s (%d)", t.Name, t.Count)
		}
		fmt.Fprintf(w, "  Top tools:   %s\n", strings.Join(parts, "  ·  "))
	}
	if len(a.TopServers) > 0 {
		parts := make([]string, len(a.TopServers))
		for i, s := range a.TopServers {
			parts[i] = fmt.Sprintf("%s (%d)", s.Name, s.Count)
		}
		fmt.Fprintf(w, "  Top servers: %s\n", strings.Join(parts, "  ·  "))
	}

	// File access heatmap.
	if len(a.TopPaths) > 0 {
		maxCount := a.TopPaths[0].Count
		fmt.Fprintf(w, "  File access heatmap:\n")
		for _, p := range a.TopPaths {
			bar := heatBar(p.Count, maxCount, 12)
			fmt.Fprintf(w, "    %s%s%s  %s%3dx%s  %s\n",
				c(colorPurple, bar),
				c(colorReset, ""),
				"",
				c(colorDim, ""),
				p.Count,
				c(colorReset, ""),
				shortenPath(p.Name),
			)
		}
	}
	fmt.Fprintln(w)
}

// heatBar returns a Unicode block bar scaled to maxWidth.
func heatBar(count, max, maxWidth int) string {
	if max == 0 {
		return ""
	}
	filled := (count * maxWidth) / max
	if filled < 1 {
		filled = 1
	}
	// Use block elements ▏▎▍▌▋▊▉█ for smooth rendering.
	const blocks = "▏▎▍▌▋▊▉█"
	full := filled
	bar := strings.Repeat("█", full)
	_ = blocks
	return bar
}

// shortenPath replaces the home directory with ~ for display.
func shortenPath(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if strings.HasPrefix(p, home) {
		return "~" + p[len(home):]
	}
	return p
}

func printTraceSeveritySection(w io.Writer, c colorFn, severity string, events []trace.FlaggedEvent) {
	if len(events) == 0 {
		return
	}
	col := colorRed
	if severity == "MEDIUM" || severity == "LOW" {
		col = colorYellow
	} else if severity == "HIGH" {
		col = colorRed
	}
	fmt.Fprintf(w, "  %s\n", c(col+colorBold, severity))
	for _, fe := range events {
		ts := fe.Event.Timestamp.Format("15:04:05")
		fmt.Fprintf(w, "  %s [%s]  %s / %s  %s\n",
			c(col, "●"),
			ts,
			SanitizeForTerminal(fe.Event.Client),
			SanitizeForTerminal(fe.Event.Server),
			SanitizeForTerminal(fe.Event.Tool),
		)
		for _, f := range fe.Findings {
			fmt.Fprintf(w, "    %s  %s\n", f.RuleID, SanitizeForTerminal(f.Name))
			if f.Detail != "" {
				detail := SanitizeForTerminal(f.Detail)
				if len(detail) > 150 {
					detail = detail[:150] + "…"
				}
				fmt.Fprintf(w, "         %s%s%s\n", c(colorDim, ""), detail, c(colorReset, ""))
			}
		}
		fmt.Fprintln(w)
	}
}
