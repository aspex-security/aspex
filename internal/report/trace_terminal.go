package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/trace"
)

// TraceReport is the data for an aspex-trace terminal render.
type TraceReport struct {
	Version     string
	Since       time.Duration
	TotalEvents int
	Sessions    int
	Servers     []string
	Clients     []string
	Flagged     []trace.FlaggedEvent
	NoColor     bool
}

// PrintTraceReport writes the aspex-trace terminal report to w.
func PrintTraceReport(w io.Writer, r TraceReport) {
	c := newColorizer(r.NoColor)

	fmt.Fprintf(w, "\n  %s Aspex%s  v%s\n\n", c(colorPurple+colorBold, "◆"), c(colorReset, ""), r.Version)

	clientStr := strings.Join(r.Clients, ", ")
	if clientStr == "" {
		clientStr = "none found"
	}
	fmt.Fprintf(w, "  Clients scanned: %s\n", clientStr)
	fmt.Fprintf(w, "  Sessions found: %d (last %s)\n", r.Sessions, r.Since)
	fmt.Fprintf(w, "  Tool calls: %d across %d server(s)\n\n", r.TotalEvents, len(r.Servers))

	if len(r.Flagged) == 0 {
		fmt.Fprintf(w, "  %s No anomalies found in %d tool calls.\n\n", c(colorGreen+colorBold, "OK"), r.TotalEvents)
	} else {
		// Group by severity.
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
			fe.Event.Client,
			fe.Event.Server,
			fe.Event.Tool,
		)
		for _, f := range fe.Findings {
			fmt.Fprintf(w, "    %s  %s\n", f.RuleID, f.Name)
			if f.Detail != "" {
				fmt.Fprintf(w, "         %s%s%s\n", c(colorDim, ""), f.Detail, c(colorReset, ""))
			}
		}
		fmt.Fprintln(w)
	}
}
