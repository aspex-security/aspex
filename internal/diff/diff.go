// Package diff compares two scan outputs and produces a structured diff.
package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/aspex-security/aspex/internal/report"
	"github.com/aspex-security/aspex/internal/rules"
)

// ServerDiff holds the finding changes for a single server between two scans.
type ServerDiff struct {
	Name       string
	Client     string
	Added      []rules.Finding // new findings not in baseline
	Removed    []rules.Finding // findings present in baseline but gone now
	ScoreDelta int             // current score - baseline score (negative = got worse)
}

// ScanDiff is the top-level result of comparing two scans.
type ScanDiff struct {
	BaselineTime   string
	CurrentTime    string
	ServersAdded   []string     // server names new in current scan
	ServersRemoved []string     // server names in baseline but not current
	Changed        []ServerDiff // servers with changed findings
	Regressed      bool         // true if any server got new CRITICAL or HIGH findings
}

// serverKey returns the match key for a server result.
func serverKey(s report.JSONServerResult) string {
	return s.Name + "\x00" + s.Client
}

// parseSeverity converts a severity string from JSONFinding to rules.Severity.
func parseSeverity(s string) rules.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return rules.SeverityCritical
	case "HIGH":
		return rules.SeverityHigh
	case "MEDIUM":
		return rules.SeverityMedium
	case "LOW":
		return rules.SeverityLow
	default:
		return rules.SeverityInfo
	}
}

// toFinding converts a JSONFinding to a rules.Finding.
func toFinding(jf report.JSONFinding) rules.Finding {
	return rules.Finding{
		RuleID:   jf.RuleID,
		Name:     jf.Name,
		Severity: parseSeverity(jf.Severity),
		Detail:   jf.Detail,
		Fix:      jf.Fix,
		Mapping:  jf.Mapping,
	}
}

// Compare computes the diff between a baseline and a current scan output.
func Compare(baseline, current report.JSONScanOutput) ScanDiff {
	d := ScanDiff{
		BaselineTime: baseline.Version,
		CurrentTime:  current.Version,
	}

	// Index baseline servers by key.
	baseMap := make(map[string]report.JSONServerResult, len(baseline.Servers))
	for _, s := range baseline.Servers {
		baseMap[serverKey(s)] = s
	}

	// Index current servers by key.
	currMap := make(map[string]report.JSONServerResult, len(current.Servers))
	for _, s := range current.Servers {
		currMap[serverKey(s)] = s
	}

	// Find added servers (in current but not baseline).
	for _, s := range current.Servers {
		if _, ok := baseMap[serverKey(s)]; !ok {
			d.ServersAdded = append(d.ServersAdded, s.Name)
		}
	}

	// Find removed servers (in baseline but not current).
	for _, s := range baseline.Servers {
		if _, ok := currMap[serverKey(s)]; !ok {
			d.ServersRemoved = append(d.ServersRemoved, s.Name)
		}
	}

	// Compare servers present in both.
	for _, curr := range current.Servers {
		base, ok := baseMap[serverKey(curr)]
		if !ok {
			continue
		}

		// Build RuleID sets.
		baseIDs := make(map[string]report.JSONFinding, len(base.Findings))
		for _, f := range base.Findings {
			baseIDs[f.RuleID] = f
		}
		currIDs := make(map[string]report.JSONFinding, len(curr.Findings))
		for _, f := range curr.Findings {
			currIDs[f.RuleID] = f
		}

		var added, removed []rules.Finding

		for ruleID, jf := range currIDs {
			if _, exists := baseIDs[ruleID]; !exists {
				added = append(added, toFinding(jf))
			}
		}
		for ruleID, jf := range baseIDs {
			if _, exists := currIDs[ruleID]; !exists {
				removed = append(removed, toFinding(jf))
			}
		}

		if len(added) == 0 && len(removed) == 0 && curr.Score == base.Score {
			continue
		}

		sd := ServerDiff{
			Name:       curr.Name,
			Client:     curr.Client,
			Added:      added,
			Removed:    removed,
			ScoreDelta: curr.Score - base.Score,
		}
		d.Changed = append(d.Changed, sd)

		// Check for regression.
		for _, f := range added {
			if f.Severity >= rules.SeverityHigh {
				d.Regressed = true
			}
		}
	}

	return d
}

// ANSI color codes.
const (
	ansiRed   = "\033[31m"
	ansiGreen = "\033[32m"
	ansiBold  = "\033[1m"
	ansiReset = "\033[0m"
)

func colorize(s, code string, noColor bool) string {
	if noColor {
		return s
	}
	return code + s + ansiReset
}

// PrintDiff writes a human-readable diff to w.
func PrintDiff(w io.Writer, d ScanDiff, noColor bool) {
	fmt.Fprintf(w, "Diff: baseline %s vs current %s\n\n", d.BaselineTime, d.CurrentTime)

	if len(d.ServersAdded) > 0 {
		fmt.Fprintf(w, "Servers added: %s\n", strings.Join(d.ServersAdded, ", "))
	}
	if len(d.ServersRemoved) > 0 {
		fmt.Fprintf(w, "Servers removed: %s\n", strings.Join(d.ServersRemoved, ", "))
	}

	totalNew := 0
	totalResolved := 0

	for _, sd := range d.Changed {
		header := fmt.Sprintf("[%s / %s]  score delta: %+d", sd.Name, sd.Client, sd.ScoreDelta)
		fmt.Fprintln(w, colorize(header, ansiBold, noColor))

		for _, f := range sd.Added {
			line := fmt.Sprintf("  + [%s] %s: %s", f.Severity.String(), f.RuleID, f.Name)
			fmt.Fprintln(w, colorize(line, ansiRed, noColor))
			totalNew++
		}
		for _, f := range sd.Removed {
			line := fmt.Sprintf("  - [%s] %s: %s", f.Severity.String(), f.RuleID, f.Name)
			fmt.Fprintln(w, colorize(line, ansiGreen, noColor))
			totalResolved++
		}
		fmt.Fprintln(w)
	}

	regressed := "no"
	if d.Regressed {
		regressed = colorize("yes", ansiRed, noColor)
	}
	fmt.Fprintf(w, "%d new findings, %d resolved. Regressed: %s\n", totalNew, totalResolved, regressed)
}

// WriteDiffJSON marshals d as indented JSON to w.
func WriteDiffJSON(w io.Writer, d ScanDiff) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}
