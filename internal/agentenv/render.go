package agentenv

import (
	"fmt"
	"io"
	"strings"

	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/report"
)

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cCyan   = "\033[36m"
	cPurple = "\033[35m"
)

func colorizer(noColor bool) func(string, string) string {
	return func(col, s string) string {
		if noColor {
			return s
		}
		return col + s + cReset
	}
}

func classColor(class string) string {
	switch class {
	case ClassSuspicious:
		return cRed + cBold
	case ClassSecurityRelevant:
		return cYellow + cBold
	}
	return cDim
}

func classLabel(class string) string {
	switch class {
	case ClassSuspicious:
		return "SUSPICIOUS"
	case ClassSecurityRelevant:
		return "SECURITY"
	}
	return "INFO"
}

func blastColor(level string) string {
	switch level {
	case "HIGH":
		return cRed + cBold
	case "MEDIUM":
		return cYellow + cBold
	case "LOW":
		return cGreen
	}
	return cDim
}

// PrintDrift renders a comparison for a terminal. Suspicious first, then
// security-relevant, then informational (collapsed unless verbose).
func PrintDrift(w io.Writer, d Drift, noColor, verbose bool) {
	c := colorizer(noColor)
	if d.Empty() && d.BlastBefore.Level == d.BlastAfter.Level {
		fmt.Fprintf(w, "\n  %s  No security-relevant change. Blast radius %s.\n\n", c(cGreen, "✓"), c(blastColor(d.BlastAfter.Level), d.BlastAfter.Level))
		return
	}
	var nSus, nSec, nInfo int
	for _, ch := range d.Changes {
		switch ch.Class {
		case ClassSuspicious:
			nSus++
		case ClassSecurityRelevant:
			nSec++
		default:
			nInfo++
		}
	}
	fmt.Fprintf(w, "\n  %s  %s  %s\n\n", c(cPurple+cBold, "◆"), c(cBold, "Agent environment changed"),
		c(cDim, fmt.Sprintf("%d suspicious · %d security-relevant · %d informational · %d attack path(s) added · %d removed", nSus, nSec, nInfo, len(d.PathsAdded), len(d.PathsRemoved))))

	for _, ch := range d.Changes {
		if ch.Class == ClassInformational && !verbose {
			continue
		}
		printChange(w, c, ch)
	}
	if nInfo > 0 && !verbose {
		fmt.Fprintf(w, "  %s\n\n", c(cDim, fmt.Sprintf("%d informational change(s) hidden. Show them: --verbose", nInfo)))
	}

	if len(d.PathsAdded) > 0 {
		fmt.Fprintf(w, "  %s  %s\n", c(cRed+cBold, "NEW ATTACK PATH"), c(cDim, fmt.Sprintf("%d", len(d.PathsAdded))))
		report.PrintAttackPaths(w, noColor, d.PathsAdded)
	}
	if len(d.PathsRemoved) > 0 {
		fmt.Fprintf(w, "  %s  %d path(s) no longer exist:\n", c(cGreen+cBold, "ATTACK PATH REMOVED"), len(d.PathsRemoved))
		for _, p := range d.PathsRemoved {
			fmt.Fprintf(w, "     %s %s  %s  %s\n", c(cGreen, "-"), c(cDim, strings.ToUpper(p.Severity)), p.ID, report.SanitizeForTerminal(p.Name+"  ("+strings.Join(p.Servers, " + ")+")"))
		}
		fmt.Fprintln(w)
	}

	printBlastDelta(w, c, d.BlastBefore, d.BlastAfter)
	if d.StaticAfter {
		fmt.Fprintf(w, "  %s\n\n", c(cDim, "Capabilities inferred from packages and configs (no server launched). Run without --no-exec for live tool lists."))
	}
}

func printChange(w io.Writer, c func(string, string) string, ch Change) {
	fmt.Fprintf(w, "  %s  %s  %s\n", c(classColor(ch.Class), fmt.Sprintf("%-10s", classLabel(ch.Class))), c(cBold, ch.Kind), c(cCyan, report.SanitizeForTerminal(ch.Entity)))
	if ch.Before != "" {
		fmt.Fprintf(w, "     %s %s\n", c(cDim, "before:"), report.SanitizeForTerminal(quoteIfText(ch.Before)))
	}
	if ch.After != "" {
		fmt.Fprintf(w, "     %s %s\n", c(cDim, "after: "), report.SanitizeForTerminal(quoteIfText(ch.After)))
	}
	if ch.Reason != "" {
		fmt.Fprintf(w, "     %s %s\n", c(cDim, "why:   "), c(classColor(ch.Class), report.SanitizeForTerminal(ch.Reason)))
	}
	if ch.Impact != "" {
		for _, line := range wrap(ch.Impact, 72) {
			fmt.Fprintf(w, "     %s\n", c(cDim, line))
		}
	}
	fmt.Fprintln(w)
}

func printBlastDelta(w io.Writer, c func(string, string) string, before, after BlastRadius) {
	if before.Level == after.Level {
		fmt.Fprintf(w, "  %s %s\n", c(cDim, "Blast radius:"), c(blastColor(after.Level), after.Level))
	} else {
		fmt.Fprintf(w, "  %s %s %s %s\n", c(cDim, "Blast radius:"), c(blastColor(before.Level), before.Level), c(cDim, "→"), c(blastColor(after.Level), after.Level))
	}
	for _, r := range after.Why {
		mark := c(cDim, "✗")
		if r.Present {
			mark = c(cYellow, "✓")
		}
		fmt.Fprintf(w, "     %s %s\n", mark, c(cDim, r.Text))
	}
	fmt.Fprintln(w)
}

// PrintBlastRadius prints the level and its reasons.
func PrintBlastRadius(w io.Writer, b BlastRadius, noColor bool) {
	c := colorizer(noColor)
	fmt.Fprintf(w, "  %s %s\n", c(cDim, "Blast radius:"), c(blastColor(b.Level), b.Level))
	for _, r := range b.Why {
		mark := c(cDim, "✗")
		if r.Present {
			mark = c(cYellow, "✓")
		}
		fmt.Fprintf(w, "     %s %s\n", mark, c(cDim, r.Text))
	}
}

// PrintSummary renders a compact environment inventory (used by lock and bom).
func PrintSummary(w io.Writer, env Environment, noColor bool) {
	c := colorizer(noColor)
	for _, a := range env.Agents {
		fmt.Fprintf(w, "  %s %s\n", c(cDim, "Agent:"), c(cBold, a.Name))
	}
	fmt.Fprintf(w, "\n  %s\n", c(cBold, "MCP servers"))
	tree(w, c, len(env.Servers), func(i int) string {
		s := env.Servers[i]
		caps := strings.Join(s.Capabilities, ", ")
		if caps == "" {
			caps = "no classified capabilities"
		}
		extra := ""
		if s.Scope != "" {
			extra = " · " + s.Scope + " scope"
		}
		surface := fmt.Sprintf("%d tools", len(s.Tools))
		if s.Static {
			surface = "inferred from package"
		}
		return fmt.Sprintf("%s  %s", c(cCyan, s.Name), c(cDim, fmt.Sprintf("%s · %s%s", surface, caps, extra)))
	})
	if len(env.Skills) > 0 {
		fmt.Fprintf(w, "\n  %s\n", c(cBold, "Skills"))
		tree(w, c, len(env.Skills), func(i int) string {
			s := env.Skills[i]
			tag := ""
			if s.Executes {
				tag = " · runs commands"
			}
			return fmt.Sprintf("%s  %s", c(cCyan, s.Name), c(cDim, s.Scope+tag))
		})
	}
	if len(env.Hooks) > 0 {
		fmt.Fprintf(w, "\n  %s\n", c(cBold, "Hooks"))
		tree(w, c, len(env.Hooks), func(i int) string {
			h := env.Hooks[i]
			return fmt.Sprintf("%s  %s", c(cCyan, h.Event), c(cDim, strings.ToUpper(h.Severity)+" · "+truncate(h.Command, 60)))
		})
	}
	if len(env.SensitiveResources) > 0 {
		// Credentials and databases one per line; agent-state files collapse
		// into one line per writer set, because the point is "this server can
		// rewrite what the agent trusts", not nine paths.
		type line struct{ path, detail string }
		var lines []line
		stateVia := map[string]int{}
		for _, r := range env.SensitiveResources {
			if r.Kind == "agent-state" {
				stateVia[strings.Join(r.Via, ", ")]++
				continue
			}
			lines = append(lines, line{r.Path, r.Access + " via " + strings.Join(r.Via, ", ")})
		}
		for via, n := range stateVia {
			lines = append(lines, line{fmt.Sprintf("agent config, hooks, instructions, memory (%d files)", n), "write via " + via})
		}
		fmt.Fprintf(w, "\n  %s\n", c(cBold, "Sensitive resources reachable"))
		tree(w, c, len(lines), func(i int) string {
			return fmt.Sprintf("%s  %s", report.SanitizeForTerminal(lines[i].path), c(cDim, lines[i].detail))
		})
	}
	if len(env.Destinations) > 0 {
		fmt.Fprintf(w, "\n  %s\n", c(cBold, "External destinations"))
		tree(w, c, len(env.Destinations), func(i int) string { return env.Destinations[i] })
	}
	if len(env.Instructions) > 0 {
		fmt.Fprintf(w, "\n  %s\n", c(cBold, "Persistent state"))
		tree(w, c, len(env.Instructions), func(i int) string {
			in := env.Instructions[i]
			return fmt.Sprintf("%s  %s", in.Path, c(cDim, in.Kind))
		})
	}
	fmt.Fprintf(w, "\n  %s\n", c(cBold, "Attack paths"))
	if len(env.AttackPaths) == 0 {
		fmt.Fprintf(w, "  %s %s\n", c(cDim, "└──"), c(cGreen, "none"))
	} else {
		counts := map[string]int{}
		for _, p := range env.AttackPaths {
			counts[p.Severity]++
		}
		var parts []string
		for _, s := range []string{"critical", "high", "medium", "low"} {
			if counts[s] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", counts[s], strings.ToUpper(s)))
			}
		}
		fmt.Fprintf(w, "  %s %s\n", c(cDim, "└──"), strings.Join(parts, ", "))
	}
	fmt.Fprintln(w)
	PrintBlastRadius(w, env.BlastRadius, noColor)
}

func tree(w io.Writer, c func(string, string) string, n int, line func(i int) string) {
	for i := 0; i < n; i++ {
		branch := "├──"
		if i == n-1 {
			branch = "└──"
		}
		fmt.Fprintf(w, "  %s %s\n", c(cDim, branch), line(i))
	}
}

// Markdown renders the drift as a PR comment / CI artifact.
func Markdown(d Drift, title string) string {
	var b strings.Builder
	if title == "" {
		title = "Aspex agent security impact"
	}
	icon := "🟢"
	switch d.Worst() {
	case ClassSuspicious:
		icon = "🔴"
	case ClassSecurityRelevant:
		icon = "🟠"
	case ClassInformational:
		icon = "🟡"
	}
	for _, p := range d.PathsAdded {
		if p.Severity == "critical" {
			icon = "🔴"
		}
	}
	fmt.Fprintf(&b, "## %s %s\n\n", icon, title)
	if d.Empty() && d.BlastBefore.Level == d.BlastAfter.Level {
		fmt.Fprintf(&b, "No security-relevant change to the agent environment. Blast radius **%s**.\n", d.BlastAfter.Level)
		return b.String()
	}
	if d.BlastBefore.Level != d.BlastAfter.Level {
		fmt.Fprintf(&b, "**Blast radius: %s → %s**\n\n", d.BlastBefore.Level, d.BlastAfter.Level)
	} else {
		fmt.Fprintf(&b, "Blast radius: **%s** (unchanged)\n\n", d.BlastAfter.Level)
	}
	if len(d.PathsAdded) > 0 {
		fmt.Fprintf(&b, "### 🔴 New attack path%s\n\n", plural(len(d.PathsAdded)))
		for _, p := range d.PathsAdded {
			fmt.Fprintf(&b, "**%s %s** (%s, confidence %s)\n\n```\n", strings.ToUpper(p.Severity), p.Name, strings.Join(p.Servers, " + "), p.Confidence)
			for i, s := range p.Steps {
				if i == 0 {
					fmt.Fprintf(&b, "    %s\n", s)
				} else {
					fmt.Fprintf(&b, "  ↓ %s\n", s)
				}
			}
			fmt.Fprintf(&b, "```\n\n%s\n\n**Fix:** %s\n\n", p.Impact, p.Remediation)
		}
	}
	if len(d.PathsRemoved) > 0 {
		fmt.Fprintf(&b, "### 🟢 Attack path%s removed\n\n", plural(len(d.PathsRemoved)))
		for _, p := range d.PathsRemoved {
			fmt.Fprintf(&b, "- ~~%s %s~~ (%s)\n", strings.ToUpper(p.Severity), p.Name, strings.Join(p.Servers, " + "))
		}
		b.WriteString("\n")
	}
	sec := d.SecurityRelevant()
	if len(sec) > 0 {
		fmt.Fprintf(&b, "### Changes\n\n")
		for _, ch := range sec {
			label := "⚠️"
			if ch.Class == ClassSuspicious {
				label = "🚨"
			}
			fmt.Fprintf(&b, "%s **%s** `%s`\n\n", label, ch.Kind, ch.Entity)
			if ch.Before != "" {
				fmt.Fprintf(&b, "- Before: %s\n", mdInline(ch.Before))
			}
			if ch.After != "" {
				fmt.Fprintf(&b, "- After: %s\n", mdInline(ch.After))
			}
			if ch.Reason != "" {
				fmt.Fprintf(&b, "- Why flagged: %s\n", ch.Reason)
			}
			fmt.Fprintf(&b, "\n%s\n\n", ch.Impact)
		}
	}
	var info int
	for _, ch := range d.Changes {
		if ch.Class == ClassInformational {
			info++
		}
	}
	if info > 0 {
		fmt.Fprintf(&b, "<details><summary>%d informational change%s</summary>\n\n", info, plural(info))
		for _, ch := range d.Changes {
			if ch.Class == ClassInformational {
				fmt.Fprintf(&b, "- %s `%s`", ch.Kind, ch.Entity)
				if ch.After != "" && ch.Kind != ToolAdded {
					fmt.Fprintf(&b, ": %s", mdInline(ch.After))
				}
				b.WriteString("\n")
			}
		}
		b.WriteString("\n</details>\n\n")
	}
	if d.StaticAfter {
		b.WriteString("_Capabilities inferred from packages and configs; no server was launched._\n")
	}
	return b.String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func mdInline(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return "`" + s + "`"
}

func quoteIfText(s string) string {
	if strings.ContainsAny(s, " ") && !strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "~") {
		return `"` + truncate(s, 160) + `"`
	}
	return truncate(s, 160)
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func wrap(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	var cur string
	for _, w := range words {
		if len(cur)+len(w)+1 > width && cur != "" {
			lines = append(lines, cur)
			cur = w
			continue
		}
		if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// PathSeverities is a helper for gates: severities of the added paths.
func PathSeverities(chains []attackpath.AttackChain) []string {
	var out []string
	for _, c := range chains {
		out = append(out, c.Severity)
	}
	return out
}
