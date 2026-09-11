// Package snapshot builds the one-screen answer to "what did my AI agents do
// this week, and how risky is what they can reach?" It is what `aspex` shows
// with no arguments: static findings for every configured server joined with
// observed activity from the clients' own logs, reduced to a few sentences a
// person can read in ten seconds and paste into a chat.
package snapshot

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/correlate"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/policy"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/score"
	"github.com/aspex-security/aspex/internal/trace"
)

// ServerLine is one configured server in the snapshot.
type ServerLine struct {
	Name   string
	Client string
	Score  int
	MaxSev rules.Severity
	Calls  int // observed calls in the window, 0 if never seen
}

// Snapshot is the computed picture.
type Snapshot struct {
	Version    string
	Window     time.Duration
	Static     bool // configs only, servers not launched
	Servers    []ServerLine
	Overall    score.OverallScore
	Policy     string // path of .aspex.yaml applied, if any
	Suppressed int
	// Paths are cross-server capability compositions, most severe first.
	Paths []attackpath.AttackChain

	Events        int
	Calls         int
	SeenServers   int                   // distinct servers in logs, excluding client built-ins
	Unscored      []*correlate.Activity // in use, in no scanned config
	UnscoredCalls int
	Flagged       int
	FlaggedBySev  map[rules.Severity]int
	TopRule       string
	TopRuleCount  int
	ClientsSeen   []string
}

// Build discovers every configured server, evaluates it statically, reads the
// last window of agent logs, and joins the two.
func Build(ctx context.Context, version string, window time.Duration) *Snapshot {
	s := &Snapshot{Version: version, Window: window, Static: true, FlaggedBySev: map[rules.Severity]int{}}
	now := time.Now()

	// Static side.
	entries, _ := discover.DiscoverAll(discover.AllClients)
	inspected := inspect.InspectAll(ctx, entries, inspect.Options{NoExec: true}, nil)
	cfg, _ := policy.Load("")
	if cfg != nil {
		s.Policy = cfg.Path
	}
	var scores []score.ServerScore
	for _, srv := range inspected {
		findings := rules.EvalServer(srv)
		kept, sup, _ := cfg.Apply(srv.Entry.Name, findings, now)
		s.Suppressed += len(sup)
		sc := score.ScoreServer(kept)
		scores = append(scores, sc)
		var maxSev rules.Severity
		for _, f := range kept {
			if f.Severity > maxSev {
				maxSev = f.Severity
			}
		}
		s.Servers = append(s.Servers, ServerLine{Name: srv.Entry.Name, Client: srv.Entry.Client, Score: sc.Score, MaxSev: maxSev})
	}
	s.Overall = score.ScoreOverall(scores)
	_, s.Paths = attackpath.Analyze(inspected)
	var sevs, names []string
	for _, p := range s.Paths {
		sevs, names = append(sevs, p.Severity), append(names, p.Name)
	}
	s.Overall = score.ApplyAttackPaths(s.Overall, sevs, names)

	// Runtime side.
	events, clients, _ := logparse.CollectEvents(nil, now.Add(-window))
	s.Events = len(events)
	s.ClientsSeen = clients
	activity := correlate.Summarize(events)

	matched := map[*correlate.Activity]bool{}
	for i := range s.Servers {
		if a := correlate.Match(activity, s.Servers[i].Name); a != nil {
			s.Servers[i].Calls = a.Calls
			matched[a] = true
		}
	}
	for name, a := range activity {
		if correlate.IsClientBuiltin(name) {
			continue
		}
		s.Calls += a.Calls
		if a.Calls > 0 {
			s.SeenServers++
		}
		if !matched[a] && a.Calls > 0 {
			s.Unscored = append(s.Unscored, a)
			s.UnscoredCalls += a.Calls
		}
	}
	sort.Slice(s.Unscored, func(i, j int) bool { return s.Unscored[i].Calls > s.Unscored[j].Calls })

	ruleCount := map[string]int{}
	for _, fe := range trace.AnalyzeEvents(events) {
		if correlate.IsClientBuiltin(fe.Event.Server) {
			continue
		}
		s.Flagged++
		var top rules.Severity
		for _, f := range fe.Findings {
			ruleCount[f.Name]++
			if f.Severity > top {
				top = f.Severity
			}
		}
		s.FlaggedBySev[top]++
	}
	for name, n := range ruleCount {
		if n > s.TopRuleCount {
			s.TopRule, s.TopRuleCount = name, n
		}
	}

	// Worst first.
	sort.SliceStable(s.Servers, func(i, j int) bool {
		if s.Servers[i].MaxSev != s.Servers[j].MaxSev {
			return s.Servers[i].MaxSev > s.Servers[j].MaxSev
		}
		return s.Servers[i].Calls > s.Servers[j].Calls
	})
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func humanWindow(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days >= 14 && days%7 == 0 && days%30 != 0:
		w := days / 7
		return fmt.Sprintf("%d weeks", w)
	case days >= 1:
		return fmt.Sprintf("%d %s", days, plural(days, "day", "days"))
	default:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
}

// Headlines are the sentences. They are written to be true, specific, and
// worth repeating to someone else - that is the whole point of the snapshot.
func (s *Snapshot) Headlines() []string {
	var h []string
	win := humanWindow(s.Window)

	if s.Events == 0 {
		h = append(h, fmt.Sprintf("No agent activity found in the last %s. Aspex reads logs from Claude Code, Claude Desktop, Cursor, Windsurf, Cline and Roo.", win))
	} else {
		h = append(h, fmt.Sprintf("In the last %s your agents made %d tool %s to %d MCP %s.",
			win, s.Calls, plural(s.Calls, "call", "calls"), s.SeenServers, plural(s.SeenServers, "server", "servers")))
		if s.UnscoredCalls > 0 {
			target := fmt.Sprintf("%d %s no security scan had ever checked", len(s.Unscored), plural(len(s.Unscored), "server", "servers"))
			if s.UnscoredCalls == s.Calls {
				h = append(h, fmt.Sprintf("All of them went to %s.", target))
			} else {
				h = append(h, fmt.Sprintf("%d of those calls went to %s.", s.UnscoredCalls, target))
			}
		}
		if s.Flagged > 0 {
			line := fmt.Sprintf("%d %s tripped a detection rule", s.Flagged, plural(s.Flagged, "call", "calls"))
			if s.TopRule != "" {
				line += fmt.Sprintf(". Most common: %s (%d)", strings.ToLower(s.TopRule[:1])+s.TopRule[1:], s.TopRuleCount)
			}
			h = append(h, line+".")
		}
	}

	if len(s.Servers) == 0 {
		h = append(h, "No MCP servers configured in any supported client.")
	} else {
		line := fmt.Sprintf("%d configured %s, overall security score %d/100.",
			len(s.Servers), plural(len(s.Servers), "server", "servers"), s.Overall.Score)
		if len(s.Paths) > 0 {
			line += fmt.Sprintf(" %d potential attack %s across servers; worst: %s (%s).",
				len(s.Paths), plural(len(s.Paths), "path", "paths"), strings.ToLower(s.Paths[0].Name), s.Paths[0].Severity)
		}
		worst := s.Servers[0]
		if worst.MaxSev >= rules.SeverityHigh {
			if worst.Calls > 0 {
				line += fmt.Sprintf(" Riskiest: %s (%d), used %d %s this period.", worst.Name, worst.Score, worst.Calls, plural(worst.Calls, "time", "times"))
			} else {
				line += fmt.Sprintf(" Riskiest: %s (%d), not used in this period - a good candidate to remove.", worst.Name, worst.Score)
			}
		}
		h = append(h, line)
	}
	return h
}

// Render writes the terminal panel.
func (s *Snapshot) Render(w io.Writer, noColor bool) {
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		dim    = "\033[2m"
		purple = "\033[35m"
		red    = "\033[91m"
		yellow = "\033[93m"
		green  = "\033[92m"
		cyan   = "\033[96m"
	)
	c := func(col, t string) string {
		if noColor {
			return t
		}
		return col + t + reset
	}
	sevColor := func(sev rules.Severity) string {
		switch {
		case sev >= rules.SeverityCritical:
			return red
		case sev >= rules.SeverityHigh:
			return yellow
		case sev >= rules.SeverityMedium:
			return cyan
		}
		return green
	}

	fmt.Fprintf(w, "\n  %s  %s  %s\n\n", c(purple+bold, "◆"), c(bold, "Your AI agents, last "+humanWindow(s.Window)), c(dim, "aspex v"+s.Version))
	for _, line := range s.Headlines() {
		fmt.Fprintf(w, "  %s %s\n", c(purple, "▸"), line)
	}

	if len(s.Servers) > 0 {
		fmt.Fprintln(w)
		shown := s.Servers
		if len(shown) > 6 {
			shown = shown[:6]
		}
		for _, sl := range shown {
			used := c(dim, "not used")
			if sl.Calls > 0 {
				used = fmt.Sprintf("%d %s", sl.Calls, plural(sl.Calls, "call", "calls"))
			}
			sev := c(dim, "clean")
			if sl.MaxSev > 0 {
				sev = c(sevColor(sl.MaxSev), sl.MaxSev.String())
			}
			fmt.Fprintf(w, "    %-20s %3d  %-9s %s\n", sl.Name, sl.Score, sev, used)
		}
		if len(s.Servers) > len(shown) {
			fmt.Fprintf(w, "    %s\n", c(dim, fmt.Sprintf("+%d more", len(s.Servers)-len(shown))))
		}
	}
	if len(s.Unscored) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s %s\n", c(yellow+bold, "?"), c(bold, "In use, never scanned:"))
		shown := s.Unscored
		if len(shown) > 4 {
			shown = shown[:4]
		}
		for _, a := range shown {
			flag := ""
			if a.Flagged > 0 {
				flag = c(red, fmt.Sprintf("  %d flagged", a.Flagged))
			}
			fmt.Fprintf(w, "    %-38s %d %s%s\n", a.Server, a.Calls, plural(a.Calls, "call", "calls"), flag)
		}
		if len(s.Unscored) > len(shown) {
			fmt.Fprintf(w, "    %s\n", c(dim, fmt.Sprintf("+%d more", len(s.Unscored)-len(shown))))
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", c(dim, "aspex-scan for findings and fixes  ·  aspex-trace for the full audit trail  ·  aspex share to post this"))
	if s.Static {
		fmt.Fprintf(w, "  %s\n", c(dim, "scores are from configs only; aspex-scan connects to each server for the full picture"))
	}
	fmt.Fprintln(w)
}

// ShareCard is a privacy-safe Markdown card: counts and score only, no server
// names, paths, or commands. Safe to paste anywhere.
func (s *Snapshot) ShareCard() string {
	var b strings.Builder
	b.WriteString("**My AI agents, last " + humanWindow(s.Window) + "** (via [Aspex](https://github.com/aspex-security/aspex))\n\n")
	for _, line := range s.Headlines() {
		// Strip server names from the "Riskiest:" sentence for sharing.
		if i := strings.Index(line, " Riskiest:"); i >= 0 {
			line = line[:i]
		}
		b.WriteString("- " + line + "\n")
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("Score **%d/100** · %d servers scanned · %d tool calls observed · %d flagged\n\n",
		s.Overall.Score, len(s.Servers), s.Calls, s.Flagged))
	b.WriteString("Check yours: `brew install aspex-security/tap/aspex && aspex`  ")
	b.WriteString("Offline, no account, nothing leaves your machine.\n")
	return b.String()
}
