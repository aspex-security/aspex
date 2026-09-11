// Package tighten recommends least-privilege agent configuration by comparing
// what is configured (the environment) with what was observed (trace events).
// It only recommends; it never edits a config. Every recommendation says it
// is based on observed usage, and refuses to call an unobserved tool
// unnecessary when the evidence is thin.
package tighten

import (
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/correlate"
	"github.com/aspex-security/aspex/internal/logparse"
)

// Options tunes the analysis.
type Options struct {
	Window   time.Duration // how far back the events reach
	MinCalls int           // below this many calls to a server, tool recommendations are marked weak
	Home     string
}

// ToolRec is the allowlist recommendation for one server.
type ServerRec struct {
	Server        string   `json:"server"`
	Client        string   `json:"client"`
	Calls         int      `json:"observed_calls"`
	Exposed       int      `json:"exposed_tools"`
	Observed      []string `json:"observed_tools"`
	Unobserved    []string `json:"unobserved_tools"`
	Evidence      string   `json:"evidence"` // strong | weak | none
	Roots         []string `json:"filesystem_roots,omitempty"`
	ObservedPaths []string `json:"observed_paths,omitempty"`
	NeverObserved []string `json:"never_observed_sensitive,omitempty"`
	Recommended   []string `json:"recommended_roots,omitempty"`
	Reduction     string   `json:"scope_reduction,omitempty"` // qualitative
	Note          string   `json:"note,omitempty"`
}

// Report is the full recommendation set.
type Report struct {
	Window     time.Duration `json:"window_seconds"`
	Events     int           `json:"events"`
	Servers    []ServerRec   `json:"servers"`
	NoActivity []string      `json:"servers_with_no_activity"`
	Static     bool          `json:"static"`
}

var sensitiveUnderHome = []string{".ssh", ".aws", ".gnupg", ".kube", ".docker", "Documents", "Downloads", "Desktop", "Library"}

// Analyze builds the report.
func Analyze(env agentenv.Environment, events []logparse.Event, opts Options) Report {
	if opts.MinCalls == 0 {
		opts.MinCalls = 20
	}
	r := Report{Window: opts.Window, Events: len(events), Static: env.Static}
	activity := correlate.Summarize(events)
	pathsByServer := observedPaths(events, opts.Home)

	for _, s := range env.Servers {
		act := correlate.Match(activity, s.Name)
		rec := ServerRec{Server: s.Name, Client: s.Client, Exposed: len(s.Tools), Roots: s.Roots}
		if act == nil || act.Calls == 0 {
			r.NoActivity = append(r.NoActivity, s.Name)
			rec.Evidence = "none"
			rec.Note = "Not observed in the available traces. Candidate for removal if the window is representative; do not treat as proof it is unused."
			if len(s.Tools) > 0 {
				for _, t := range s.Tools {
					rec.Unobserved = append(rec.Unobserved, t.Name)
				}
			}
			r.Servers = append(r.Servers, rec)
			continue
		}
		rec.Calls = act.Calls
		rec.Evidence = "strong"
		if act.Calls < opts.MinCalls {
			rec.Evidence = "weak"
		}
		seen := map[string]bool{}
		for _, t := range act.Tools {
			seen[t] = true
			rec.Observed = append(rec.Observed, t)
		}
		sort.Strings(rec.Observed)
		for _, t := range s.Tools {
			if !seen[t.Name] {
				rec.Unobserved = append(rec.Unobserved, t.Name)
			}
		}
		if len(s.Tools) == 0 {
			rec.Note = "Tool list unavailable (static scan); run without --no-exec to get an allowlist recommendation."
		} else if rec.Evidence == "weak" {
			rec.Note = fmt.Sprintf("Only %d calls observed; the unobserved list is a hint, not a recommendation.", act.Calls)
		}

		// Filesystem scope: compare declared roots with where reads/writes went.
		if len(s.Roots) > 0 && capHas(s, "file-read") {
			rec.ObservedPaths = pathsByServer[correlate.Normalize(s.Name)]
			rec.Recommended, rec.NeverObserved, rec.Reduction = recommendRoots(s.Roots, rec.ObservedPaths, opts.Home, act.Calls >= opts.MinCalls)
		}
		r.Servers = append(r.Servers, rec)
	}
	sort.Slice(r.Servers, func(i, j int) bool {
		// Biggest wins first: many unobserved tools or a scope reduction.
		wi := len(r.Servers[i].Unobserved) + boolInt(r.Servers[i].Reduction != "")*100
		wj := len(r.Servers[j].Unobserved) + boolInt(r.Servers[j].Reduction != "")*100
		if wi != wj {
			return wi > wj
		}
		return r.Servers[i].Server < r.Servers[j].Server
	})
	sort.Strings(r.NoActivity)
	return r
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func capHas(s agentenv.Server, c string) bool {
	for _, x := range s.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}

// observedPaths collects absolute paths from tool arguments, per normalized
// server name. Content-bearing args are skipped so file contents that
// happen to contain paths are not mistaken for accessed files.
func observedPaths(events []logparse.Event, home string) map[string][]string {
	skip := map[string]bool{"content": true, "new_string": true, "old_string": true, "text": true, "body": true, "data": true, "query": true, "sql": true, "message": true}
	out := map[string]map[string]bool{}
	for _, ev := range events {
		if ev.Event != logparse.EventToolsCall || ev.Server == "" {
			continue
		}
		key := correlate.Normalize(ev.Server)
		for k, v := range ev.Args {
			if skip[strings.ToLower(k)] || v == "" {
				continue
			}
			v = filepath.ToSlash(strings.TrimSpace(v))
			if strings.HasPrefix(v, "~/") && home != "" {
				v = path.Join(filepath.ToSlash(home), v[2:])
			}
			if !strings.HasPrefix(v, "/") || strings.ContainsAny(v, "\n ") {
				continue
			}
			if out[key] == nil {
				out[key] = map[string]bool{}
			}
			out[key][path.Clean(v)] = true
		}
	}
	res := map[string][]string{}
	for k, set := range out {
		for p := range set {
			res[k] = append(res[k], p)
		}
		sort.Strings(res[k])
	}
	return res
}

// recommendRoots proposes narrower roots from observed paths. Roots are
// collapsed to at most two path components below home (or below the root
// itself), so ~/projects/acme/src/x.go becomes ~/projects/acme. Sensitive
// home subdirectories that were never touched are listed by name. The
// reduction is qualitative unless the evidence is strong.
func recommendRoots(roots, observed []string, home string, strong bool) (recommended, neverObserved []string, reduction string) {
	if len(observed) == 0 {
		return nil, nil, ""
	}
	home = filepath.ToSlash(home)
	for i := range roots {
		roots[i] = filepath.ToSlash(roots[i])
	}
	broad := false
	for _, r := range roots {
		if r == "/" || (home != "" && (r == home || isAncestorOf(r, home))) {
			broad = true
		}
	}
	if !broad {
		return nil, nil, "" // already scoped; nothing to recommend from paths alone
	}
	set := map[string]bool{}
	for _, p := range observed {
		set[collapse(p, home)] = true
	}
	for p := range set {
		recommended = append(recommended, p)
	}
	sort.Strings(recommended)
	touched := map[string]bool{}
	for _, p := range observed {
		if home != "" && strings.HasPrefix(p, home+"/") {
			first := strings.SplitN(strings.TrimPrefix(p, home+"/"), "/", 2)[0]
			touched[first] = true
		}
	}
	for _, d := range sensitiveUnderHome {
		if !touched[d] {
			neverObserved = append(neverObserved, "~/"+d)
		}
	}
	switch {
	case !strong:
		reduction = "LIKELY SIGNIFICANT (weak evidence: few observed calls)"
	case len(recommended) <= 3:
		reduction = "SIGNIFICANT: from the whole home directory to " + fmt.Sprintf("%d director%s", len(recommended), plural(len(recommended), "y", "ies"))
	default:
		reduction = "MODERATE: " + fmt.Sprintf("%d directories", len(recommended)) + " instead of the whole home directory"
	}
	return recommended, neverObserved, reduction
}

func collapse(p, home string) string {
	if home != "" && strings.HasPrefix(p, home+"/") {
		rest := strings.Split(strings.TrimPrefix(p, home+"/"), "/")
		n := 2
		if len(rest) < n {
			n = len(rest)
		}
		// A file directly under home: keep the file's directory (home itself
		// would be no reduction), so recommend the file path.
		if len(rest) == 1 {
			return "~/" + rest[0]
		}
		return "~/" + strings.Join(rest[:n], "/")
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	n := 3
	if len(parts) < n {
		n = len(parts)
	}
	return "/" + strings.Join(parts[:n], "/")
}

func isAncestorOf(dir, p string) bool {
	dir = strings.TrimSuffix(dir, "/")
	return p == dir || strings.HasPrefix(p, dir+"/")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ---- rendering ---------------------------------------------------------------

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	purple = "\033[35m"
)

// Print renders the report for a terminal.
func Print(w io.Writer, r Report, noColor bool) {
	c := func(col, s string) string {
		if noColor {
			return s
		}
		return col + s + reset
	}
	fmt.Fprintf(w, "\n  %s  %s  %s\n\n", c(purple+bold, "◆"), c(bold, "Least-privilege recommendations"),
		c(dim, fmt.Sprintf("based on %d observed calls over %s", r.Events, humanWindow(r.Window))))
	if r.Events == 0 {
		fmt.Fprintf(w, "  %s No agent activity found in this window. Nothing can be recommended from observed use;\n  widen --since or run your agents first.\n\n", c(yellow, "!"))
		return
	}
	for _, s := range r.Servers {
		if s.Evidence == "none" {
			continue
		}
		fmt.Fprintf(w, "  %s  %s\n", c(bold+cyan, s.Server), c(dim, fmt.Sprintf("%d calls · %s evidence", s.Calls, s.Evidence)))
		if s.Exposed > 0 {
			fmt.Fprintf(w, "     %s %d    %s %d\n", c(dim, "Exposed tools:"), s.Exposed, c(dim, "Observed:"), len(s.Observed))
			if len(s.Unobserved) > 0 {
				label := "Candidates for removal (not observed in available traces):"
				if s.Evidence == "weak" {
					label = "Not observed (weak evidence, review only):"
				}
				fmt.Fprintf(w, "     %s\n", c(dim, label))
				for _, t := range s.Unobserved {
					fmt.Fprintf(w, "       %s %s\n", c(yellow, "-"), t)
				}
			}
			if len(s.Observed) > 0 {
				fmt.Fprintf(w, "     %s\n", c(dim, "Recommended allowlist:"))
				for _, t := range s.Observed {
					fmt.Fprintf(w, "       %s %s\n", c(green, "+"), t)
				}
			}
		}
		if len(s.Roots) > 0 {
			fmt.Fprintf(w, "     %s %s\n", c(dim, "Current scope:"), strings.Join(s.Roots, ", "))
			if len(s.ObservedPaths) > 0 {
				fmt.Fprintf(w, "     %s %d path(s), e.g. %s\n", c(dim, "Observed usage:"), len(s.ObservedPaths), strings.Join(firstN(s.ObservedPaths, 3), ", "))
			}
			if len(s.NeverObserved) > 0 {
				fmt.Fprintf(w, "     %s %s\n", c(dim, "Never observed:"), strings.Join(s.NeverObserved, ", "))
			}
			if len(s.Recommended) > 0 {
				fmt.Fprintf(w, "     %s\n", c(dim, "Recommendation:"))
				for _, r := range s.Roots {
					fmt.Fprintf(w, "       %s %s\n", c(red, "-"), r)
				}
				for _, r := range s.Recommended {
					fmt.Fprintf(w, "       %s %s\n", c(green, "+"), r)
				}
				fmt.Fprintf(w, "     %s %s\n", c(dim, "Blast-radius reduction:"), c(bold, s.Reduction))
			}
		}
		if s.Note != "" {
			fmt.Fprintf(w, "     %s\n", c(dim, s.Note))
		}
		fmt.Fprintln(w)
	}
	if len(r.NoActivity) > 0 {
		fmt.Fprintf(w, "  %s %s\n", c(bold, "No activity in this window:"), strings.Join(r.NoActivity, ", "))
		fmt.Fprintf(w, "  %s\n\n", c(dim, "Candidates for removal if the window is representative. Absence in traces is not proof of disuse."))
	}
	fmt.Fprintf(w, "  %s\n\n", c(dim, "Aspex recommends; it never edits your config. Apply changes in your client, then re-run aspex-scan lock."))
}

func humanWindow(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	return d.String()
}

func firstN(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}
