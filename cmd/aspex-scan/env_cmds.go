package main

// Environment commands: lock, verify, diff. All three consume one model
// (internal/agentenv) so a change reads the same whether it was detected
// against a lockfile, between two git revisions, or in a PR comment.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/aspexmcp"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/explore"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/killchain"
	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/provenance"
	"github.com/aspex-security/aspex/internal/registry"
	"github.com/aspex-security/aspex/internal/report"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/tighten"
	"github.com/aspex-security/aspex/internal/trace"
	"github.com/aspex-security/aspex/internal/version"
)

// loadEnvironment discovers and inspects every configured server on this
// machine and assembles the environment, including local hooks, skills and
// instruction files. Honors --no-exec, --clients, -j.
func loadEnvironment(gf *globalFlags, quiet bool) agentenv.Environment {
	in := loadInputs(gf, quiet)
	return agentenv.Build(in.Servers, in.Options)
}

// loadInputs discovers and inspects every configured server once and returns
// the inputs an environment is built from, so simulate can rebuild
// before/after through the same pipeline without inspecting twice.
func loadInputs(gf *globalFlags, quiet bool) agentenv.Inputs {
	entries, discoveryErrs := discover.DiscoverAll(gf.clients)
	if !quiet {
		for _, e := range discoveryErrs {
			fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
		}
	}
	ctx := context.Background()
	inspected := inspect.InspectAll(ctx, entries, inspect.Options{NoExec: gf.noExec, Concurrency: gf.concurrency}, nil)
	cwd, _ := os.Getwd()
	return agentenv.Inputs{Servers: inspected, Options: agentenv.Options{Cwd: cwd}}
}

func projectRootHint() string {
	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
		return ""
	}
	return cwd
}

func lockPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return agentenv.LockFileName
}

// ---------------------------------------------------------------------------
// lock
// ---------------------------------------------------------------------------

func newLockCmd(gf *globalFlags) *cobra.Command {
	var out string
	var stdout bool
	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Write the agent security lockfile (.aspex.lock)",
		Long: `Record the security-relevant state of this agent environment in a lockfile:
every MCP server's identity and full tool surface (names, descriptions,
schema hashes), its capabilities and filesystem scope, lifecycle hooks,
skills, instruction files (hashed), reachable sensitive resources, attack
paths and blast radius.

The file is deterministic and diffable. Commit it. Then:

  aspex-scan verify        exit 1 when the environment drifted from the lock
  aspex-scan diff          explain what changed in security terms

No secret values are ever written; env var names only.`,
		Example: `  aspex-scan lock                    # writes .aspex.lock
  aspex-scan lock --no-exec          # configs only, nothing launched
  aspex-scan lock -o infra/agent.lock`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			env := loadEnvironment(gf, false)
			if stdout || gf.jsonOut {
				data, err := agentenv.Marshal(env, version.Version)
				if err != nil {
					return err
				}
				os.Stdout.Write(data)
				return nil
			}
			p := lockPath(out)
			prev, prevErr := agentenv.ReadLock(p)
			if err := agentenv.WriteLock(p, env, version.Version); err != nil {
				return err
			}
			c := func(col, s string) string {
				if gf.noColor {
					return s
				}
				return col + s + ansiReset
			}
			fmt.Fprintf(os.Stdout, "\n  %s  %s %s\n\n", c(ansiPurple+ansiBold, "◆"), c(ansiBold, "Locked"), c(ansiDim, p))
			agentenv.PrintSummary(os.Stdout, env, gf.noColor)
			if prevErr == nil {
				d := agentenv.Compare(prev, env)
				if !d.Empty() {
					fmt.Fprintf(os.Stdout, "\n  %s Replaced a previous lock that differed (%d change(s)). Review with: git diff %s\n", c(ansiYellow, "note:"), len(d.Changes), p)
				}
			}
			fmt.Fprintf(os.Stdout, "\n  %s\n\n", c(ansiDim, "Next: commit "+p+", then run aspex-scan verify in CI."))
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "Lockfile path (default .aspex.lock)")
	cmd.Flags().BoolVar(&stdout, "stdout", false, "Print the lockfile instead of writing it")
	return cmd
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

func newVerifyCmd(gf *globalFlags) *cobra.Command {
	var lockFile string
	var verbose bool
	var failOn string
	cmd := &cobra.Command{
		Use:   "verify [lockfile]",
		Short: "Check the environment against .aspex.lock and explain any drift",
		Long: `Compare the current agent environment with the lockfile written by
aspex-scan lock. Drift is reported by security meaning, not as "file changed":

  NEW TOOL, TOOL DESCRIPTION CHANGED (classified informational,
  security-relevant or suspicious from its content), CAPABILITY ADDED,
  FILESYSTEM SCOPE EXPANDED, NETWORK EGRESS OPENED, AGENT STATE NEWLY
  WRITABLE, HOOK/SKILL/INSTRUCTION changes, NEW ATTACK PATH, and the blast
  radius before and after.

Exit codes: 0 no drift at or above --fail-on, 1 drift, 2 error.`,
		Example: `  aspex-scan verify                       # against ./.aspex.lock
  aspex-scan verify --fail-on suspicious  # only rug-pull-shaped changes fail
  aspex-scan verify --json | jq .changes`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				lockFile = args[0]
				// Compatibility: `verify <package>` used to look a package up in
				// the known-malicious registry. Route that use through.
				looksLikePackage := strings.HasPrefix(lockFile, "@") || !strings.ContainsAny(lockFile, `/\`)
				if _, err := os.Stat(lockFile); err != nil && looksLikePackage && !strings.HasSuffix(lockFile, ".lock") {
					fmt.Fprintf(os.Stderr, "note: package lookup moved to `aspex-scan check-package %s`\n\n", lockFile)
					return printRegistryLookup(lockFile)
				}
			}
			p := lockPath(lockFile)
			locked, err := agentenv.ReadLock(p)
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("no lockfile at %s. Create one with: aspex-scan lock", p)
				}
				return err
			}
			current := loadEnvironment(gf, gf.jsonOut)
			d := agentenv.Compare(locked, current)
			d.SetProjectRoot(projectRootHint())

			if gf.jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(struct {
					Version  string `json:"version"`
					Lockfile string `json:"lockfile"`
					Drifted  bool   `json:"drift"`
					Worst    string `json:"worst"`
					agentenv.Drift
				}{version.Version, p, !d.Empty(), d.Worst(), d}); err != nil {
					return err
				}
			} else {
				agentenv.PrintDrift(os.Stdout, d, gf.noColor, verbose)
			}
			return verifyGate(d, failOn)
		},
	}
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show informational changes too")
	cmd.Flags().StringVar(&failOn, "fail-on", "security-relevant", "Exit 1 when drift reaches this class: suspicious | security-relevant | informational | off")
	return cmd
}

// verifyGate maps drift class to an exit code. New attack paths always count
// as security-relevant.
func verifyGate(d agentenv.Drift, failOn string) error {
	rank := func(c string) int {
		switch c {
		case agentenv.ClassSuspicious:
			return 3
		case agentenv.ClassSecurityRelevant:
			return 2
		case agentenv.ClassInformational:
			return 1
		}
		return 0
	}
	switch failOn {
	case "off", "":
		return nil
	case "suspicious", "security-relevant", "informational":
	default:
		return fmt.Errorf("--fail-on must be suspicious, security-relevant, informational, or off")
	}
	if rank(d.Worst()) >= rank(failOn) && rank(d.Worst()) > 0 {
		return errExitOne
	}
	return nil
}

func printRegistryLookup(pkg string) error {
	entry := registry.Lookup(pkg)
	if entry == nil {
		fmt.Printf("No registry entry found for %q\n", pkg)
		return nil
	}
	fmt.Printf("Package:  %s\nVersion:  %s\nSeverity: %s\nSummary:  %s\n", entry.Package, entry.Version, entry.Severity, entry.Summary)
	if entry.FixedIn != "" {
		fmt.Printf("Fixed in: %s\n", entry.FixedIn)
	}
	if entry.CVE != "" {
		fmt.Printf("CVE:      %s\n", entry.CVE)
	}
	return nil
}

func newCheckPackageCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "check-package <package-name>",
		Short:         "Check a package name against the known-malicious registry",
		Long:          "Look up a package name in Aspex's registry of known-malicious MCP server packages. Checks for exact matches, typosquats, and known CVEs. (Formerly `verify <package>`.)",
		Example:       "  aspex-scan check-package @modelcontextprotocol/server-filesystem",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          func(cmd *cobra.Command, args []string) error { return printRegistryLookup(args[0]) },
	}
}

// ---------------------------------------------------------------------------
// diff
// ---------------------------------------------------------------------------

func newDiffCmd(gf *globalFlags) *cobra.Command {
	var baselineFile, lockFile, markdownOut string
	var verbose bool
	cmd := &cobra.Command{
		Use:   "diff [<rev>|<rev>..<rev>|<lock> <lock>]",
		Short: "Security impact diff: what changed in the agent's effective capabilities",
		Long: `Not a textual config diff. Answers: what changed in what the agent can do,
what it can reach, and which attack paths exist.

  aspex-scan diff                 lockfile vs the environment right now
  aspex-scan diff main..HEAD      this repo's agent config between two revisions
  aspex-scan diff HEAD~1          a revision vs the working tree
  aspex-scan diff a.lock b.lock   two lockfiles

Revision diffs read only the project's own files (.mcp.json, .cursor/mcp.json,
.vscode/mcp.json, .claude/settings*.json, .claude/skills, CLAUDE.md,
.cursorrules, AGENTS.md) at each side and analyze them statically. Nothing
from either revision is executed.

--baseline <scan.json> keeps the older finding-level diff against a saved
aspex-scan --json output.`,
		Example: `  aspex-scan diff main..HEAD --markdown pr-comment.md
  aspex-scan diff HEAD~1 --json`,
		Args:          cobra.MaximumNArgs(2),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if baselineFile != "" {
				return runFindingDiff(gf, baselineFile)
			}
			ctx := context.Background()
			home, _ := os.UserHomeDir()
			cwd, _ := os.Getwd()
			var before, after agentenv.Environment
			var title string

			switch {
			case len(args) == 2:
				var err error
				if before, err = agentenv.ReadLock(args[0]); err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				if after, err = agentenv.ReadLock(args[1]); err != nil {
					return fmt.Errorf("%s: %w", args[1], err)
				}
				title = fmt.Sprintf("Aspex: %s → %s", filepath.Base(args[0]), filepath.Base(args[1]))
			case len(args) == 1:
				root := agentenv.GitRoot(cwd)
				if root == "" {
					return fmt.Errorf("not inside a git repository; pass two lockfiles instead")
				}
				spec := args[0]
				var err error
				if a, b, ok := strings.Cut(spec, ".."); ok {
					if before, err = agentenv.BuildRevision(ctx, root, a, home); err != nil {
						return err
					}
					if after, err = agentenv.BuildRevision(ctx, root, b, home); err != nil {
						return err
					}
					title = "Aspex agent security impact: " + spec
				} else {
					if before, err = agentenv.BuildRevision(ctx, root, spec, home); err != nil {
						return err
					}
					after = agentenv.BuildWorkingTree(ctx, root, home)
					title = "Aspex agent security impact: " + spec + " → working tree"
				}
			default:
				p := lockPath(lockFile)
				var err error
				if before, err = agentenv.ReadLock(p); err != nil {
					if os.IsNotExist(err) {
						return fmt.Errorf("no lockfile at %s. Create one with: aspex-scan lock, or diff two git revisions", p)
					}
					return err
				}
				after = loadEnvironment(gf, gf.jsonOut)
				title = "Aspex: " + p + " → now"
			}

			d := agentenv.Compare(before, after)
			if root := agentenv.GitRoot(cwd); root != "" {
				d.SetProjectRoot(root)
			} else {
				d.SetProjectRoot(cwd)
			}
			if markdownOut != "" {
				md := agentenv.Markdown(d, title)
				if markdownOut == "-" {
					fmt.Print(md)
				} else if err := os.WriteFile(markdownOut, []byte(md), 0o644); err != nil {
					return err
				}
			}
			if gf.jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					Version string `json:"version"`
					Title   string `json:"title"`
					Worst   string `json:"worst"`
					agentenv.Drift
				}{version.Version, title, d.Worst(), d})
			}
			if markdownOut != "-" {
				agentenv.PrintDrift(os.Stdout, d, gf.noColor, verbose)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&baselineFile, "baseline", "", "Finding-level diff against a saved aspex-scan --json output")
	cmd.Flags().StringVar(&lockFile, "lock", "", "Lockfile to compare against (default .aspex.lock)")
	cmd.Flags().StringVar(&markdownOut, "markdown", "", "Also write a Markdown report (PR comment) to this file, or - for stdout")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show informational changes too")
	return cmd
}

// ---------------------------------------------------------------------------
// explain <question>  (server-name form kept)
// ---------------------------------------------------------------------------

func printAnswer(w *os.File, a agentenv.Answer, noColor bool) {
	c := func(col, s string) string {
		if noColor {
			return s
		}
		return col + s + ansiReset
	}
	verdictColor := ansiGreen
	if a.Verdict == "YES" {
		verdictColor = ansiRed
	}
	sub := ""
	switch a.Verdict {
	case "YES":
		sub = "plausible path exists"
	case "NO COMPLETE PATH":
		sub = "no complete path found"
	}
	fmt.Fprintf(w, "\n  %s  %s\n", c(verdictColor+ansiBold, a.Verdict), c(ansiDim, sub))
	fmt.Fprintf(w, "  %s %s\n\n", c(ansiDim, "Understood as:"), a.Query.Interpretation)
	fmt.Fprintf(w, "  %s\n\n", a.Summary)
	if len(a.Path) > 0 {
		for i, hop := range a.Path {
			if i == 0 {
				fmt.Fprintf(w, "     %s\n", c(ansiBold, hop))
			} else {
				fmt.Fprintf(w, "       %s\n     %s\n", c(ansiDim, "↓"), c(ansiBold, hop))
			}
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  %s\n", c(ansiDim, "Required conditions"))
	for _, cond := range a.Conditions {
		mark := c(ansiGreen, "✓")
		if !cond.Met {
			mark = c(ansiRed, "✗")
		}
		fmt.Fprintf(w, "     %s %s\n", mark, cond.Text)
		if cond.Evidence != "" {
			fmt.Fprintf(w, "       %s\n", c(ansiDim, cond.Evidence))
		}
	}
	if len(a.Missing) > 0 {
		fmt.Fprintf(w, "\n  %s\n", c(ansiDim, "Missing capabilities"))
		for _, m := range a.Missing {
			fmt.Fprintf(w, "     %s %s\n", c(ansiDim, "✗"), m)
		}
	}
	if len(a.NotProven) > 0 {
		fmt.Fprintf(w, "\n  %s\n", c(ansiDim, "Not proven"))
		for _, n := range a.NotProven {
			fmt.Fprintf(w, "     %s %s\n", c(ansiDim, "✗"), n)
		}
	}
	fmt.Fprintf(w, "\n  %s %s\n\n", c(ansiDim, "Confidence:"), c(ansiBold, strings.ToUpper(a.Confidence)))
}

func runExplainQuestion(gf *globalFlags, question string) error {
	in := loadInputs(gf, gf.jsonOut)
	env := agentenv.Build(in.Servers, in.Options)
	c := func(col, s string) string {
		if gf.noColor {
			return s
		}
		return col + s + ansiReset
	}
	// Follow the data: forward or reverse flow questions.
	if dir, subject, ok := agentenv.ParseFlow(question); ok {
		var fa agentenv.FlowAnswer
		if dir == "forward" {
			fa = agentenv.Forward(env, subject, nil)
		} else {
			fa = agentenv.Reverse(env, subject, nil)
		}
		if gf.jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(struct {
				Version  string `json:"version"`
				Question string `json:"question"`
				agentenv.FlowAnswer
			}{version.Version, question, fa})
		}
		printFlow(os.Stdout, fa, c)
		return nil
	}
	a, ok := agentenv.Explain(env, question)
	if !ok {
		fmt.Fprintf(os.Stderr, "aspex could not map that question to a security query it can answer deterministically.\nSupported shapes:\n")
		for _, s := range agentenv.SupportedQuestions {
			fmt.Fprintf(os.Stderr, "  %s\n", s)
		}
		fmt.Fprintf(os.Stderr, "Or name a server: aspex-scan explain <server-name>\n")
		return errExitOne
	}
	if gf.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Version  string `json:"version"`
			Question string `json:"question"`
			agentenv.Answer
		}{version.Version, question, a})
	}
	printAnswer(os.Stdout, a, gf.noColor)
	// What breaks this path: concrete controls, each simulated.
	if a.Verdict == "YES" {
		printControls(os.Stdout, in, env, a, c)
	}
	return nil
}

// printControls derives path-breaking controls for the paths behind a YES and
// simulates each one so the user sees which single change removes the path.
func printControls(w *os.File, in agentenv.Inputs, env agentenv.Environment, a agentenv.Answer, c func(string, string) string) {
	var controls []agentenv.Control
	seen := map[string]bool{}
	for _, p := range env.AttackPaths {
		if !involves(p.Servers, a.Servers) {
			continue
		}
		for _, ctl := range agentenv.Evaluate(in, p, agentenv.ControlsFor(env, p, projectRootHint())) {
			if !seen[ctl.Text] {
				seen[ctl.Text] = true
				controls = append(controls, ctl)
			}
		}
	}
	if len(controls) == 0 {
		// The answer is a capability, not a composition (e.g. exec via a hook); still name the lever.
		for _, s := range a.Servers {
			if !seen[s] {
				seen[s] = true
				controls = append(controls, agentenv.Control{Text: "remove or sandbox " + s, Change: agentenv.HypotheticalChange{Kind: agentenv.RemoveServer, Server: s}})
			}
		}
	}
	if len(controls) == 0 {
		return
	}
	fmt.Fprintf(w, "  %s\n", c(ansiDim, "What breaks this path"))
	for _, ctl := range controls {
		mark := c(ansiGreen, "→")
		note := c(ansiDim, "  removes the path on its own")
		if !ctl.Breaks && ctl.Change.Kind != agentenv.RemoveServer {
			mark = c(ansiDim, "→")
			note = c(ansiDim, "  lowers severity; another leg of the path remains")
		} else if !ctl.Breaks {
			note = ""
		}
		fmt.Fprintf(w, "     %s %s%s\n", mark, report.SanitizeForTerminal(ctl.Text), note)
	}
	fmt.Fprintf(w, "     %s\n\n", c(ansiDim, "Try one: aspex simulate --"+string(controls[0].Change.Kind)+" "+simArg(controls[0].Change)))
}

func simArg(ch agentenv.HypotheticalChange) string {
	switch ch.Kind {
	case agentenv.RestrictFilesystem:
		return ch.Server + "=" + strings.Join(ch.Roots, ",")
	case agentenv.RemoveTool:
		return ch.Server + "." + ch.Tool
	case agentenv.RemoveHook:
		return ch.Hook
	case agentenv.RemoveSkill:
		return ch.Skill
	}
	return ch.Server
}

func involves(pathServers, answerServers []string) bool {
	if len(answerServers) == 0 {
		return false
	}
	set := map[string]bool{}
	for _, s := range pathServers {
		set[s] = true
	}
	for _, s := range answerServers {
		if !set[s] {
			return false
		}
	}
	return true
}

func printFlow(w *os.File, fa agentenv.FlowAnswer, c func(string, string) string) {
	sevColor := map[string]string{"high": ansiRed + ansiBold, "medium": ansiYellow, "low": ansiDim}
	stColor := map[string]string{agentenv.FlowObserved: ansiGreen, agentenv.FlowPotential: ansiDim, agentenv.FlowReachable: ansiCyan}
	fmt.Fprintf(w, "\n  %s  %s\n\n", c(ansiPurple+ansiBold, "◆"), c(ansiBold, "Data flow: "+fa.Subject))
	fmt.Fprintf(w, "  %s\n\n", fa.Summary)
	if fa.Direction == "forward" && len(fa.Sources) > 0 {
		fmt.Fprintf(w, "     %s\n", c(ansiBold, report.SanitizeForTerminal(fa.Subject)))
		readers := firstNSources(fa.Sources, 4)
		for i, s := range readers {
			branch := "├──"
			if i == len(readers)-1 {
				branch = "└──"
			}
			fmt.Fprintf(w, "       %s %s  %s\n", c(ansiDim, branch), c(ansiBold, report.SanitizeForTerminal(s.Reader)), c(stColor[s.Status], s.Status))
		}
		fmt.Fprintf(w, "       %s\n     %s\n", c(ansiDim, "↓ (any of the readers above)"), c(ansiBold, "agent context"))
		for i, sk := range fa.Sinks {
			branch := "├──"
			if i == len(fa.Sinks)-1 {
				branch = "└──"
			}
			fmt.Fprintf(w, "       %s %s  %s  %s\n", c(ansiDim, branch), c(ansiBold, report.SanitizeForTerminal(sk.Via)), c(ansiDim, "→ "+report.SanitizeForTerminal(sk.Destination)), c(stColor[sk.Status], sk.Status))
		}
		fmt.Fprintln(w)
	}
	if fa.Direction == "reverse" && len(fa.Sinks) > 0 {
		fmt.Fprintf(w, "  %s\n", c(ansiDim, "Potentially reachable by "+fa.Subject+":"))
		for _, s := range fa.Sources {
			fmt.Fprintf(w, "     %s  %s  %s\n", c(sevColor[s.Sensitivity], fmt.Sprintf("%-6s", strings.ToUpper(s.Sensitivity))), report.SanitizeForTerminal(s.Resource), c(ansiDim, "via "+s.Reader+"  "+s.Status))
		}
		fmt.Fprintf(w, "\n  %s\n", c(ansiDim, "Why"))
		fmt.Fprintf(w, "     %s\n       %s\n     %s\n", c(ansiBold, "reads above"), c(ansiDim, "↓"), c(ansiBold, "agent context"))
		for _, sk := range fa.Sinks {
			fmt.Fprintf(w, "       %s\n     %s  %s\n", c(ansiDim, "↓"), c(ansiBold, report.SanitizeForTerminal(sk.Via)), c(ansiDim, "→ "+report.SanitizeForTerminal(sk.Destination)))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  %s\n", c(ansiDim, "Evidence"))
	for _, e := range fa.Evidence {
		mark := c(ansiGreen, "✓")
		if !e.Met {
			mark = c(ansiRed, "✗")
		}
		fmt.Fprintf(w, "     %s %s", mark, e.Text)
		if e.Evidence != "" {
			fmt.Fprintf(w, "  %s", c(ansiDim, e.Evidence))
		}
		fmt.Fprintln(w)
	}
	if len(fa.NotProven) > 0 {
		fmt.Fprintf(w, "\n  %s\n", c(ansiDim, "Not proven"))
		for _, n := range fa.NotProven {
			fmt.Fprintf(w, "     %s %s\n", c(ansiDim, "✗"), n)
		}
	}
	fmt.Fprintf(w, "\n  %s\n\n", c(ansiDim, "REACHABLE = within a reader's scope · POTENTIAL = the capabilities allow it · OBSERVED = that server or tool was invoked in the trace window (not that this data moved)"))
}

func firstNSources(in []agentenv.FlowSource, n int) []agentenv.FlowSource {
	seen := map[string]bool{}
	var out []agentenv.FlowSource
	for _, s := range in {
		if !seen[s.Reader] {
			seen[s.Reader] = true
			out = append(out, s)
		}
		if len(out) == n {
			break
		}
	}
	return out
}

// runExplainFinding prints a finding definition and how it applies here.
func runExplainFinding(gf *globalFlags, id string) error {
	id = strings.ToUpper(id)
	c := func(col, s string) string {
		if gf.noColor {
			return s
		}
		return col + s + ansiReset
	}
	if strings.HasPrefix(id, "AP") {
		in := loadInputs(gf, gf.jsonOut)
		env := agentenv.Build(in.Servers, in.Options)
		fe, ok := agentenv.ExplainFinding(env, id, projectRootHint())
		if !ok {
			return fmt.Errorf("unknown attack path id %s (AP001-AP006)", id)
		}
		if fe.Present {
			for i := range fe.Instances {
				fe.Controls = agentenv.Evaluate(in, fe.Instances[i], fe.Controls)
			}
		}
		if gf.jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(struct {
				Version string `json:"version"`
				agentenv.FindingExplanation
			}{version.Version, fe})
		}
		d := fe.Definition
		fmt.Fprintf(os.Stdout, "\n  %s  %s  %s\n\n", c(ansiPurple+ansiBold, d.ID), c(ansiBold, d.Name), c(ansiDim, d.Kind))
		fmt.Fprintf(os.Stdout, "  %s\n     %s\n\n", c(ansiDim, "What it is"), report.SanitizeForTerminal(d.Composition))
		fmt.Fprintf(os.Stdout, "  %s\n     %s\n\n", c(ansiDim, "Why it matters"), d.Why)
		fmt.Fprintf(os.Stdout, "  %s\n     %s\n\n", c(ansiDim, "How severity is decided"), d.Severity)
		fmt.Fprintf(os.Stdout, "  %s\n", c(ansiDim, "Assumptions"))
		for _, a := range d.Assumptions {
			fmt.Fprintf(os.Stdout, "     %s %s\n", c(ansiDim, "•"), a)
		}
		fmt.Fprintf(os.Stdout, "\n  %s\n", c(ansiDim, "Never claimed"))
		for _, n := range d.NotClaimed {
			fmt.Fprintf(os.Stdout, "     %s %s\n", c(ansiDim, "✗"), n)
		}
		fmt.Fprintf(os.Stdout, "\n  %s\n", c(ansiDim, "False-positive notes"))
		for _, n := range d.FalsePos {
			fmt.Fprintf(os.Stdout, "     %s %s\n", c(ansiDim, "•"), n)
		}
		fmt.Fprintln(os.Stdout)
		if !fe.Present {
			fmt.Fprintf(os.Stdout, "  %s %s\n\n", c(ansiGreen, "✓"), "Not present in this environment: no server composition matches.")
			return nil
		}
		fmt.Fprintf(os.Stdout, "  %s  %s\n", c(ansiRed+ansiBold, "PRESENT"), c(ansiDim, fmt.Sprintf("%d instance(s) in this environment", len(fe.Instances))))
		for _, p := range fe.Instances {
			fmt.Fprintf(os.Stdout, "     %s  %s  %s\n", c(ansiBold, strings.ToUpper(p.Severity)), strings.Join(p.Servers, " + "), c(ansiDim, "confidence "+p.Confidence))
			for i, st := range p.Steps {
				pre := "       "
				if i > 0 {
					pre = "     ↓ "
				}
				fmt.Fprintf(os.Stdout, "%s%s\n", c(ansiDim, pre), report.SanitizeForTerminal(st))
			}
		}
		fmt.Fprintf(os.Stdout, "\n  %s\n", c(ansiDim, "Why Aspex believes it"))
		for _, e := range fe.Evidence {
			col := ansiDim
			switch e.Level {
			case "OBSERVED CONFIGURATION":
				col = ansiGreen
			case "INFERRED":
				col = ansiYellow
			case "NOT OBSERVED":
				col = ansiRed
			}
			fmt.Fprintf(os.Stdout, "     %s %s\n", c(col, fmt.Sprintf("%-22s", e.Level)), report.SanitizeForTerminal(e.Text))
		}
		fmt.Fprintf(os.Stdout, "\n  %s\n", c(ansiDim, "What breaks it"))
		for _, ctl := range fe.Controls {
			note := "removes the path on its own"
			if !ctl.Breaks {
				note = "lowers severity; another leg remains"
			}
			fmt.Fprintf(os.Stdout, "     %s %s  %s\n", c(ansiGreen, "→"), report.SanitizeForTerminal(ctl.Text), c(ansiDim, note))
		}
		fmt.Fprintf(os.Stdout, "\n  %s\n\n", c(ansiDim, "Accept it with a reason: add `- rule: "+d.ID+"` to .aspex.yaml. Docs: https://aspex.mintlify.site/reference/rules"))
		return nil
	}
	if strings.HasPrefix(id, "MCP") {
		return runExplainRule(gf, id)
	}
	if strings.HasPrefix(id, "HOOK") || strings.HasPrefix(id, "AT") {
		fmt.Fprintf(os.Stdout, "\n  %s is documented at https://aspex.mintlify.site/reference/rules\n\n", id)
		return nil
	}
	return fmt.Errorf("unknown finding id %q", id)
}

// runExplainRule explains a per-server rule: its advisory plus where it fires now.
func runExplainRule(gf *globalFlags, id string) error {
	c := func(col, s string) string {
		if gf.noColor {
			return s
		}
		return col + s + ansiReset
	}
	in := loadInputs(gf, true)
	type hit struct {
		Server  string
		Finding rules.Finding
	}
	var hits []hit
	for _, srv := range in.Servers {
		for _, f := range rules.EvalServer(srv) {
			if f.RuleID == id {
				hits = append(hits, hit{srv.Entry.Name, f})
			}
		}
	}
	adv, hasAdv := rules.AdvisoryFor(id)
	if gf.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Version  string      `json:"version"`
			ID       string      `json:"id"`
			Advisory interface{} `json:"advisory,omitempty"`
			Hits     []hit       `json:"instances"`
		}{version.Version, id, adv, hits})
	}
	fmt.Fprintf(os.Stdout, "\n  %s  %s\n\n", c(ansiPurple+ansiBold, id), c(ansiDim, "per-server rule (risky configuration or capability, not a composition)"))
	if hasAdv {
		fmt.Fprintf(os.Stdout, "  %s\n     %s\n\n  %s\n     %s\n\n  %s\n     %s\n\n", c(ansiDim, "Why"), adv.Why, c(ansiDim, "How it could be exploited"), adv.Exploit, c(ansiDim, "Impact"), adv.Impact)
	}
	if len(hits) == 0 {
		fmt.Fprintf(os.Stdout, "  %s Not firing in this environment.\n\n", c(ansiGreen, "✓"))
		return nil
	}
	fmt.Fprintf(os.Stdout, "  %s  %d instance(s)\n", c(ansiRed+ansiBold, "PRESENT"), len(hits))
	for _, h := range hits {
		fmt.Fprintf(os.Stdout, "     %s  %s  %s\n", c(ansiBold, h.Finding.Severity.String()), c(ansiCyan, h.Server), report.SanitizeForTerminal(h.Finding.Detail))
		for _, e := range h.Finding.Evidence {
			col := ansiGreen
			if e.Level != "OBSERVED" {
				col = ansiYellow
			}
			fmt.Fprintf(os.Stdout, "        %s %s\n", c(col, fmt.Sprintf("%-8s", e.Level)), report.SanitizeForTerminal(e.Text))
		}
		fmt.Fprintf(os.Stdout, "        %s %s\n", c(ansiDim, "fix:"), report.SanitizeForTerminal(h.Finding.Fix))
	}
	fmt.Fprintln(os.Stdout)
	return nil
}

// ---------------------------------------------------------------------------
// bom
// ---------------------------------------------------------------------------

func newBomCmd(gf *globalFlags) *cobra.Command {
	var out, format string
	cmd := &cobra.Command{
		Use:   "bom",
		Short: "Agent Security Bill of Materials: what constitutes this agent environment",
		Long: `A portable description of the agent environment: agents, MCP servers and
their tools, skills, hooks, persistent state, capabilities, reachable
sensitive resources, external destinations, attack paths, fingerprints.

  aspex-scan bom                       tree for humans
  aspex-scan bom --json                aspex-asbom/v1 JSON (no secret values)
  aspex-scan bom --format cyclonedx    CycloneDX 1.5 JSON: servers as components
                                       (purl, fingerprint hash), destinations as
                                       external references, attack paths as
                                       vulnerabilities; Aspex specifics as properties

The native JSON is the same schema as .aspex.lock's environment, wrapped with a
BOM header, and remains the authoritative form.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			env := loadEnvironment(gf, gf.jsonOut || out != "" || format != "")
			if format == "cyclonedx" {
				data, err := agentenv.CycloneDX(env, version.Version)
				if err != nil {
					return err
				}
				data = append(data, '\n')
				if out != "" {
					return os.WriteFile(out, data, 0o644)
				}
				os.Stdout.Write(data)
				return nil
			}
			if format != "" && format != "aspex" {
				return fmt.Errorf("--format must be aspex or cyclonedx")
			}
			if gf.jsonOut || out != "" {
				doc := struct {
					Schema      string               `json:"$schema"`
					Generator   string               `json:"generator"`
					Environment agentenv.Environment `json:"environment"`
				}{fmt.Sprintf("aspex-asbom/v%d", agentenv.SchemaVersion), "aspex " + version.Version, env}
				data, err := json.MarshalIndent(doc, "", "  ")
				if err != nil {
					return err
				}
				data = append(data, '\n')
				if out != "" {
					return os.WriteFile(out, data, 0o644)
				}
				os.Stdout.Write(data)
				return nil
			}
			c := func(col, s string) string {
				if gf.noColor {
					return s
				}
				return col + s + ansiReset
			}
			fmt.Fprintf(os.Stdout, "\n  %s  %s\n\n", c(ansiPurple+ansiBold, "◆"), c(ansiBold, "Agent Security BOM"))
			agentenv.PrintSummary(os.Stdout, env, gf.noColor)
			fmt.Fprintln(os.Stdout)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "Write JSON BOM to this file (e.g. agent.asbom.json)")
	cmd.Flags().StringVar(&format, "format", "", "JSON format: aspex (default) or cyclonedx")
	return cmd
}

// ---------------------------------------------------------------------------
// tighten
// ---------------------------------------------------------------------------

func newTightenCmd(gf *globalFlags) *cobra.Command {
	var since string
	var minCalls int
	cmd := &cobra.Command{
		Use:   "tighten",
		Short: "Recommend least-privilege configuration from configured vs observed use",
		Long: `Compare what each server is allowed to do (its tools and filesystem roots)
with what your agents actually did (aspex-trace logs) and recommend:

  - a tool allowlist per server: observed tools kept, unobserved tools listed
    as candidates for removal
  - narrower filesystem roots from the paths that were actually accessed,
    naming the sensitive directories never touched

Recommendations are based on observed usage in the window. An unobserved tool
is a candidate, not proven unnecessary; thin evidence is labelled weak. Aspex
never edits your configuration.`,
		Example: `  aspex-scan tighten
  aspex-scan tighten --since 30d
  aspex-scan tighten --json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			window, err := parseWindow(since)
			if err != nil {
				return err
			}
			in := loadInputs(gf, gf.jsonOut)
			env := agentenv.Build(in.Servers, in.Options)
			events, _, _ := logparse.CollectEvents(nil, time.Now().Add(-window))
			home, _ := os.UserHomeDir()
			r := tighten.Analyze(env, events, tighten.Options{Window: window, MinCalls: minCalls, Home: home, Inputs: &in})
			if gf.jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					Version string `json:"version"`
					Since   string `json:"since"`
					tighten.Report
				}{version.Version, since, r})
			}
			tighten.Print(os.Stdout, r, gf.noColor)
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "30d", "Activity window (e.g. 7d, 30d)")
	cmd.Flags().IntVar(&minCalls, "min-calls", 20, "Calls below which a server's tool evidence is marked weak")
	return cmd
}

// ---------------------------------------------------------------------------
// mcp (read-only MCP server exposing Aspex to agents)
// ---------------------------------------------------------------------------

func newMCPCmd(gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve Aspex to an AI agent as a read-only MCP server (stdio)",
		Long: `Expose Aspex's analysis to the agent itself over the Model Context Protocol
on stdin/stdout. The agent can then ask, before it edits .mcp.json or hooks:

  aspex_security_impact   what would this proposed config do to my attack surface?
  aspex_explain           can external content reach my credentials?
  aspex_scan              summarize servers, capabilities, blast radius
  aspex_get_attack_paths  list compositions with evidence
  aspex_get_capabilities  per-server capabilities and scope
  aspex_verify            drift against .aspex.lock
  aspex_simulate_change   counterfactual: remove/restrict something, see paths removed
  aspex_explain_path      a finding id explained with evidence and what breaks it
  aspex_data_flow         where could data from X go / what could reach Y

Every tool is read-only. Nothing here writes files, runs commands, or changes
Aspex configuration. Proposed configs are analyzed statically, never launched.

Add to Claude Code:  claude mcp add aspex -- aspex-scan mcp --no-exec
Add to .mcp.json:    {"aspex":{"command":"aspex-scan","args":["mcp","--no-exec"]}}`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			loader := func(ctx context.Context) agentenv.Environment { return loadEnvironment(gf, true) }
			s := aspexmcp.New(loader, version.Version, os.Stderr).WithInputs(func(ctx context.Context) agentenv.Inputs { return loadInputs(gf, true) })
			return s.Serve(context.Background(), os.Stdin, os.Stdout)
		},
	}
	return cmd
}

// ---------------------------------------------------------------------------
// explore (local session explorer, loopback only)
// ---------------------------------------------------------------------------

func newExploreCmd(gf *globalFlags) *cobra.Command {
	var since string
	var port int
	var noOpen, printOnly bool
	cmd := &cobra.Command{
		Use:   "explore",
		Short: "Open a local session explorer: timeline, provenance, capability graph, findings",
		Long: `Launch an ephemeral local web UI bound to 127.0.0.1 (never any other
interface) that shows what your agents did and what they could do:

  Timeline      every tool call, content ingestion and network call, per session
  Provenance    which ingested content preceded a suspicious call, with
                OBSERVED / INFERRED / NOT OBSERVED evidence
  Kill chains   multi-step patterns with labeled evidence
  Graph         external content -> agent -> servers -> sensitive resources,
                attack-path edges highlighted, exercised edges in green
  Findings      why Aspex believes each one, and what it cannot prove

Nothing leaves the machine; the page loads one JSON document from the local
process. Ctrl-C stops it.`,
		Example: `  aspex-scan explore
  aspex-scan explore --since 7d --port 7777
  aspex-scan explore --json > session.json     # the dataset, no server`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			window, err := parseWindow(since)
			if err != nil {
				return err
			}
			ds, err := buildExploreDataset(gf, window)
			if err != nil {
				return err
			}
			if gf.jsonOut || printOnly {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(ds)
			}
			ln, url, err := explore.Listen(port)
			if err != nil {
				return err
			}
			c := func(col, s string) string {
				if gf.noColor {
					return s
				}
				return col + s + ansiReset
			}
			fmt.Fprintf(os.Stderr, "\n  %s  aspex explore  %s\n  %s\n\n", c(ansiPurple+ansiBold, "◆"), c(ansiBold, url), c(ansiDim, "loopback only · nothing leaves this machine · Ctrl-C to stop"))
			if !noOpen {
				openBrowser(url)
			}
			srv := &http.Server{Handler: explore.Handler(ds), ReadHeaderTimeout: 5 * time.Second}
			return srv.Serve(ln)
		},
	}
	cmd.Flags().StringVar(&since, "since", "7d", "Activity window (e.g. 24h, 7d, 30d)")
	cmd.Flags().IntVar(&port, "port", 0, "Port on 127.0.0.1 (default: a free port)")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "Do not open a browser")
	cmd.Flags().BoolVar(&printOnly, "dataset", false, "Print the dataset as JSON instead of serving")
	return cmd
}

func buildExploreDataset(gf *globalFlags, window time.Duration) (explore.Dataset, error) {
	since := time.Now().Add(-window)
	events, _, _ := logparse.CollectEvents(nil, since)
	flagged := trace.AnalyzeEvents(events)
	chains := killchain.Analyze(events, flagged)
	prov := provenance.Analyze(events, flagged)
	env := loadEnvironment(gf, true)
	return explore.Build(explore.Inputs{Events: events, Flagged: flagged, Chains: chains, Prov: prov, Env: env, Window: window}), nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// ---------------------------------------------------------------------------
// simulate (counterfactual analysis; never modifies configuration)
// ---------------------------------------------------------------------------

func newSimulateCmd(gf *globalFlags) *cobra.Command {
	var removeServers, restrictFS, denyNet, removeTools, removeHooks, removeSkills []string
	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "What would happen to my security posture if I changed X? (nothing is modified)",
		Long: `Counterfactual analysis. The current environment is cloned in memory, the
hypothetical change is applied, capabilities and attack paths are recomputed
through the same pipeline as a real scan, and before is compared with after.
Your configuration is never touched.

  aspex-scan simulate --remove-server playwright
  aspex-scan simulate --restrict-filesystem ~/projects/acme          # every filesystem server
  aspex-scan simulate --restrict-filesystem filesystem=~/projects/acme
  aspex-scan simulate --deny-network '*'                            # or one server
  aspex-scan simulate --remove-tool desktop-commander.start_process
  aspex-scan simulate --remove-hook PostToolUse --remove-skill deploy

Combine flags to evaluate several changes at once. --json emits the versioned
aspex-simulate schema (before/after environments, capability deltas, attack
paths added/removed, blast radius change).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var changes []agentenv.HypotheticalChange
			add := func(kind agentenv.ChangeKind, vals []string) error {
				for _, v := range vals {
					ch, err := agentenv.ParseChange(kind, expandHome(v))
					if err != nil {
						return err
					}
					changes = append(changes, ch)
				}
				return nil
			}
			for _, pair := range []struct {
				k agentenv.ChangeKind
				v []string
			}{{agentenv.RemoveServer, removeServers}, {agentenv.RestrictFilesystem, restrictFS}, {agentenv.DenyNetwork, denyNet}, {agentenv.RemoveTool, removeTools}, {agentenv.RemoveHook, removeHooks}, {agentenv.RemoveSkill, removeSkills}} {
				if err := add(pair.k, pair.v); err != nil {
					return err
				}
			}
			if len(changes) == 0 {
				return fmt.Errorf("nothing to simulate; pass at least one --remove-server, --restrict-filesystem, --deny-network, --remove-tool, --remove-hook or --remove-skill")
			}
			in := loadInputs(gf, gf.jsonOut)
			sim := agentenv.Simulate(in, changes)
			if gf.jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(struct {
					Schema  string `json:"$schema"`
					Version string `json:"version"`
					agentenv.Simulation
				}{fmt.Sprintf("aspex-simulate/v%d", agentenv.SimSchemaVersion), version.Version, sim})
			}
			printSimulation(os.Stdout, sim, gf.noColor)
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&removeServers, "remove-server", nil, "Remove a configured server (repeatable)")
	cmd.Flags().StringArrayVar(&restrictFS, "restrict-filesystem", nil, "Restrict filesystem roots: ROOT[,ROOT] for every filesystem server, or SERVER=ROOT[,ROOT]")
	cmd.Flags().StringArrayVar(&denyNet, "deny-network", nil, "Remove network egress from SERVER, or '*' for all")
	cmd.Flags().StringArrayVar(&removeTools, "remove-tool", nil, "Remove one tool: SERVER.TOOL")
	cmd.Flags().StringArrayVar(&removeHooks, "remove-hook", nil, "Remove hooks for an event (e.g. PostToolUse)")
	cmd.Flags().StringArrayVar(&removeSkills, "remove-skill", nil, "Remove a skill by name")
	return cmd
}

func expandHome(v string) string {
	if strings.HasPrefix(v, "~/") || v == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(v, "~"))
		}
	}
	if i := strings.Index(v, "=~/"); i > 0 {
		if home, err := os.UserHomeDir(); err == nil {
			return v[:i+1] + filepath.Join(home, v[i+3:])
		}
	}
	return v
}

func printSimulation(w *os.File, sim agentenv.Simulation, noColor bool) {
	c := func(col, s string) string {
		if noColor {
			return s
		}
		return col + s + ansiReset
	}
	fmt.Fprintf(w, "\n  %s  %s\n", c(ansiPurple+ansiBold, "◆"), c(ansiBold, "Security impact simulation"))
	for _, ch := range sim.Changes {
		fmt.Fprintf(w, "     %s %s\n", c(ansiDim, "•"), report.SanitizeForTerminal(ch.Describe()))
	}
	for _, u := range sim.Unmatched {
		fmt.Fprintf(w, "     %s %s\n", c(ansiYellow, "!"), "no match in this environment: "+report.SanitizeForTerminal(u))
	}
	fmt.Fprintln(w)
	bc := func(l string) string {
		switch l {
		case "HIGH":
			return c(ansiRed+ansiBold, l)
		case "MEDIUM":
			return c(ansiYellow+ansiBold, l)
		}
		return c(ansiGreen, l)
	}
	fmt.Fprintf(w, "  %-8s blast radius %s   %d attack path(s)\n", c(ansiDim, "BEFORE"), bc(sim.Before.BlastRadius.Level), len(sim.Before.AttackPaths))
	fmt.Fprintf(w, "  %-8s blast radius %s   %d attack path(s)\n\n", c(ansiDim, "AFTER"), bc(sim.After.BlastRadius.Level), len(sim.After.AttackPaths))
	if len(sim.Drift.PathsRemoved) > 0 {
		fmt.Fprintf(w, "  %s\n", c(ansiGreen+ansiBold, "REMOVED ATTACK PATHS"))
		for _, p := range sim.Drift.PathsRemoved {
			fmt.Fprintf(w, "     %s %s  %s\n", c(ansiGreen, "✓"), report.SanitizeForTerminal(p.Name), c(ansiDim, strings.ToUpper(p.Severity)+" · "+strings.Join(p.Servers, " + ")))
		}
		fmt.Fprintln(w)
	}
	if len(sim.Drift.PathsAdded) > 0 {
		fmt.Fprintf(w, "  %s\n", c(ansiRed+ansiBold, "NEW ATTACK PATHS"))
		for _, p := range sim.Drift.PathsAdded {
			fmt.Fprintf(w, "     %s %s  %s\n", c(ansiRed, "+"), report.SanitizeForTerminal(p.Name), c(ansiDim, strings.ToUpper(p.Severity)+" · "+strings.Join(p.Servers, " + ")))
		}
		fmt.Fprintln(w)
	}
	// Severity changes for paths present on both sides.
	before := map[string]string{}
	for _, p := range sim.Before.AttackPaths {
		before[p.ID+"|"+strings.Join(p.Servers, ",")] = p.Severity
	}
	var lowered []string
	for _, p := range sim.After.AttackPaths {
		if b, ok := before[p.ID+"|"+strings.Join(p.Servers, ",")]; ok && b != p.Severity {
			lowered = append(lowered, fmt.Sprintf("%s (%s): %s → %s", p.Name, strings.Join(p.Servers, " + "), strings.ToUpper(b), strings.ToUpper(p.Severity)))
		}
	}
	if len(lowered) > 0 {
		fmt.Fprintf(w, "  %s\n", c(ansiYellow+ansiBold, "SEVERITY CHANGED"))
		for _, l := range lowered {
			fmt.Fprintf(w, "     %s %s\n", c(ansiYellow, "~"), report.SanitizeForTerminal(l))
		}
		fmt.Fprintln(w)
	}
	if len(sim.After.AttackPaths) > 0 {
		fmt.Fprintf(w, "  %s\n", c(ansiBold, "REMAINING"))
		for _, p := range sim.After.AttackPaths {
			fmt.Fprintf(w, "     %s  %s  %s\n", c(ansiDim, fmt.Sprintf("%-8s", strings.ToUpper(p.Severity))), report.SanitizeForTerminal(p.Name), c(ansiDim, strings.Join(p.Servers, " + ")))
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "  %s No attack paths remain.\n\n", c(ansiGreen, "✓"))
	}
	if len(sim.Capabilities) > 0 {
		fmt.Fprintf(w, "  %s\n", c(ansiBold, "Capability changes"))
		for _, d := range sim.Capabilities {
			for _, r := range d.Removed {
				fmt.Fprintf(w, "     %s %s  %s\n", c(ansiGreen, "-"), d.Server, r)
			}
			for _, a := range d.Added {
				fmt.Fprintf(w, "     %s %s  %s\n", c(ansiRed, "+"), d.Server, a)
			}
			if len(d.RootsAfter) > 0 {
				fmt.Fprintf(w, "     %s %s  roots %s → %s\n", c(ansiYellow, "~"), d.Server, report.SanitizeForTerminal(strings.Join(d.RootsBefore, ", ")), report.SanitizeForTerminal(strings.Join(d.RootsAfter, ", ")))
			}
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  %s\n\n", c(ansiDim, "No configuration was modified."))
}
