package main

// Environment commands: lock, verify, diff. All three consume one model
// (internal/agentenv) so a change reads the same whether it was detected
// against a lockfile, between two git revisions, or in a PR comment.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/registry"
	"github.com/aspex-security/aspex/internal/version"
)

// loadEnvironment discovers and inspects every configured server on this
// machine and assembles the environment, including local hooks, skills and
// instruction files. Honors --no-exec, --clients, -j.
func loadEnvironment(gf *globalFlags, quiet bool) agentenv.Environment {
	entries, discoveryErrs := discover.DiscoverAll(gf.clients)
	if !quiet {
		for _, e := range discoveryErrs {
			fmt.Fprintf(os.Stderr, "  warning: %v\n", e)
		}
	}
	ctx := context.Background()
	inspected := inspect.InspectAll(ctx, entries, inspect.Options{NoExec: gf.noExec, Concurrency: gf.concurrency}, nil)
	cwd, _ := os.Getwd()
	return agentenv.Build(inspected, agentenv.Options{Cwd: cwd})
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
