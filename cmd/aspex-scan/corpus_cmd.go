package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aspex-security/aspex/internal/corpus"
	"github.com/aspex-security/aspex/internal/repro"
	"github.com/aspex-security/aspex/internal/version"
)

func newCorpusCmd(gf *globalFlags) *cobra.Command {
	var dir string
	root := &cobra.Command{
		Use:   "corpus",
		Short: "Run the Aspex Agent Security Corpus (environment scenarios)",
		Long: `The corpus is a set of agent environment scenarios with tool-agnostic truth
and Aspex's expected output. Running it reports true positives, false
negatives and false positives per scenario. See testdata/corpus/README.md.`,
	}
	test := &cobra.Command{
		Use:           "test",
		Short:         "Evaluate every scenario and summarize TP / FN / FP",
		Example:       "  aspex-scan corpus test\n  aspex-scan corpus test --dir ./my-scenarios --json",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				dir = findScenarioDir()
			}
			sum, err := corpus.RunAll(context.Background(), dir)
			if err != nil {
				return err
			}
			if sum.Scenarios == 0 {
				return fmt.Errorf("no scenarios found in %s (use --dir)", dir)
			}
			if gf.jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(struct {
					Version string `json:"version"`
					Dir     string `json:"dir"`
					corpus.Summary
				}{version.Version, dir, sum}); err != nil {
					return err
				}
			} else {
				printCorpus(sum, dir, gf.noColor)
			}
			if sum.Passed != sum.Scenarios {
				return errExitOne
			}
			return nil
		},
	}
	test.Flags().StringVar(&dir, "dir", "", "Scenario directory (default: testdata/corpus/scenarios in the current repo)")
	root.AddCommand(test)

	var name, category, outDir string
	imp := &cobra.Command{
		Use:   "import <bundle-dir>",
		Short: "Turn a reproduction bundle into a corpus scenario (tool-agnostic truth + Aspex expectations)",
		Long: `Reads a bundle written by aspex-trace repro create and writes a scenario YAML:
the environment's servers become the scenario environment, the attack paths
Aspex reported become expectations, and must_not_report defaults to the paths
that were not reported. The truth section is left for you to fill in generic
terms; a scenario states what a human analyst would conclude, not just what
Aspex printed. Real investigation -> sanitized reproduction -> regression case.`,
		Example:       "  aspex-scan corpus import ./repro --name ssh-key-exfil-via-browser --category cross-mcp",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := repro.Load(args[0])
			if err != nil {
				return err
			}
			if name == "" {
				name = filepath.Base(strings.TrimSuffix(args[0], "/"))
			}
			if outDir == "" {
				outDir = findScenarioDir()
			}
			y := corpus.FromEnvironment(r.Env, name, category)
			p := filepath.Join(outDir, name+".yaml")
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("%s exists; choose --name", p)
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(p, y, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "\n  ◆  Scenario written: %s\n\n  Fill in truth: (generic capability and path names) and review expect:, then run aspex-scan corpus test.\n\n", p)
			return nil
		},
	}
	imp.Flags().StringVar(&name, "name", "", "Scenario name (file stem)")
	imp.Flags().StringVar(&category, "category", "cross-mcp", "Category: prompt-injection | tool-poisoning | mcp-rug-pull | credential-access | cross-mcp | memory-poisoning | hook-persistence | destructive-actions | false-positive | benign")
	imp.Flags().StringVar(&outDir, "out", "", "Scenario directory (default testdata/corpus/scenarios)")
	root.AddCommand(imp)
	return root
}

func findScenarioDir() string {
	for _, c := range []string{"testdata/corpus/scenarios", "corpus/scenarios", "scenarios"} {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return filepath.Join("testdata", "corpus", "scenarios")
}

func printCorpus(sum corpus.Summary, dir string, noColor bool) {
	c := func(col, s string) string {
		if noColor {
			return s
		}
		return col + s + ansiReset
	}
	fmt.Fprintf(os.Stdout, "\n  %s  %s  %s\n\n", c(ansiPurple+ansiBold, "◆"), c(ansiBold, "Agent Security Corpus"), c(ansiDim, dir))
	for _, r := range sum.Results {
		mark := c(ansiGreen, "PASS")
		if !r.Pass {
			mark = c(ansiRed+ansiBold, "FAIL")
		}
		fmt.Fprintf(os.Stdout, "  %s  %-44s %s\n", mark, r.Scenario, c(ansiDim, fmt.Sprintf("%-20s %d checks", r.Category, len(r.TruePositives)+len(r.FalseNegatives))))
		for _, fn := range r.FalseNegatives {
			fmt.Fprintf(os.Stdout, "        %s %s\n", c(ansiRed, "missed:"), fn)
		}
		for _, fp := range r.FalsePositives {
			fmt.Fprintf(os.Stdout, "        %s %s\n", c(ansiYellow, "false positive:"), fp)
		}
	}
	fmt.Fprintf(os.Stdout, "\n  %s %d/%d scenarios passed · %d true positives · %d false negatives · %d false positives\n\n",
		c(ansiDim, "─"), sum.Passed, sum.Scenarios, sum.TruePositives, sum.FalseNegatives, sum.FalsePositives)
}
