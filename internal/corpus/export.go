package corpus

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aspex-security/aspex/internal/agentenv"
)

// FromEnvironment renders a scenario skeleton from an environment: servers
// with their command lines (env values are never present in the model),
// Aspex's reported paths as expectations, unreported paths as
// must_not_report, and a truth section for the author to fill.
func FromEnvironment(env agentenv.Environment, name, category string) []byte {
	// Anonymize: the real home directory becomes the scenario home so a
	// contributed scenario carries no personal path.
	home, _ := os.UserHomeDir()
	anon := func(v string) string {
		if home != "" && home != "/" {
			return strings.ReplaceAll(v, home, "/Users/dev")
		}
		return v
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "name: %s\ncategory: %s\ndescription: >\n  TODO: why this scenario exists, in two sentences.\n\n", name, category)
	fmt.Fprintf(&b, "environment:\n  home: /Users/dev\n  servers:\n")
	for _, s := range env.Servers {
		fmt.Fprintf(&b, "    - name: %s\n", s.Name)
		if s.Command != "" {
			fmt.Fprintf(&b, "      command: %s\n", anon(s.Command))
		}
		if len(s.Args) > 0 {
			var q []string
			for _, a := range s.Args {
				q = append(q, fmt.Sprintf("%q", anon(a)))
			}
			fmt.Fprintf(&b, "      args: [%s]\n", strings.Join(q, ", "))
		}
		if s.URL != "" {
			fmt.Fprintf(&b, "      url: %s\n", s.URL)
		}
		if len(s.Tools) > 0 {
			fmt.Fprintf(&b, "      tools:\n")
			for _, t := range s.Tools {
				fmt.Fprintf(&b, "        - {name: %s, description: %q}\n", t.Name, t.Description)
			}
		}
	}
	if len(env.Hooks) > 0 {
		fmt.Fprintf(&b, "  hooks:\n")
		for _, h := range env.Hooks {
			fmt.Fprintf(&b, "    - {event: %s, command: %q}\n", h.Event, anon(h.Command))
		}
	}
	fmt.Fprintf(&b, "\ntruth:\n  # Tool-agnostic. Fill in what a human analyst would conclude.\n  capabilities: {}\n  attack_paths: []\n  severity: TODO\n\nexpect:\n  capabilities:\n")
	for _, s := range env.Servers {
		if len(s.Capabilities) > 0 {
			fmt.Fprintf(&b, "    %s: [%s]\n", s.Name, strings.Join(s.Capabilities, ", "))
		}
	}
	seen := map[string]bool{}
	var ids []string
	for _, p := range env.AttackPaths {
		if !seen[p.ID] {
			seen[p.ID] = true
			ids = append(ids, p.ID)
		}
	}
	sort.Strings(ids)
	fmt.Fprintf(&b, "  attack_paths: [%s]\n  blast_radius: %s\n", strings.Join(ids, ", "), env.BlastRadius.Level)
	var not []string
	for _, id := range []string{"AP001", "AP002", "AP003", "AP004", "AP005", "AP006"} {
		if !seen[id] {
			not = append(not, id)
		}
	}
	fmt.Fprintf(&b, "\nmust_not_report:\n  attack_paths: [%s]\n", strings.Join(not, ", "))
	return b.Bytes()
}
