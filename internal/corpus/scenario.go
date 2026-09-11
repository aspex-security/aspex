// Package corpus runs the Aspex Agent Security Corpus: environment-level
// scenarios that state, independently of any tool, what a given agent setup
// can do (truth), and what Aspex is expected to report about it (expect). A
// scenario passes when every expected capability, attack path, blast radius
// and explain verdict is produced and nothing in must_not_report appears.
//
// The truth section is tool-agnostic so other scanners can test themselves
// against the same scenarios; the expect section is Aspex's contract.
package corpus

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/hooks"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/mcpclient"
)

// Scenario is one corpus case.
type Scenario struct {
	Name        string `yaml:"name"`
	Category    string `yaml:"category"` // prompt-injection | tool-poisoning | mcp-rug-pull | credential-access | cross-mcp | memory-poisoning | hook-persistence | destructive-actions | false-positive | benign
	Description string `yaml:"description"`

	Environment struct {
		Home    string       `yaml:"home"`
		Servers []ScenServer `yaml:"servers"`
		Hooks   []struct {
			Event   string `yaml:"event"`
			Command string `yaml:"command"`
		} `yaml:"hooks"`
	} `yaml:"environment"`

	// Truth is tool-agnostic: what a human analyst would say about this setup.
	Truth struct {
		Capabilities map[string][]string `yaml:"capabilities"` // server -> generic capability names
		AttackPaths  []string            `yaml:"attack_paths"` // generic names: credential-exfiltration, persistent-compromise, remote-control, memory-poisoning, untrusted-to-exec, data-exfiltration
		Severity     string              `yaml:"severity"`     // worst path severity: critical|high|medium|low|none
	} `yaml:"truth"`

	// Expect is Aspex's contract for this scenario.
	Expect struct {
		Capabilities map[string][]string `yaml:"capabilities"` // server -> aspex capability names
		AttackPaths  []string            `yaml:"attack_paths"` // AP IDs
		BlastRadius  string              `yaml:"blast_radius"`
		Explain      []struct {
			Question string `yaml:"question"`
			Verdict  string `yaml:"verdict"`
		} `yaml:"explain"`
	} `yaml:"expect"`

	MustNotReport struct {
		AttackPaths  []string            `yaml:"attack_paths"`
		Capabilities map[string][]string `yaml:"capabilities"`
		BlastAbove   string              `yaml:"blast_radius_above"` // e.g. LOW: reporting MEDIUM or HIGH is a false positive
	} `yaml:"must_not_report"`

	Path string `yaml:"-"`
}

// ScenServer is a server in a scenario. Tools omitted means static inference.
type ScenServer struct {
	Name    string            `yaml:"name"`
	Client  string            `yaml:"client"`
	Command string            `yaml:"command"`
	Args    []string          `yaml:"args"`
	URL     string            `yaml:"url"`
	Env     map[string]string `yaml:"env"`
	Tools   []ScenTool        `yaml:"tools"`
}

// ScenTool is a tool with an optional description and parameter list.
type ScenTool struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Params      []string `yaml:"params"`
}

// Load reads every *.yaml scenario under dir.
func Load(dir string) ([]Scenario, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []Scenario
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var sc Scenario
		if err := yaml.Unmarshal(data, &sc); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if sc.Name == "" {
			sc.Name = strings.TrimSuffix(filepath.Base(p), ".yaml")
		}
		sc.Path = p
		out = append(out, sc)
	}
	return out, nil
}

// Build turns a scenario into an Environment without launching anything.
func Build(ctx context.Context, sc Scenario) agentenv.Environment {
	home := sc.Environment.Home
	if home == "" {
		home = "/Users/dev"
	}
	var servers []*inspect.Server
	for _, s := range sc.Environment.Servers {
		client := s.Client
		if client == "" {
			client = "claude-code"
		}
		entry := discover.ServerEntry{Name: s.Name, Client: client, Command: s.Command, Args: s.Args, URL: s.URL, ConfigPath: filepath.Join(home, ".claude.json")}
		for k, v := range s.Env {
			entry.EnvKeys = append(entry.EnvKeys, k)
			if !strings.HasPrefix(v, "$") && v != "" {
				entry.PlaintextEnvKeys = append(entry.PlaintextEnvKeys, k)
			}
		}
		srv := &inspect.Server{Entry: entry, StaticOnly: len(s.Tools) == 0}
		for _, t := range s.Tools {
			props := map[string]interface{}{}
			for _, p := range t.Params {
				props[p] = map[string]string{"type": "string"}
			}
			schema := fmt.Sprintf(`{"type":"object","properties":%s}`, mustJSON(props))
			desc := t.Description
			if desc == "" {
				desc = strings.ReplaceAll(t.Name, "_", " ")
			}
			srv.Tools = append(srv.Tools, mcpclient.Tool{Name: t.Name, Description: desc, InputSchema: []byte(schema)})
		}
		servers = append(servers, srv)
	}
	local := &agentenv.LocalState{}
	for _, h := range sc.Environment.Hooks {
		local.Hooks = append(local.Hooks, hooks.Hook{Client: "claude-code", Event: h.Event, Command: h.Command, Source: filepath.Join(home, ".claude", "settings.json"), Scope: "user"})
	}
	return agentenv.Build(servers, agentenv.Options{Home: home, Cwd: filepath.Join(home, "projects", "x"), Local: local})
}

// Result of running one scenario.
type Result struct {
	Scenario       string   `json:"scenario"`
	Category       string   `json:"category"`
	Pass           bool     `json:"pass"`
	TruePositives  []string `json:"true_positives"`
	FalseNegatives []string `json:"false_negatives"`
	FalsePositives []string `json:"false_positives"`
}

// Run evaluates one scenario.
func Run(ctx context.Context, sc Scenario) Result {
	env := Build(ctx, sc)
	r := Result{Scenario: sc.Name, Category: sc.Category, Pass: true}
	fail := func(kind string, list *[]string, item string) {
		*list = append(*list, item)
		r.Pass = false
		_ = kind
	}
	// Capabilities expected.
	for server, caps := range sc.Expect.Capabilities {
		s := findServer(env, server)
		for _, c := range caps {
			if s != nil && has(s.Capabilities, c) {
				r.TruePositives = append(r.TruePositives, "cap "+server+":"+c)
			} else {
				fail("fn", &r.FalseNegatives, "cap "+server+":"+c)
			}
		}
	}
	// Attack paths expected.
	got := map[string]bool{}
	for _, p := range env.AttackPaths {
		got[p.ID] = true
	}
	for _, id := range sc.Expect.AttackPaths {
		if got[id] {
			r.TruePositives = append(r.TruePositives, "path "+id)
		} else {
			fail("fn", &r.FalseNegatives, "path "+id)
		}
	}
	if sc.Expect.BlastRadius != "" {
		if env.BlastRadius.Level == sc.Expect.BlastRadius {
			r.TruePositives = append(r.TruePositives, "blast "+sc.Expect.BlastRadius)
		} else {
			fail("fn", &r.FalseNegatives, fmt.Sprintf("blast want %s got %s", sc.Expect.BlastRadius, env.BlastRadius.Level))
		}
	}
	for _, q := range sc.Expect.Explain {
		a, ok := agentenv.Explain(env, q.Question)
		switch {
		case !ok:
			fail("fn", &r.FalseNegatives, "explain not understood: "+q.Question)
		case a.Verdict == q.Verdict:
			r.TruePositives = append(r.TruePositives, "explain "+q.Verdict+": "+q.Question)
		default:
			fail("fn", &r.FalseNegatives, fmt.Sprintf("explain want %s got %s: %s", q.Verdict, a.Verdict, q.Question))
		}
	}
	// Must not report.
	for _, id := range sc.MustNotReport.AttackPaths {
		if got[id] {
			fail("fp", &r.FalsePositives, "path "+id)
		}
	}
	for server, caps := range sc.MustNotReport.Capabilities {
		if s := findServer(env, server); s != nil {
			for _, c := range caps {
				if has(s.Capabilities, c) {
					fail("fp", &r.FalsePositives, "cap "+server+":"+c)
				}
			}
		}
	}
	if sc.MustNotReport.BlastAbove != "" && blastRank(env.BlastRadius.Level) > blastRank(sc.MustNotReport.BlastAbove) {
		fail("fp", &r.FalsePositives, fmt.Sprintf("blast %s exceeds %s", env.BlastRadius.Level, sc.MustNotReport.BlastAbove))
	}
	return r
}

// Summary aggregates results.
type Summary struct {
	Scenarios      int      `json:"scenarios"`
	Passed         int      `json:"passed"`
	TruePositives  int      `json:"true_positives"`
	FalseNegatives int      `json:"false_negatives"`
	FalsePositives int      `json:"false_positives"`
	Results        []Result `json:"results"`
}

// RunAll runs every scenario in dir.
func RunAll(ctx context.Context, dir string) (Summary, error) {
	scs, err := Load(dir)
	if err != nil {
		return Summary{}, err
	}
	var sum Summary
	for _, sc := range scs {
		r := Run(ctx, sc)
		sum.Scenarios++
		if r.Pass {
			sum.Passed++
		}
		sum.TruePositives += len(r.TruePositives)
		sum.FalseNegatives += len(r.FalseNegatives)
		sum.FalsePositives += len(r.FalsePositives)
		sum.Results = append(sum.Results, r)
	}
	return sum, nil
}

func findServer(env agentenv.Environment, name string) *agentenv.Server {
	for i := range env.Servers {
		if env.Servers[i].Name == name {
			return &env.Servers[i]
		}
	}
	return nil
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func blastRank(s string) int {
	switch strings.ToUpper(s) {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

func mustJSON(v interface{}) string {
	b, err := jsonMarshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
