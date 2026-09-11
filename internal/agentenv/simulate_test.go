package agentenv_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/inspect"
)

func inputs(servers ...*inspect.Server) agentenv.Inputs {
	return agentenv.Inputs{Servers: servers, Options: opts}
}

func hasPath(env agentenv.Environment, id string) bool {
	for _, p := range env.AttackPaths {
		if p.ID == id {
			return true
		}
	}
	return false
}

func TestSimulateRestrictFilesystemRemovesExfilPath(t *testing.T) {
	in := inputs(fsHome, fetch)
	sim := agentenv.Simulate(in, []agentenv.HypotheticalChange{{Kind: agentenv.RestrictFilesystem, Server: "filesystem", Roots: []string{home + "/projects/acme"}}})
	if !hasPath(sim.Before, "AP001") || sim.Before.BlastRadius.Level != "HIGH" {
		t.Fatalf("before should have the critical path: %+v", sim.Before.AttackPaths)
	}
	var after *struct{ sev string }
	for _, p := range sim.After.AttackPaths {
		if p.ID == "AP001" {
			after = &struct{ sev string }{p.Severity}
		}
	}
	// Project scope + open egress is still a path, but HIGH not CRITICAL; the
	// credential resources vanish and blast radius must not be reported worse.
	if after != nil && after.sev == "critical" {
		t.Error("restricting to a project directory must lower AP001 from critical")
	}
	if len(sim.Drift.Changes) == 0 || sim.Capabilities == nil {
		t.Error("simulation should report changes")
	}
	found := false
	for _, d := range sim.Capabilities {
		if d.Server == "filesystem" && len(d.RootsAfter) == 1 && strings.HasSuffix(d.RootsAfter[0], "acme") {
			found = true
		}
	}
	if !found {
		t.Errorf("capability delta should show the new root: %+v", sim.Capabilities)
	}
}

func TestSimulateRemoveServerAndDenyNetwork(t *testing.T) {
	in := inputs(fsHome, fetch, github)
	sim := agentenv.Simulate(in, []agentenv.HypotheticalChange{{Kind: agentenv.RemoveServer, Server: "fetch"}})
	if hasPath(sim.After, "AP001") {
		// github is still a channel: AP001 via github remains, but as high not critical
		for _, p := range sim.After.AttackPaths {
			if p.ID == "AP001" && p.Severity == "critical" {
				t.Error("removing the open-egress server must remove the critical exfil path")
			}
		}
	}
	if len(sim.Drift.PathsRemoved) == 0 {
		t.Error("removing fetch must remove at least one path")
	}
	sim = agentenv.Simulate(in, []agentenv.HypotheticalChange{{Kind: agentenv.DenyNetwork, Server: "*"}})
	for _, p := range sim.After.AttackPaths {
		if p.ID == "AP001" || p.ID == "AP005" {
			t.Errorf("denying all egress must remove exfiltration paths, still have %s via %v", p.ID, p.Servers)
		}
	}
	// Egress factors must be absent; blast radius may stay HIGH for another
	// reason (home-scoped write reaches agent config while ingress exists).
	for _, r := range sim.After.BlastRadius.Why {
		if r.Present && strings.Contains(r.Text, "egress") {
			t.Errorf("egress factor should be gone: %+v", r)
		}
	}
}

func TestSimulateRemoveToolAndUnmatched(t *testing.T) {
	in := inputs(fsHome, fetch)
	sim := agentenv.Simulate(in, []agentenv.HypotheticalChange{{Kind: agentenv.RemoveTool, Server: "fetch", Tool: "fetch"}})
	if hasPath(sim.After, "AP001") {
		t.Error("removing the only network tool removes the path")
	}
	sim = agentenv.Simulate(in, []agentenv.HypotheticalChange{{Kind: agentenv.RemoveServer, Server: "nope"}, {Kind: agentenv.RemoveTool, Server: "fetch", Tool: "missing"}})
	if len(sim.Unmatched) != 2 {
		t.Errorf("changes that match nothing must be reported, got %v", sim.Unmatched)
	}
	if !sim.Drift.Empty() {
		t.Error("unmatched changes must not alter the environment")
	}
}

func TestSimulateNeverMutatesInputs(t *testing.T) {
	in := inputs(fsHome, fetch)
	argsBefore := append([]string(nil), fsHome.Entry.Args...)
	toolsBefore := len(fetch.Tools)
	before := agentenv.Build(in.Servers, in.Options)
	agentenv.Simulate(in, []agentenv.HypotheticalChange{
		{Kind: agentenv.RestrictFilesystem, Server: "filesystem", Roots: []string{"/tmp/x"}},
		{Kind: agentenv.RemoveTool, Server: "fetch", Tool: "fetch"},
		{Kind: agentenv.DenyNetwork, Server: "*"},
	})
	if strings.Join(fsHome.Entry.Args, " ") != strings.Join(argsBefore, " ") || len(fetch.Tools) != toolsBefore {
		t.Fatal("simulation mutated the input servers")
	}
	if in.Options.AttackPath.RootsOverride != nil || in.Options.AttackPath.DenyNetwork != nil {
		t.Fatal("simulation mutated the caller's options")
	}
	again := agentenv.Build(in.Servers, in.Options)
	if d := agentenv.Compare(before, again); !d.Empty() {
		t.Fatal("environment differs after a simulation: state leaked")
	}
}

func TestSimulateAddServerIntroducesPath(t *testing.T) {
	in := inputs(fsHome)
	sim := agentenv.Simulate(in, []agentenv.HypotheticalChange{{Kind: agentenv.AddServer, Added: fetch}})
	if len(sim.Drift.PathsAdded) == 0 || sim.Drift.PathsAdded[0].ID != "AP001" {
		t.Errorf("adding open egress next to a home read introduces AP001: %+v", sim.Drift.PathsAdded)
	}
	if sim.Drift.BlastBefore.Level == sim.Drift.BlastAfter.Level {
		t.Error("blast radius should rise")
	}
}

func TestControlsBreakPaths(t *testing.T) {
	in := inputs(fsHome, fetch)
	env := agentenv.Build(in.Servers, in.Options)
	var ap1 = env.AttackPaths[0]
	for _, p := range env.AttackPaths {
		if p.ID == "AP001" {
			ap1 = p
		}
	}
	controls := agentenv.Evaluate(in, ap1, agentenv.ControlsFor(env, ap1, home+"/projects/acme"))
	if len(controls) < 2 {
		t.Fatalf("expected restrict + deny controls, got %+v", controls)
	}
	kinds := map[agentenv.ChangeKind]bool{}
	for _, c := range controls {
		kinds[c.Change.Kind] = true
		if strings.Contains(c.Text, "least privilege") {
			t.Error("controls must be concrete")
		}
	}
	if !kinds[agentenv.RestrictFilesystem] || !kinds[agentenv.DenyNetwork] {
		t.Errorf("AP001 controls should include restrict filesystem and deny network: %+v", controls)
	}
	for _, c := range controls {
		if c.Change.Kind == agentenv.DenyNetwork && !c.Breaks {
			t.Error("denying the only egress must break AP001")
		}
	}
}

func TestSimulationJSONIsVersioned(t *testing.T) {
	sim := agentenv.Simulate(inputs(fsHome), nil)
	b, _ := json.Marshal(sim)
	if !strings.Contains(string(b), `"schema_version":1`) {
		t.Error("simulation JSON must carry schema_version")
	}
}
