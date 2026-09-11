package agentenv_test

import (
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/inspect"
)

var fsReadOnly = server("filesystem", []string{"-y", "@modelcontextprotocol/server-filesystem@0.6.2", home}, tool("read_file", "Read a file.", "path"))

func TestForwardFlowListsEverySink(t *testing.T) {
	env := agentenv.Build([]*inspect.Server{fsHome, fetch, github, shell}, opts)
	a := agentenv.Forward(env, "~/.aws/credentials", nil)
	if len(a.Sources) == 0 {
		t.Fatal("home-scoped filesystem reads ~/.aws")
	}
	kinds := map[string]bool{}
	for _, s := range a.Sinks {
		kinds[s.Kind] = true
		if s.Status != agentenv.FlowPotential {
			t.Errorf("without trace evidence every sink is POTENTIAL, got %s", s.Status)
		}
	}
	for _, k := range []string{"network", "channel", "exec", "persistence"} {
		if !kinds[k] {
			t.Errorf("expected a %s sink: %+v", k, a.Sinks)
		}
	}
	if len(a.NotProven) == 0 {
		t.Error("forward flow must state what is not proven")
	}
}

func TestForwardFlowNoReaderNoSink(t *testing.T) {
	env := agentenv.Build([]*inspect.Server{fetch}, opts)
	a := agentenv.Forward(env, "~/.ssh", nil)
	if len(a.Sources) != 0 || !strings.Contains(a.Summary, "nothing to follow") {
		t.Errorf("fetch cannot read ~/.ssh: %+v", a)
	}
	env = agentenv.Build([]*inspect.Server{fsReadOnly}, opts)
	a = agentenv.Forward(env, "ssh keys", nil)
	if len(a.Sources) == 0 || len(a.Sinks) != 0 || !strings.Contains(a.Summary, "stays on this machine") {
		t.Errorf("read with no sink stays local: %+v", a)
	}
}

func TestReverseFlowRanksSensitiveSources(t *testing.T) {
	slack := server("slack", []string{"-y", "@modelcontextprotocol/server-slack"}, tool("slack_post_message", "Post a message.", "channel", "text"))
	env := agentenv.Build([]*inspect.Server{fsHome, slack}, opts)
	a := agentenv.Reverse(env, "Slack", nil)
	if len(a.Sinks) == 0 || !strings.Contains(a.Sinks[0].Via, "slack") {
		t.Fatalf("slack should be a sink: %+v", a.Sinks)
	}
	if len(a.Sources) == 0 || a.Sources[0].Sensitivity != "high" {
		t.Errorf("sources should be ranked high first: %+v", a.Sources)
	}
	a = agentenv.Reverse(env, "Jira", nil)
	if len(a.Sinks) != 0 {
		t.Error("no server reaches Jira")
	}
}

func TestObservedEvidenceMarksHops(t *testing.T) {
	env := agentenv.Build([]*inspect.Server{fsHome, fetch}, opts)
	a := agentenv.Forward(env, "~/.aws", agentenv.Observed{"fetch": true})
	var seen bool
	for _, s := range a.Sinks {
		if strings.HasPrefix(s.Via, "fetch") && s.Status == agentenv.FlowObserved {
			seen = true
		}
	}
	if !seen {
		t.Error("a sink whose server was invoked in the trace window is OBSERVED (the tool ran), never 'data moved'")
	}
}

func TestParseFlowQuestions(t *testing.T) {
	cases := map[string][2]string{
		"Where could data from ~/.aws/credentials go?": {"forward", "~/.aws/credentials"},
		"where can files from ~/.ssh end up":           {"forward", "~/.ssh"},
		"What sensitive data could reach Slack?":       {"reverse", "Slack"},
		"Which files could be sent to github?":         {"reverse", "github"},
		"Can this agent leak my credentials?":          {"", ""},
	}
	for q, want := range cases {
		d, s, ok := agentenv.ParseFlow(q)
		if want[0] == "" {
			if ok {
				t.Errorf("%q should not parse as a flow question", q)
			}
			continue
		}
		if !ok || d != want[0] || !strings.EqualFold(s, want[1]) {
			t.Errorf("%q -> %s %q (ok=%v), want %v", q, d, s, ok, want)
		}
	}
}

func TestExplainFindingDefinitionAndControls(t *testing.T) {
	env := agentenv.Build([]*inspect.Server{fsHome, fetch}, opts)
	fe, ok := agentenv.ExplainFinding(env, "ap001", home+"/projects/acme")
	if !ok || !fe.Present || len(fe.Instances) == 0 {
		t.Fatalf("AP001 should be present: %+v", fe)
	}
	levels := map[string]int{}
	for _, e := range fe.Evidence {
		levels[e.Level]++
	}
	if levels["OBSERVED CONFIGURATION"] == 0 || levels["INFERRED"] == 0 || levels["NOT OBSERVED"] == 0 {
		t.Errorf("evidence must carry all three levels: %v", levels)
	}
	if len(fe.Controls) == 0 {
		t.Error("what breaks it must not be empty")
	}
	fe, _ = agentenv.ExplainFinding(agentenv.Build([]*inspect.Server{github}, opts), "AP001", "")
	if fe.Present {
		t.Error("github alone has no AP001")
	}
	if _, ok := agentenv.ExplainFinding(env, "AP999", ""); ok {
		t.Error("unknown id")
	}
}
