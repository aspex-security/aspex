package agentenv_test

import (
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/inspect"
)

func ask(t *testing.T, env agentenv.Environment, q string) agentenv.Answer {
	t.Helper()
	a, ok := agentenv.Explain(env, q)
	if !ok {
		t.Fatalf("question not understood: %q", q)
	}
	return a
}

func TestExplainCompleteExfiltrationPath(t *testing.T) {
	env := agentenv.Build([]*inspect.Server{fsHome, fetch}, opts)
	a := ask(t, env, "Can a malicious README steal my AWS credentials?")
	if a.Verdict != "YES" {
		t.Fatalf("home read + open egress is a YES, got %s: %s", a.Verdict, a.Summary)
	}
	if a.Query.Verb != agentenv.VerbExfil || a.Query.Target != agentenv.NodeCredentials || a.Query.Source != agentenv.NodeUntrustedContent {
		t.Errorf("query misparsed: %+v", a.Query)
	}
	if len(a.Path) < 4 || !strings.Contains(strings.Join(a.Path, " "), "filesystem.read_file") || !strings.Contains(strings.Join(a.Path, " "), "fetch.fetch") {
		t.Errorf("path should name both tools: %v", a.Path)
	}
	for _, c := range a.Conditions {
		if !c.Met {
			t.Errorf("all conditions should be met on a YES: %+v", c)
		}
	}
	if len(a.NotProven) == 0 || !strings.Contains(a.NotProven[0], "no runtime evidence") {
		t.Error("a YES must say what is not proven")
	}
	if a.Confidence != "high" {
		t.Errorf("live tools + sensitive scope -> high, got %s", a.Confidence)
	}
}

func TestExplainNoPathWhenOnlyOneHalfExists(t *testing.T) {
	env := agentenv.Build([]*inspect.Server{fsHome}, opts) // read, no egress
	a := ask(t, env, "Can this agent exfiltrate SSH keys?")
	if a.Verdict != "NO COMPLETE PATH" {
		t.Fatalf("no egress means no complete path, got %s", a.Verdict)
	}
	var unmet int
	for _, c := range a.Conditions {
		if !c.Met {
			unmet++
		}
	}
	if unmet != 1 || len(a.Missing) == 0 {
		t.Errorf("exactly the egress condition should be unmet and listed as missing: %+v / %v", a.Conditions, a.Missing)
	}
	// The other way round: egress but nothing to read.
	env = agentenv.Build([]*inspect.Server{fetch}, opts)
	a = ask(t, env, "Can external content reach my AWS credentials?")
	if a.Verdict != "NO COMPLETE PATH" {
		t.Errorf("fetch alone cannot reach credentials: %s", a.Summary)
	}
}

func TestExplainProjectScopeLowersButChannelStillLeaks(t *testing.T) {
	env := agentenv.Build([]*inspect.Server{fsProject, github}, opts)
	a := ask(t, env, "Can the agent leak my SSH keys?")
	if a.Verdict != "NO COMPLETE PATH" {
		t.Errorf("project-scoped filesystem cannot read ~/.ssh: %s / %s", a.Verdict, a.Summary)
	}
	a = ask(t, env, "Can external content exfiltrate source files from the repo?")
	if a.Verdict != "YES" || a.Confidence == "high" {
		t.Errorf("project files via GitHub channel is YES at lowered confidence, got %s %s", a.Verdict, a.Confidence)
	}
}

func TestExplainDestructiveDatabaseQuery(t *testing.T) {
	ro := server("postgres", []string{"-y", "@modelcontextprotocol/server-postgres@0.6.2", "postgresql://ro@db/prod"}, tool("query", "Run a read-only SQL query.", "sql"))
	env := agentenv.Build([]*inspect.Server{ro}, opts)
	a := ask(t, env, "Can this agent delete production data?")
	if a.Verdict != "NO COMPLETE PATH" {
		t.Fatalf("read-only postgres: %s / %s", a.Verdict, a.Summary)
	}
	if len(a.Missing) == 0 || a.Missing[0] != "UPDATE" {
		t.Errorf("missing capabilities should be listed: %v", a.Missing)
	}
	// Adding a shell changes the honest answer: a local db client can be driven.
	env = agentenv.Build([]*inspect.Server{ro, shell}, opts)
	a = ask(t, env, "Can this agent delete production data?")
	if !strings.Contains(a.Summary, "command execution") {
		t.Errorf("shell presence should be noted: %s", a.Summary)
	}
}

func TestExplainExecuteAndPersist(t *testing.T) {
	env := agentenv.Build([]*inspect.Server{github}, opts)
	a := ask(t, env, "Can a malicious README run commands on my machine?")
	if a.Verdict != "NO COMPLETE PATH" {
		t.Errorf("github alone has no exec: %s", a.Summary)
	}
	env = agentenv.Build([]*inspect.Server{github, shell}, opts)
	if a = ask(t, env, "Can a malicious README run commands on my machine?"); a.Verdict != "YES" {
		t.Errorf("shell server -> YES: %s", a.Summary)
	}
	env = agentenv.Build([]*inspect.Server{fsHome, fetch}, opts)
	a = ask(t, env, "Can external content change my agent's instructions or hooks?")
	if a.Verdict != "YES" || a.Query.Verb != agentenv.VerbPersist {
		t.Errorf("home-writable fs + fetch ingress -> persistence YES, got %s (%s)", a.Verdict, a.Query.Verb)
	}
	env = agentenv.Build([]*inspect.Server{fsProject}, opts)
	a = ask(t, env, "Can external content rewrite my CLAUDE.md?")
	// project scope reaches the project's own CLAUDE.md
	if a.Verdict != "YES" {
		t.Errorf("project-scoped write reaches project CLAUDE.md: %s", a.Summary)
	}
}

func TestExplainUnknownQuestionIsRejectedNotGuessed(t *testing.T) {
	env := agentenv.Build([]*inspect.Server{fsHome}, opts)
	if _, ok := agentenv.Explain(env, "what is the meaning of life"); ok {
		t.Error("an unmappable question must not produce an answer")
	}
}

func TestExplainAnswersComeFromGraphState(t *testing.T) {
	// Same question, two environments, opposite answers: proof the verdict is
	// computed, not templated.
	yes := agentenv.Build([]*inspect.Server{fsHome, fetch}, opts)
	no := agentenv.Build([]*inspect.Server{server("memory", []string{"-y", "@modelcontextprotocol/server-memory"}, tool("store", "Store.", "k"))}, opts)
	q := "Can this agent leak my credentials?"
	if ask(t, yes, q).Verdict != "YES" || ask(t, no, q).Verdict != "NO COMPLETE PATH" {
		t.Error("verdict must follow the environment")
	}
	// Static inference reports medium confidence.
	static := agentenv.Build([]*inspect.Server{
		{Entry: fsHome.Entry, StaticOnly: true}, {Entry: fetch.Entry, StaticOnly: true},
	}, opts)
	if a := ask(t, static, q); a.Verdict != "YES" || a.Confidence == "high" {
		t.Errorf("static YES must not claim high confidence: %s %s", a.Verdict, a.Confidence)
	}
}
