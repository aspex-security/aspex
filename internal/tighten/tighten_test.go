package tighten_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/mcpclient"
	"github.com/aspex-security/aspex/internal/tighten"
)

const home = "/Users/dev"

func tool(name string) mcpclient.Tool {
	s, _ := json.Marshal(map[string]interface{}{"type": "object", "properties": map[string]interface{}{"path": map[string]string{"type": "string"}}})
	return mcpclient.Tool{Name: name, Description: name, InputSchema: s}
}

func call(server, tool string, args map[string]string, at time.Time) logparse.Event {
	return logparse.Event{Client: "claude-code", Server: server, Tool: tool, Event: logparse.EventToolsCall, Args: args, Timestamp: at}
}

func env(t *testing.T, tools ...string) agentenv.Environment {
	var ts []mcpclient.Tool
	for _, n := range tools {
		ts = append(ts, tool(n))
	}
	fs := &inspect.Server{Entry: discover.ServerEntry{Name: "filesystem", Client: "claude-code", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@0.6.2", home}}, Tools: ts}
	gh := &inspect.Server{Entry: discover.ServerEntry{Name: "github", Client: "claude-code", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-github@2025.4.8"}},
		Tools: []mcpclient.Tool{tool("search_repositories"), tool("create_issue"), tool("create_pull_request"), tool("merge_pull_request"), tool("delete_branch")}}
	return agentenv.Build([]*inspect.Server{fs, gh}, agentenv.Options{Home: home, SkipLocalState: true})
}

func TestUnusedToolsBecomeCandidatesOnlyWithStrongEvidence(t *testing.T) {
	e := env(t, "read_file", "write_file")
	base := time.Now()
	var events []logparse.Event
	for i := 0; i < 30; i++ {
		events = append(events, call("github", "search_repositories", map[string]string{"query": "x"}, base.Add(time.Duration(i)*time.Minute)))
	}
	events = append(events, call("github", "create_issue", map[string]string{"title": "t"}, base))
	r := tighten.Analyze(e, events, tighten.Options{Window: 7 * 24 * time.Hour, Home: home})
	var gh tighten.ServerRec
	for _, s := range r.Servers {
		if s.Server == "github" {
			gh = s
		}
	}
	if gh.Evidence != "strong" || len(gh.Observed) != 2 || len(gh.Unobserved) != 3 {
		t.Fatalf("github: %+v", gh)
	}
	for _, u := range gh.Unobserved {
		if u == "search_repositories" || u == "create_issue" {
			t.Error("observed tools must be retained, never listed for removal")
		}
	}
	// Few calls: weak evidence, note says review only.
	r = tighten.Analyze(e, events[:3], tighten.Options{Window: time.Hour, Home: home})
	for _, s := range r.Servers {
		if s.Server == "github" && (s.Evidence != "weak" || !strings.Contains(s.Note, "hint")) {
			t.Errorf("3 calls is weak evidence: %+v", s)
		}
	}
}

func TestFilesystemScopeRecommendationFromObservedPaths(t *testing.T) {
	e := env(t, "read_file", "write_file")
	base := time.Now()
	var events []logparse.Event
	for i := 0; i < 40; i++ {
		events = append(events, call("filesystem", "read_file", map[string]string{"path": home + "/projects/acme/src/file" + string(rune('a'+i%5)) + ".go"}, base))
	}
	events = append(events, call("filesystem", "read_file", map[string]string{"path": home + "/.gitconfig"}, base))
	// A path inside file *content* must not count as accessed.
	events = append(events, call("filesystem", "write_file", map[string]string{"path": home + "/projects/acme/README.md", "content": "see /Users/dev/.ssh/id_rsa"}, base))
	r := tighten.Analyze(e, events, tighten.Options{Window: 30 * 24 * time.Hour, Home: home})
	var fs tighten.ServerRec
	for _, s := range r.Servers {
		if s.Server == "filesystem" {
			fs = s
		}
	}
	if len(fs.Recommended) != 2 || fs.Recommended[0] != "~/.gitconfig" || fs.Recommended[1] != "~/projects/acme" {
		t.Errorf("recommended roots: %v", fs.Recommended)
	}
	joined := strings.Join(fs.NeverObserved, " ")
	if !strings.Contains(joined, "~/.ssh") || !strings.Contains(joined, "~/.aws") {
		t.Errorf("never-observed sensitive dirs should be listed: %v", fs.NeverObserved)
	}
	if !strings.HasPrefix(fs.Reduction, "SIGNIFICANT") {
		t.Errorf("home -> 2 dirs is SIGNIFICANT, got %q", fs.Reduction)
	}
	if strings.Contains(fs.Reduction, "%") {
		t.Error("no percentage without a justified model")
	}
}

func TestNoActivityIsACaveatNotAVerdict(t *testing.T) {
	e := env(t, "read_file")
	r := tighten.Analyze(e, nil, tighten.Options{Window: 24 * time.Hour, Home: home})
	if len(r.NoActivity) != 2 {
		t.Fatalf("both servers unobserved: %v", r.NoActivity)
	}
	for _, s := range r.Servers {
		if s.Evidence != "none" || !strings.Contains(s.Note, "not treat as proof") {
			t.Errorf("unobserved server must carry the caveat: %+v", s)
		}
		if s.Reduction != "" {
			t.Error("no scope recommendation without observed paths")
		}
	}
}

func TestAlreadyScopedServerGetsNoRootRecommendation(t *testing.T) {
	fs := &inspect.Server{Entry: discover.ServerEntry{Name: "filesystem", Client: "claude-code", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@0.6.2", home + "/projects/acme"}}, Tools: []mcpclient.Tool{tool("read_file")}}
	e := agentenv.Build([]*inspect.Server{fs}, agentenv.Options{Home: home, SkipLocalState: true})
	var events []logparse.Event
	for i := 0; i < 25; i++ {
		events = append(events, call("filesystem", "read_file", map[string]string{"path": home + "/projects/acme/x.go"}, time.Now()))
	}
	r := tighten.Analyze(e, events, tighten.Options{Window: time.Hour, Home: home})
	if len(r.Servers[0].Recommended) != 0 {
		t.Errorf("project-scoped root needs no narrowing: %v", r.Servers[0].Recommended)
	}
}
