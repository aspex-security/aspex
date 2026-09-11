package explore_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/explore"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/killchain"
	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/mcpclient"
	"github.com/aspex-security/aspex/internal/provenance"
	"github.com/aspex-security/aspex/internal/trace"
)

func call(session, server, tool string, args map[string]string, at time.Time) logparse.Event {
	return logparse.Event{Client: "claude-code", Session: session, Server: server, Tool: tool, Event: logparse.EventToolsCall, Args: args, Timestamp: at}
}

func dataset(t *testing.T) explore.Dataset {
	base := time.Date(2026, 9, 11, 14, 23, 0, 0, time.UTC)
	events := []logparse.Event{
		call("s1", "fetch", "fetch", map[string]string{"url": "https://attacker.example/README.md"}, base),
		call("s1", "filesystem", "read_file", map[string]string{"path": "/Users/x/.aws/credentials"}, base.Add(12*time.Second)),
		call("s1", "github", "create_issue", map[string]string{"title": "notes", "body": "very long body text"}, base.Add(30*time.Second)),
		call("s2", "filesystem", "read_file", map[string]string{"path": "/Users/x/projects/a/main.go"}, base.Add(3*time.Hour)),
	}
	flagged := trace.AnalyzeEvents(events)
	fs := &inspect.Server{Entry: discover.ServerEntry{Name: "filesystem", Client: "claude-code", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/Users/x"}},
		Tools: []mcpclient.Tool{{Name: "read_file", Description: "Read.", InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`)}}}
	fetch := &inspect.Server{Entry: discover.ServerEntry{Name: "fetch", Client: "claude-code", Command: "uvx", Args: []string{"mcp-server-fetch"}},
		Tools: []mcpclient.Tool{{Name: "fetch", Description: "Fetch.", InputSchema: json.RawMessage(`{"type":"object","properties":{"url":{"type":"string"}}}`)}}}
	env := agentenv.Build([]*inspect.Server{fs, fetch}, agentenv.Options{Home: "/Users/x", SkipLocalState: true})
	return explore.Build(explore.Inputs{
		Events: events, Flagged: flagged, Chains: killchain.Analyze(events, flagged), Prov: provenance.Analyze(events, flagged), Env: env, Window: 7 * 24 * time.Hour,
	})
}

func TestTimelineKindsSessionsAndDetail(t *testing.T) {
	ds := dataset(t)
	if len(ds.Timeline) != 4 || ds.Summary.Events != 4 {
		t.Fatalf("timeline: %d", len(ds.Timeline))
	}
	kinds := map[string]string{}
	for _, e := range ds.Timeline {
		kinds[e.Tool] = e.Kind
	}
	if kinds["fetch"] != "NETWORK" || kinds["read_file"] != "CONTENT" || kinds["create_issue"] != "NETWORK" {
		t.Errorf("kinds: %v", kinds)
	}
	if ds.Timeline[1].Detail != "/Users/x/.aws/credentials" || ds.Timeline[1].Severity == "" {
		t.Errorf("credential read should show its path and a severity: %+v", ds.Timeline[1])
	}
	if strings.Contains(ds.Timeline[2].Detail, "very long body") {
		t.Error("content-bearing arguments must not be surfaced as the detail")
	}
	if len(ds.Sessions) != 2 || ds.Sessions[0].ID != "claude-code/s2" { // newest first
		t.Errorf("sessions: %+v", ds.Sessions)
	}
	if ds.Sessions[1].Flagged == 0 || len(ds.Sessions[1].Servers) != 3 {
		t.Errorf("session s1 should have flagged events and 3 servers: %+v", ds.Sessions[1])
	}
}

func TestProvenanceEvidenceKeepsObservedAndInferredApart(t *testing.T) {
	ds := dataset(t)
	if len(ds.Provenance) == 0 {
		t.Fatal("fetch -> credential read 12s later should yield a provenance link")
	}
	p := ds.Provenance[0]
	if p.Source.Tool != "fetch" || p.Target.Tool != "read_file" || p.Confidence != "high" {
		t.Errorf("link: %+v", p)
	}
	levels := map[string]int{}
	for _, e := range p.Evidence {
		levels[e.Level]++
	}
	if levels["OBSERVED"] < 2 || levels["INFERRED"] != 1 || levels["NOT OBSERVED"] != 1 {
		t.Errorf("evidence levels: %v", levels)
	}
	for _, e := range p.Evidence {
		if e.Level == "INFERRED" && !strings.Contains(e.Text, "may have") {
			t.Errorf("inferred text must hedge: %s", e.Text)
		}
	}
}

func TestFindingDetailAnswersWhy(t *testing.T) {
	ds := dataset(t)
	var cred *explore.Finding
	for i := range ds.Findings {
		if ds.Findings[i].RuleID == "AT001" {
			cred = &ds.Findings[i]
		}
	}
	if cred == nil {
		t.Fatal("expected AT001 on the credential read")
	}
	if cred.Fix == "" || len(cred.Evidence) < 3 {
		t.Errorf("finding needs remediation and evidence: %+v", cred)
	}
	if cred.Evidence[len(cred.Evidence)-1].Level != "NOT OBSERVED" {
		t.Error("the last evidence line must say what Aspex cannot show")
	}
}

func TestGraphSerializationIsSmallAndMarksObservedEdges(t *testing.T) {
	ds := dataset(t)
	g := ds.Graph
	if len(g.Nodes) > 30 {
		t.Errorf("graph should stay small: %d nodes", len(g.Nodes))
	}
	var agentToFS, agentToFetch *explore.GEdge
	for i := range g.Edges {
		e := &g.Edges[i]
		if e.From == "agent" && e.To == "srv:filesystem" {
			agentToFS = e
		}
		if e.From == "agent" && e.To == "srv:fetch" {
			agentToFetch = e
		}
	}
	if agentToFS == nil || !agentToFS.Observed || agentToFS.Severity != "critical" {
		t.Errorf("agent->filesystem should be observed and on the critical path: %+v", agentToFS)
	}
	if agentToFetch == nil || !agentToFetch.Observed {
		t.Errorf("agent->fetch was exercised: %+v", agentToFetch)
	}
	hasRes := false
	for _, n := range g.Nodes {
		if n.Kind == "resource" && strings.Contains(n.Label, ".aws") {
			hasRes = true
		}
	}
	if !hasRes {
		t.Error("~/.aws should be a resource node")
	}
	if _, err := json.Marshal(ds); err != nil {
		t.Fatal(err)
	}
}

func TestServerIsLoopbackOnlyAndRefusesForeignHosts(t *testing.T) {
	ln, url, err := explore.Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Errorf("must bind loopback, got %s", url)
	}
	h := explore.Handler(dataset(t))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/dataset", nil)
	req.Host = "127.0.0.1:1234"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"timeline"`) {
		t.Errorf("dataset endpoint: %d %s", rec.Code, rec.Body.String()[:80])
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/dataset", nil)
	req.Host = "evil.example"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("foreign Host header must be refused, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/", nil)
	req.Host = "localhost:1"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "aspex explore") || rec.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("UI should be served with a CSP: %d", rec.Code)
	}
}
