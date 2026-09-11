package aspexmcp_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/aspexmcp"
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/mcpclient"
)

const home = "/Users/dev"

func srv(name string, args []string, tools ...string) *inspect.Server {
	var ts []mcpclient.Tool
	for _, t := range tools {
		ts = append(ts, mcpclient.Tool{Name: t, Description: t, InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`)})
	}
	return &inspect.Server{Entry: discover.ServerEntry{Name: name, Client: "claude-code", Command: "npx", Args: args, ConfigPath: filepath.Join(home, ".claude.json")}, Tools: ts}
}

func newServer(servers ...*inspect.Server) *aspexmcp.Server {
	load := func(ctx context.Context) agentenv.Environment {
		return agentenv.Build(servers, agentenv.Options{Home: home, SkipLocalState: true})
	}
	return aspexmcp.New(load, "test", nil)
}

func call(t *testing.T, s *aspexmcp.Server, tool string, args map[string]string) (text string, isError bool) {
	t.Helper()
	req, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]interface{}{"name": tool, "arguments": args}})
	var resp struct {
		Result struct {
			Content []struct{ Text string }
			IsError bool
		}
		Error *struct{ Message string }
	}
	if err := json.Unmarshal(s.Handle(context.Background(), req), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("rpc error: %s", resp.Error.Message)
	}
	return resp.Result.Content[0].Text, resp.Result.IsError
}

func TestInitializeAndToolListAreReadOnly(t *testing.T) {
	s := newServer()
	out := s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if !strings.Contains(string(out), `"protocolVersion"`) || !strings.Contains(string(out), "read-only") {
		t.Errorf("initialize: %s", out)
	}
	out = s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	var resp struct {
		Result struct {
			Tools []struct{ Name, Description string }
		}
	}
	json.Unmarshal(out, &resp)
	if len(resp.Result.Tools) != len(aspexmcp.Tools) {
		t.Fatalf("tools/list returned %d tools", len(resp.Result.Tools))
	}
	for _, tl := range resp.Result.Tools {
		for _, bad := range []string{"write", "exec", "run_", "shell", "delete", "fix", "set_", "update"} {
			if strings.Contains(tl.Name, bad) {
				t.Errorf("tool %s looks like a write or exec action; the interface must be read-only", tl.Name)
			}
		}
	}
}

func TestExplainThroughMCP(t *testing.T) {
	s := newServer(
		srv("filesystem", []string{"-y", "@modelcontextprotocol/server-filesystem@0.6.2", home}, "read_file"),
		srv("fetch", []string{"-y", "mcp-server-fetch"}, "fetch"),
	)
	text, isErr := call(t, s, "aspex_explain", map[string]string{"question": "Can external content reach my AWS credentials?"})
	if isErr || !strings.Contains(text, `"verdict": "YES"`) {
		t.Errorf("expected YES, got err=%v %s", isErr, text)
	}
	text, _ = call(t, s, "aspex_explain", map[string]string{"question": "tell me a joke"})
	if !strings.Contains(text, `"understood": false`) {
		t.Errorf("unmappable question must not be guessed: %s", text)
	}
	_, isErr = call(t, s, "aspex_explain", nil)
	if !isErr {
		t.Error("missing question should be a tool error")
	}
}

func TestSecurityImpactBeforeEditingConfig(t *testing.T) {
	// Current: only a browser (open egress). Proposal: add a home-scoped filesystem.
	s := newServer(srv("browser", []string{"-y", "@playwright/mcp@0.0.30"}, "browser_navigate"))
	text, isErr := call(t, s, "aspex_security_impact", map[string]string{
		"mcp_json": `{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@0.6.2","` + home + `"]}}}`,
	})
	if isErr {
		t.Fatalf("error: %s", text)
	}
	var res struct {
		Verdict          string
		BlastBefore      string                `json:"blast_radius_before"`
		BlastAfter       string                `json:"blast_radius_after"`
		AttackPathsAdded []struct{ ID string } `json:"attack_paths_added"`
	}
	json.Unmarshal([]byte(text), &res)
	if !strings.Contains(res.Verdict, "CRITICAL") || len(res.AttackPathsAdded) == 0 {
		t.Errorf("home fs + existing browser must introduce a critical path: %+v", res)
	}
	if res.BlastAfter != "HIGH" {
		t.Errorf("blast radius after should be HIGH, got %s", res.BlastAfter)
	}
	// A harmless proposal: memory server only.
	text, _ = call(t, s, "aspex_security_impact", map[string]string{
		"mcp_json": `{"mcpServers":{"memory":{"command":"npx","args":["-y","@modelcontextprotocol/server-memory@0.6.2"]}}}`,
	})
	json.Unmarshal([]byte(text), &res)
	// Browser ingress + a memory server is the memory-poisoning composition
	// (AP004, MEDIUM). It must be reported, and it must not be inflated.
	if strings.Contains(res.Verdict, "CRITICAL") || strings.Contains(res.Verdict, "HIGH") {
		t.Errorf("memory + browser is at most a MEDIUM path: %s", res.Verdict)
	}
	if len(res.AttackPathsAdded) != 1 || res.AttackPathsAdded[0].ID != "AP004" {
		t.Errorf("expected exactly AP004 (memory poisoning), got %+v", res.AttackPathsAdded)
	}
	_, isErr = call(t, s, "aspex_security_impact", map[string]string{"mcp_json": "not json"})
	if !isErr {
		t.Error("invalid JSON should be a tool error, not a crash")
	}
}

func TestVerifyThroughMCPRefusesNonLockPaths(t *testing.T) {
	s := newServer(srv("fetch", []string{"-y", "mcp-server-fetch"}, "fetch"))
	dir := t.TempDir()
	env := agentenv.Build([]*inspect.Server{srv("fetch", []string{"-y", "mcp-server-fetch"}, "fetch")}, agentenv.Options{Home: home, SkipLocalState: true})
	lock := filepath.Join(dir, "a.lock")
	agentenv.WriteLock(lock, env, "t")
	text, isErr := call(t, s, "aspex_verify", map[string]string{"lockfile": lock})
	if isErr || !strings.Contains(text, `"drift": false`) {
		t.Errorf("same environment -> no drift: %v %s", isErr, text)
	}
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("x"), 0o644)
	if _, isErr := call(t, s, "aspex_verify", map[string]string{"lockfile": filepath.Join(dir, "secret.txt")}); !isErr {
		t.Error("the verify tool must only read lockfiles, not arbitrary files")
	}
}

func TestUnknownToolAndMethod(t *testing.T) {
	s := newServer()
	if _, isErr := call(t, s, "aspex_delete_everything", nil); !isErr {
		t.Error("unknown tool must error")
	}
	out := s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":3,"method":"resources/list"}`))
	if !strings.Contains(string(out), "method not found") {
		t.Errorf("unsupported method: %s", out)
	}
}
