package redteam

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A probed server can be induced to write files (payloads used as paths).
// callToolStdio must run it from the given scratch directory so nothing lands
// in the user's working directory.
func TestProbedServerRunsInScratchDir(t *testing.T) {
	work := t.TempDir()
	cwd, _ := os.Getwd()

	os.Setenv("ASPEX_FAKE_MCP", "1")
	defer os.Unsetenv("ASPEX_FAKE_MCP")

	out, err := callToolStdio(t.Context(), os.Args[0], []string{"-test.run=TestHelperProcess"}, "write_file",
		map[string]interface{}{"path": "pwned.txt"}, work)
	if err != nil {
		t.Fatalf("callToolStdio: %v", err)
	}
	if out == "" {
		t.Error("expected a tool response")
	}
	// The fake server writes marker.txt in its cwd. It must be in the scratch
	// directory, never in the test's working directory.
	if _, err := os.Stat(filepath.Join(work, "marker.txt")); err != nil {
		t.Errorf("side-effect file should land in the scratch dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cwd, "marker.txt")); err == nil {
		os.Remove(filepath.Join(cwd, "marker.txt"))
		t.Fatal("side-effect file leaked into the working directory")
	}
}

// TestHelperProcess is the fake MCP server. It is inert unless ASPEX_FAKE_MCP
// is set, so normal `go test` ignores it.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("ASPEX_FAKE_MCP") != "1" {
		return
	}
	// Prove where we are running: write a marker in the current directory.
	_ = os.WriteFile("marker.txt", []byte("x"), 0o644)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var req struct {
			ID     *int64 `json:"id"`
			Method string `json:"method"`
		}
		if json.Unmarshal(sc.Bytes(), &req) != nil || req.ID == nil {
			continue // a notification, no reply
		}
		var result interface{} = map[string]interface{}{}
		if req.Method == "tools/call" {
			result = map[string]interface{}{"content": []map[string]string{{"type": "text", "text": "ok"}}}
		}
		resp, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": *req.ID, "result": result})
		os.Stdout.Write(append(resp, '\n'))
	}
	os.Exit(0)
}
