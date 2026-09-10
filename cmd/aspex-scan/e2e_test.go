package main

// End-to-end tests: drive the real cobra command tree against a fake home
// directory and assert on the JSON a user would get. Static mode only
// (--no-exec) so no subprocesses or network are involved.

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/policy"
	"github.com/aspex-security/aspex/internal/report"
	"github.com/aspex-security/aspex/internal/testenv"
)

// runCLI executes aspex-scan with args, capturing stdout. It returns the
// command error unmodified so tests can check the --fail-on sentinel.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	out := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	root := newRootCmd()
	root.SetArgs(args)
	runErr := root.Execute()
	w.Close()
	os.Stdout = old
	return <-out, runErr
}

func scanJSON(t *testing.T, extra ...string) (report.JSONScanOutput, error) {
	t.Helper()
	args := append([]string{"--no-exec", "--json", "--clients", "claude-code"}, extra...)
	out, err := runCLI(t, args...)
	var res report.JSONScanOutput
	if jsonErr := json.Unmarshal([]byte(out), &res); jsonErr != nil {
		t.Fatalf("output is not JSON (%v):\n%s", jsonErr, out)
	}
	return res, err
}

func ruleIDs(res report.JSONScanOutput) map[string]int {
	m := map[string]int{}
	for _, s := range res.Servers {
		for _, f := range s.Findings {
			m[f.RuleID]++
		}
	}
	return m
}

func TestE2E_ScanDiscoversClaudeCodeServersAndFindsRisks(t *testing.T) {
	testenv.FakeHome(t)
	t.Chdir(t.TempDir())

	res, err := scanJSON(t)
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if len(res.Servers) != 3 {
		t.Fatalf("expected 3 servers from ~/.claude.json, got %d: %+v", len(res.Servers), res.Servers)
	}
	ids := ruleIDs(res)
	for _, want := range []string{"MCP006", "MCP021", "MCP010"} {
		if ids[want] == 0 {
			t.Errorf("expected %s to fire; fired: %v", want, ids)
		}
	}
	for _, s := range res.Servers {
		if s.Client != "claude-code" {
			t.Errorf("%s: client = %q", s.Name, s.Client)
		}
		if s.Name == testenv.ServerFilesystem && len(s.Findings) != 0 {
			t.Errorf("pinned, scoped filesystem server should be clean in static mode: %+v", s.Findings)
		}
	}
	if res.Overall.Score >= 100 {
		t.Errorf("overall score should reflect critical findings, got %d", res.Overall.Score)
	}
}

func TestE2E_PolicySuppressesOverridesAndGates(t *testing.T) {
	testenv.FakeHome(t)
	dir := t.TempDir()
	t.Chdir(dir)

	// Without policy: two criticals, so --fail-on critical must exit 1.
	if _, err := scanJSON(t, "--fail-on", "critical"); err != errExitOne {
		t.Fatalf("expected fail-on sentinel without policy, got %v", err)
	}

	os.WriteFile(filepath.Join(dir, policy.FileName), []byte(`
ignore:
  - rule: MCP021
    server: kb
    reason: "internal network only, TLS terminated upstream"
severity:
  MCP006: low
fail_on: critical
`), 0o644)

	res, err := scanJSON(t)
	if err != nil {
		t.Fatalf("gate should pass once policy is applied: %v", err)
	}
	if res.Policy == "" {
		t.Error("policy path should be reported")
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].RuleID != "MCP021" || res.Suppressed[0].Reason == "" {
		t.Errorf("suppressed = %+v", res.Suppressed)
	}
	ids := ruleIDs(res)
	if ids["MCP021"] != 0 {
		t.Error("ignored MCP021 still present in findings")
	}
	for _, s := range res.Servers {
		for _, f := range s.Findings {
			if f.RuleID == "MCP006" && f.Severity != "LOW" {
				t.Errorf("MCP006 should be demoted to LOW by policy, got %s", f.Severity)
			}
		}
	}
	// fail_on from the file is the default gate: critical, nothing critical left -> passes.
	// An explicit flag still wins: low is present, so --fail-on low must fail.
	if _, err := scanJSON(t, "--fail-on", "low"); err != errExitOne {
		t.Errorf("explicit --fail-on low should fail with LOW findings present, got %v", err)
	}
}

func TestE2E_BaselineRatchet(t *testing.T) {
	testenv.FakeHome(t)
	dir := t.TempDir()
	t.Chdir(dir)
	base := filepath.Join(dir, "baseline.json")

	if _, err := scanJSON(t, "--save-baseline", base); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(base); err != nil {
		t.Fatal("baseline file not written")
	}

	res, err := scanJSON(t, "--baseline", base, "--fail-on", "low")
	if err != nil {
		t.Fatalf("all findings are baselined, gate must pass: %v", err)
	}
	if res.Baselined == 0 {
		t.Error("baselined count should be > 0")
	}
	if n := len(ruleIDs(res)); n != 0 {
		t.Errorf("no new findings expected after baseline, got %d rule ids", n)
	}
}

func TestE2E_WithTraceCorrelatesLogsToServers(t *testing.T) {
	testenv.FakeHome(t)
	t.Chdir(t.TempDir())

	res, err := scanJSON(t, "--with-trace", "--trace-since", "3650d")
	if err != nil {
		t.Fatal(err)
	}
	if res.Activity == nil {
		t.Fatal("activity missing from JSON output")
	}
	gh, ok := res.Activity[testenv.ServerGitHub]
	if !ok || gh.Calls != testenv.CallsGitHub {
		t.Errorf("github activity = %+v, want %d calls", gh, testenv.CallsGitHub)
	}
	un, ok := res.Activity[testenv.ServerUnscored]
	if !ok || un.Calls != testenv.CallsUnscored {
		t.Errorf("unscored connector activity = %+v, want %d calls", un, testenv.CallsUnscored)
	}
	fs := res.Activity[testenv.ServerFilesystem]
	if fs == nil || fs.Flagged == 0 {
		t.Errorf("credential file read should be flagged by trace rules: %+v", fs)
	}
}

func TestE2E_DoctorAndInit(t *testing.T) {
	testenv.FakeHome(t)
	dir := t.TempDir()
	t.Chdir(dir)

	out, err := runCLI(t, "doctor", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("doctor --json not JSON: %v\n%s", err, out)
	}
	for _, k := range []string{"clients", "findings", "summary"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("doctor JSON missing %q", k)
		}
	}

	if _, err := runCLI(t, "init"); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, policy.FileName)); err != nil {
		t.Fatal("init did not write .aspex.yaml")
	}
	if _, err := runCLI(t, "init"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("second init should refuse without --force, got %v", err)
	}
	if _, err := runCLI(t, "init", "--force"); err != nil {
		t.Errorf("init --force: %v", err)
	}
	// The generated file must itself be a valid policy.
	if _, err := policy.Load(""); err != nil {
		t.Errorf("generated .aspex.yaml does not load: %v", err)
	}
}
