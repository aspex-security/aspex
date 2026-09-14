package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/report"
)

// In a non-terminal stream (CI, pipes) progress must never emit escape
// sequences and must still report the completed/total counter, so a run is
// legible in a log and never silent.
func TestProgressNonTTYIsPlainAndCounts(t *testing.T) {
	var buf bytes.Buffer
	report.SetSpinnerOutput(&buf, false)
	t.Cleanup(func() { report.SetSpinnerOutput(&buf, false) }) // detach global from real stderr

	p := report.NewProgress("Inspecting servers", 3)
	p.Item("filesystem")
	p.Done()
	p.Item("github")
	p.Done()
	p.Stop()

	out := buf.String()
	if strings.ContainsRune(out, '\033') {
		t.Errorf("escape codes leaked into non-TTY progress output: %q", out)
	}
	if !strings.Contains(out, "Inspecting servers") {
		t.Errorf("progress prefix missing: %q", out)
	}
	if !strings.Contains(out, "2/3") {
		t.Errorf("progress should report the completed/total counter, got: %q", out)
	}
}

// Print routes a result line to the given writer and, on a TTY, clears the
// transient line first so the two streams do not collide.
func TestProgressPrintClearsOnTTY(t *testing.T) {
	var errBuf, outBuf bytes.Buffer
	report.SetSpinnerOutput(&errBuf, true) // animated
	t.Cleanup(func() { report.SetSpinnerOutput(&errBuf, false) })

	p := report.NewProgress("Probing servers", 1)
	p.Print(&outBuf, "  VULNERABLE result\n")
	p.Stop()

	if !strings.Contains(outBuf.String(), "VULNERABLE result") {
		t.Errorf("Print should write the result to the target writer, got: %q", outBuf.String())
	}
	// The clear sequence goes to the progress (stderr) stream, not stdout.
	if strings.ContainsRune(outBuf.String(), '\033') {
		t.Errorf("result stream must not carry the clear escape: %q", outBuf.String())
	}
	if !strings.Contains(errBuf.String(), "\033[2K") {
		t.Errorf("expected a clear sequence on the progress stream, got: %q", errBuf.String())
	}
}
