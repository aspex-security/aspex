package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aspex-security/aspex/internal/rules"
)

var now = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)

func f(id string, sev rules.Severity) rules.Finding {
	return rules.Finding{RuleID: id, Name: id, Severity: sev}
}

func TestIgnoreExactServer(t *testing.T) {
	c := &Config{Ignore: []IgnoreEntry{{Rule: "MCP004", Server: "filesystem", Reason: "scoped"}}}
	kept, sup, _ := c.Apply("filesystem", []rules.Finding{f("MCP004", rules.SeverityCritical), f("MCP006", rules.SeverityHigh)}, now)
	if len(kept) != 1 || kept[0].RuleID != "MCP006" {
		t.Fatalf("kept = %+v", kept)
	}
	if len(sup) != 1 || sup[0].Reason != "scoped" {
		t.Fatalf("suppressed = %+v", sup)
	}
	// Different server: not suppressed.
	kept, _, _ = c.Apply("other", []rules.Finding{f("MCP004", rules.SeverityCritical)}, now)
	if len(kept) != 1 {
		t.Fatal("ignore leaked to another server")
	}
}

func TestIgnoreGlobAndAllServers(t *testing.T) {
	c := &Config{Ignore: []IgnoreEntry{
		{Rule: "MCP026", Server: "internal-*", Reason: "many tools by design"},
		{Rule: "MCP019", Reason: "accepted everywhere"},
	}}
	kept, _, _ := c.Apply("internal-tools", []rules.Finding{f("MCP026", rules.SeverityMedium), f("MCP019", rules.SeverityLow)}, now)
	if len(kept) != 0 {
		t.Fatalf("expected both suppressed, kept %+v", kept)
	}
}

func TestExpiredIgnoreStopsSuppressing(t *testing.T) {
	c := &Config{Ignore: []IgnoreEntry{{Rule: "MCP004", Reason: "temp", Expires: "2026-01-01"}}}
	kept, sup, expired := c.Apply("fs", []rules.Finding{f("MCP004", rules.SeverityCritical)}, now)
	if len(kept) != 1 || len(sup) != 0 || len(expired) != 1 {
		t.Fatalf("kept=%d sup=%d expired=%d", len(kept), len(sup), len(expired))
	}
	// Still valid on the expiry day itself.
	if (IgnoreEntry{Expires: "2026-09-10"}).Expired(now) {
		t.Fatal("entry should be valid through its expiry date")
	}
}

func TestSeverityOverrideAndOff(t *testing.T) {
	c := &Config{Severity: map[string]string{"MCP021": "critical", "MCP026": "off"}}
	kept, _, _ := c.Apply("s", []rules.Finding{f("MCP021", rules.SeverityHigh), f("MCP026", rules.SeverityMedium)}, now)
	if len(kept) != 1 || kept[0].Severity != rules.SeverityCritical {
		t.Fatalf("kept = %+v", kept)
	}
}

func TestValidation(t *testing.T) {
	bad := []Config{
		{Ignore: []IgnoreEntry{{Rule: "MCP004"}}}, // no reason
		{Ignore: []IgnoreEntry{{Reason: "x"}}},    // no rule
		{Ignore: []IgnoreEntry{{Rule: "MCP004", Reason: "x", Expires: "soon"}}},
		{Severity: map[string]string{"MCP001": "urgent"}},
		{FailOn: "always"},
	}
	for i, c := range bad {
		if err := c.validate(); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
	if err := (&Config{}).validate(); err != nil {
		t.Errorf("empty config should validate: %v", err)
	}
}

func TestLoadSearchOrder(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(dir)

	cfg, err := Load("")
	if err != nil || cfg != nil {
		t.Fatalf("no file: cfg=%v err=%v", cfg, err)
	}
	os.WriteFile(filepath.Join(dir, FileName), []byte(Example()), 0o644)
	cfg, err = Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn != "high" || len(cfg.Ignore) != 1 || cfg.Severity["MCP021"] != "critical" {
		t.Fatalf("example did not round-trip: %+v", cfg)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("explicit missing path should error")
	}
}

func TestBaselineRatchet(t *testing.T) {
	servers := []string{"fs", "db"}
	findings := [][]rules.Finding{{f("MCP004", rules.SeverityCritical)}, {f("MCP006", rules.SeverityHigh)}}
	b := NewBaseline("test", servers, findings)

	p := filepath.Join(t.TempDir(), "baseline.json")
	if err := b.Save(p); err != nil {
		t.Fatal(err)
	}
	b2, err := LoadBaseline(p)
	if err != nil {
		t.Fatal(err)
	}
	fresh, known := b2.Filter("fs", []rules.Finding{f("MCP004", rules.SeverityCritical), f("MCP021", rules.SeverityHigh)})
	if len(known) != 1 || len(fresh) != 1 || fresh[0].RuleID != "MCP021" {
		t.Fatalf("fresh=%+v known=%+v", fresh, known)
	}
	if b2.Known("db", "MCP004") {
		t.Fatal("baseline must be keyed per server")
	}
	var nilB *Baseline
	fresh, _ = nilB.Filter("fs", findings[0])
	if len(fresh) != 1 {
		t.Fatal("nil baseline must pass everything through")
	}
}
