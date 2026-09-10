package policy

import (
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/aspex-security/aspex/internal/rules"
)

// Baseline is a snapshot of known findings. Findings present in the baseline
// are treated as pre-existing: hidden from output and excluded from the
// --fail-on gate, so only new findings fail. This is the "ratchet" that lets
// a team adopt Aspex on an estate with existing findings and stop regressions
// from day one, then burn the baseline down over time.
type Baseline struct {
	CreatedAt time.Time `json:"created_at"`
	Version   string    `json:"aspex_version"`
	// Keys are "server\x00ruleID".
	Keys []string `json:"findings"`

	set map[string]struct{}
}

func key(server, ruleID string) string { return server + "\x00" + ruleID }

// NewBaseline builds a baseline from per-server findings.
func NewBaseline(version string, servers []string, findings [][]rules.Finding) *Baseline {
	b := &Baseline{CreatedAt: time.Now().UTC(), Version: version, set: map[string]struct{}{}}
	for i, fs := range findings {
		for _, f := range fs {
			k := key(servers[i], f.RuleID)
			if _, dup := b.set[k]; dup {
				continue
			}
			b.set[k] = struct{}{}
			b.Keys = append(b.Keys, k)
		}
	}
	sort.Strings(b.Keys)
	return b
}

// Save writes the baseline as JSON.
func (b *Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadBaseline reads a baseline file.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	b.set = make(map[string]struct{}, len(b.Keys))
	for _, k := range b.Keys {
		b.set[k] = struct{}{}
	}
	return &b, nil
}

// Known reports whether a finding was present when the baseline was taken.
func (b *Baseline) Known(server, ruleID string) bool {
	if b == nil {
		return false
	}
	_, ok := b.set[key(server, ruleID)]
	return ok
}

// Filter splits findings into new (not in baseline) and known.
func (b *Baseline) Filter(server string, findings []rules.Finding) (fresh, known []rules.Finding) {
	if b == nil {
		return findings, nil
	}
	for _, f := range findings {
		if b.Known(server, f.RuleID) {
			known = append(known, f)
		} else {
			fresh = append(fresh, f)
		}
	}
	return fresh, known
}
