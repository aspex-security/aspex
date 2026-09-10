// Package policy loads the optional .aspex.yaml config that lets a team
// accept specific risks (ignore) and set their own severity for any rule
// (severity). Both are applied to findings before scoring and before the
// --fail-on gate, so a tuned policy is what CI actually enforces.
package policy

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aspex-security/aspex/internal/rules"
)

// FileName is the project-local config file searched for in the working directory.
const FileName = ".aspex.yaml"

// Config is the parsed .aspex.yaml.
type Config struct {
	// Ignore lists accepted risks. Each entry needs a reason; an expiry is
	// strongly recommended so accepted risks get re-reviewed.
	Ignore []IgnoreEntry `yaml:"ignore"`
	// Severity overrides a rule's severity: critical|high|medium|low|off.
	// "off" disables the rule entirely.
	Severity map[string]string `yaml:"severity"`
	// FailOn sets the default --fail-on threshold when the flag is not passed.
	FailOn string `yaml:"fail_on"`

	// Path the config was loaded from (not part of the YAML).
	Path string `yaml:"-"`
}

// IgnoreEntry is one accepted risk.
type IgnoreEntry struct {
	Rule    string `yaml:"rule"`    // rule ID, e.g. MCP004. Required.
	Server  string `yaml:"server"`  // server name or glob (path.Match). Empty = all servers.
	Reason  string `yaml:"reason"`  // required - why this risk is accepted
	Expires string `yaml:"expires"` // optional YYYY-MM-DD; expired entries stop suppressing
}

// Suppressed records a finding removed by policy, for reporting.
type Suppressed struct {
	Server  string
	Finding rules.Finding
	Reason  string
	Expires string
}

// Load reads the policy. explicitPath wins; otherwise ./.aspex.yaml, then
// $XDG_CONFIG_HOME/aspex/config.yaml (~/.config/aspex/config.yaml).
// Returns (nil, nil) when no config exists anywhere.
func Load(explicitPath string) (*Config, error) {
	candidates := []string{}
	if explicitPath != "" {
		candidates = append(candidates, explicitPath)
	} else {
		candidates = append(candidates, FileName)
		if dir, err := os.UserConfigDir(); err == nil {
			candidates = append(candidates, filepath.Join(dir, "aspex", "config.yaml"))
		}
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			if explicitPath != "" {
				return nil, fmt.Errorf("reading %s: %w", p, err)
			}
			continue
		}
		cfg := &Config{Path: p}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", p, err)
		}
		if err := cfg.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		return cfg, nil
	}
	return nil, nil
}

func (c *Config) validate() error {
	for i, e := range c.Ignore {
		if e.Rule == "" {
			return fmt.Errorf("ignore[%d]: rule is required", i)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("ignore[%d] (%s): reason is required - say why this risk is accepted", i, e.Rule)
		}
		if e.Expires != "" {
			if _, err := time.Parse("2006-01-02", e.Expires); err != nil {
				return fmt.Errorf("ignore[%d] (%s): expires must be YYYY-MM-DD", i, e.Rule)
			}
		}
	}
	for id, sev := range c.Severity {
		if _, ok := parseSeverity(sev); !ok {
			return fmt.Errorf("severity[%s]: %q is not one of critical|high|medium|low|off", id, sev)
		}
	}
	if c.FailOn != "" {
		switch c.FailOn {
		case "critical", "high", "medium", "low", "off":
		default:
			return fmt.Errorf("fail_on: %q is not one of critical|high|medium|low|off", c.FailOn)
		}
	}
	return nil
}

func parseSeverity(s string) (rules.Severity, bool) {
	switch strings.ToLower(s) {
	case "critical":
		return rules.SeverityCritical, true
	case "high":
		return rules.SeverityHigh, true
	case "medium":
		return rules.SeverityMedium, true
	case "low":
		return rules.SeverityLow, true
	case "off":
		return 0, true
	}
	return 0, false
}

// Expired reports whether an ignore entry's expiry date has passed.
func (e IgnoreEntry) Expired(now time.Time) bool {
	if e.Expires == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", e.Expires)
	return err == nil && !now.Before(t.Add(24*time.Hour))
}

func (e IgnoreEntry) matches(server, ruleID string) bool {
	if e.Rule != ruleID {
		return false
	}
	if e.Server == "" || e.Server == server {
		return true
	}
	ok, err := path.Match(e.Server, server)
	return err == nil && ok
}

// Apply filters and re-severities one server's findings.
// Returns the findings to keep, the ones suppressed by ignore entries, and
// any expired ignore entries that matched (so the user can be warned).
func (c *Config) Apply(server string, findings []rules.Finding, now time.Time) (kept []rules.Finding, suppressed []Suppressed, expired []IgnoreEntry) {
	if c == nil {
		return findings, nil, nil
	}
	for _, f := range findings {
		// Severity override first: "off" removes the rule outright.
		if sevStr, ok := c.Severity[f.RuleID]; ok {
			sev, _ := parseSeverity(sevStr)
			if sev == 0 {
				continue
			}
			f.Severity = sev
		}
		ignored := false
		for _, e := range c.Ignore {
			if !e.matches(server, f.RuleID) {
				continue
			}
			if e.Expired(now) {
				expired = append(expired, e)
				continue
			}
			suppressed = append(suppressed, Suppressed{Server: server, Finding: f, Reason: e.Reason, Expires: e.Expires})
			ignored = true
			break
		}
		if !ignored {
			kept = append(kept, f)
		}
	}
	return kept, suppressed, expired
}

// Example returns a starter .aspex.yaml for `aspex-scan init`.
func Example() string {
	return `# Aspex policy - see https://aspex.mintlify.site/guides/policy
#
# ignore: accept a specific risk. Every entry needs a reason.
# Add an expiry so accepted risks get re-reviewed instead of forgotten.
ignore:
  - rule: MCP004
    server: filesystem
    reason: "This server is intentionally scoped to ~/projects for the monorepo"
    expires: 2027-01-01

# severity: your severity for a rule, overriding the default.
# Use "off" to disable a rule entirely.
severity:
  MCP021: critical   # plaintext HTTP is never acceptable here
  MCP026: low        # we accept servers with many tools

# fail_on: default CI gate when --fail-on is not passed.
fail_on: high
`
}
