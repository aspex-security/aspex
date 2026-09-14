// Package rules — catalog evaluation functions for tools, resources, and prompts.
// Rules MCP027+ use a data-driven pattern-match approach: tool name, description, and
// input schema are each matched against lists of known-dangerous substrings.
package rules

import (
	"strings"

	"github.com/aspex-security/aspex/internal/mcpclient"
)

// toolCatalogRule fires when ANY toolNames substring matches the tool name (case-insensitive),
// OR when ANY descWords substring matches the description. A single rule cannot fire twice.
type toolCatalogRule struct {
	ruleID     string
	name       string
	sev        Severity
	fix        string
	mapping    string
	toolNames  []string // match any as substring in lowercase tool name
	descWords  []string // match any as substring in lowercase description
	schemaKeys []string // match any as substring in JSON-serialised input schema
}

// resourceCatalogRule fires when ANY uriWords substring matches the resource URI,
// or ANY mimeTypes substring matches the MIME type.
type resourceCatalogRule struct {
	ruleID    string
	name      string
	sev       Severity
	fix       string
	mapping   string
	uriWords  []string
	mimeTypes []string
}

// promptCatalogRule fires when ANY descWords substring matches the prompt description,
// or ANY nameWords substring matches the prompt name,
// or the description length >= minLen (0 = disabled).
type promptCatalogRule struct {
	ruleID    string
	name      string
	sev       Severity
	fix       string
	mapping   string
	descWords []string
	nameWords []string
	minLen    int
}

// ─── Tool catalog ─────────────────────────────────────────────────────────────

// ─── Resource catalog ─────────────────────────────────────────────────────────

// ─── Prompt catalog ──────────────────────────────────────────────────────────

// ─── EvalToolCatalog ──────────────────────────────────────────────────────────

// EvalToolCatalog runs catalog-level rules against a single tool.
func EvalToolCatalog(t *mcpclient.Tool) []Finding {
	var f []Finding
	nameLower := strings.ToLower(t.Name)
	descLower := strings.ToLower(t.Description)
	schemaLower := strings.ToLower(string(t.InputSchema))

	for _, rule := range toolCatalogRules {
		var matched bool
		detail := ""

		// Detail names the tool and where the signal was found (name /
		// description / input schema), phrased as the capability the rule
		// detects — not the raw substring that matched. Exposing the pattern
		// (e.g. "name contains 'r_eval'") reads like a bug and makes a correct
		// finding look crude; the matched pattern is kept in Evidence for
		// debugging.
		matchedPat := ""
		if !matched {
			for _, pat := range rule.toolNames {
				if strings.Contains(nameLower, pat) {
					detail = "Tool '" + t.Name + "' has a name consistent with " + lowerFirst(rule.name) + "."
					matchedPat = "name pattern '" + pat + "'"
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, word := range rule.descWords {
				if strings.Contains(descLower, word) {
					detail = "Tool '" + t.Name + "' has a description consistent with " + lowerFirst(rule.name) + "."
					matchedPat = "description pattern '" + word + "'"
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, key := range rule.schemaKeys {
				if strings.Contains(schemaLower, key) {
					detail = "Tool '" + t.Name + "' has an input schema consistent with " + lowerFirst(rule.name) + "."
					matchedPat = "schema pattern '" + key + "'"
					matched = true
					break
				}
			}
		}
		if matched {
			ev := []Evidence{Observed(detail)}
			if matchedPat != "" {
				ev = append(ev, Inferred("matched "+matchedPat))
			}
			ev = append(ev, Inferred(rule.name))
			f = append(f, Finding{
				Evidence: ev,
				RuleID:   rule.ruleID,
				Name:     rule.name,
				Severity: rule.sev,
				Detail:   detail,
				Fix:      rule.fix,
				Mapping:  rule.mapping,
			})
		}
	}
	return f
}

// lowerFirst lowercases the first rune of s, so a rule name reads naturally
// mid-sentence ("... consistent with a language REPL or eval capability.").
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	// Leave acronyms (two leading capitals, e.g. "SSRF") untouched.
	if len(r) >= 2 && r[1] >= 'A' && r[1] <= 'Z' {
		return s
	}
	r[0] = []rune(strings.ToLower(string(r[0])))[0]
	return string(r)
}

// ─── EvalResourceCatalog ──────────────────────────────────────────────────────

// EvalResourceCatalog runs catalog-level rules against a single resource.
func EvalResourceCatalog(r *mcpclient.Resource) []Finding {
	var f []Finding
	uriLower := strings.ToLower(r.URI)
	mimeLower := strings.ToLower(r.MimeType)

	for _, rule := range resourceCatalogRules {
		var matched bool
		detail := ""

		if !matched {
			for _, word := range rule.uriWords {
				if strings.Contains(uriLower, word) {
					detail = "Resource URI '" + r.URI + "' matches sensitive pattern '" + word + "'."
					matched = true
					break
				}
			}
		}
		if !matched && mimeLower != "" {
			for _, mt := range rule.mimeTypes {
				if strings.Contains(mimeLower, mt) {
					detail = "Resource '" + r.Name + "' has MIME type '" + r.MimeType + "' which indicates an executable."
					matched = true
					break
				}
			}
		}
		if matched {
			f = append(f, Finding{
				RuleID:   rule.ruleID,
				Name:     rule.name,
				Severity: rule.sev,
				Detail:   detail,
				Fix:      rule.fix,
				Mapping:  rule.mapping,
			})
		}
	}
	return f
}

// ─── EvalPromptCatalog ────────────────────────────────────────────────────────

// EvalPromptCatalog runs catalog-level rules against a single prompt.
func EvalPromptCatalog(p *mcpclient.Prompt) []Finding {
	var f []Finding
	descLower := strings.ToLower(p.Description)
	nameLower := strings.ToLower(p.Name)

	// Also check for injectionPhrasePatterns defined in rules.go.
	for _, pat := range injectionPhrasePatterns {
		if pat.MatchString(descLower) {
			f = append(f, Finding{
				RuleID:   "MCP156",
				Name:     "Regex-matched prompt injection pattern in prompt description",
				Severity: SeverityCritical,
				Detail:   "Prompt '" + p.Name + "' description matches prompt-injection regex: " + pat.String(),
				Fix:      "Remove or rewrite the prompt description. Do not trust this server.",
				Mapping:  "OWASP LLM01, ATLAS AML.T0051, CWE-77",
			})
			break
		}
	}

	for _, rule := range promptCatalogRules {
		var matched bool
		detail := ""

		if !matched && rule.minLen > 0 && len(p.Description) >= rule.minLen {
			detail = "Prompt '" + p.Name + "' description is " + itoa(len(p.Description)) + " characters."
			matched = true
		}
		if !matched {
			for _, word := range rule.descWords {
				if strings.Contains(descLower, word) {
					detail = "Prompt '" + p.Name + "' description contains '" + word + "'."
					matched = true
					break
				}
			}
		}
		if !matched {
			for _, word := range rule.nameWords {
				if strings.Contains(nameLower, word) {
					detail = "Prompt name '" + p.Name + "' contains '" + word + "'."
					matched = true
					break
				}
			}
		}
		if matched {
			f = append(f, Finding{
				RuleID:   rule.ruleID,
				Name:     rule.name,
				Severity: rule.sev,
				Detail:   detail,
				Fix:      rule.fix,
				Mapping:  rule.mapping,
			})
		}
	}
	return f
}
