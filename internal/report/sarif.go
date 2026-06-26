package report

import (
	"encoding/json"
	"io"

	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/trace"
)

const (
	sarifVersion   = "2.1.0"
	sarifSchema    = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifDocsBase  = "https://github.com/aspex-security/aspex/blob/main/docs/rules/"
	sarifInfoURI   = "https://github.com/aspex-security/aspex"
	toolVersion    = "0.1.0"
)

// sarifLog is the top-level SARIF 2.1.0 document.
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	HelpURI          string          `json:"helpUri"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// severityToLevel converts a rules.Severity to a SARIF result level.
func severityToLevel(s string) string {
	switch s {
	case "CRITICAL", "ERROR":
		return "error"
	case "HIGH":
		return "warning"
	case "MEDIUM":
		return "note"
	default:
		return "none"
	}
}

// severityFromFinding converts a rules.Severity value to a SARIF level.
func severityRulesToLevel(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "error"
	case rules.SeverityHigh:
		return "warning"
	case rules.SeverityMedium:
		return "note"
	default:
		return "none"
	}
}

// buildRules de-duplicates findings by RuleID and returns a slice of sarifRule.
func buildRules(findings []rules.Finding) []sarifRule {
	seen := map[string]bool{}
	var out []sarifRule
	for _, f := range findings {
		if seen[f.RuleID] {
			continue
		}
		seen[f.RuleID] = true
		out = append(out, sarifRule{
			ID:               f.RuleID,
			Name:             f.Name,
			ShortDescription: sarifMessage{Text: f.Name},
			HelpURI:          sarifDocsBase + f.RuleID + ".md",
		})
	}
	return out
}

// WriteSARIFScan writes a SARIF 2.1.0 document for a scan result.
func WriteSARIFScan(w io.Writer, scan JSONScanOutput) error {
	// Collect all findings across servers.
	var allFindings []rules.Finding
	type locatedFinding struct {
		finding rules.Finding
		uri     string
	}
	var located []locatedFinding

	for _, srv := range scan.Servers {
		for _, jf := range srv.Findings {
			f := rules.Finding{
				RuleID:   jf.RuleID,
				Name:     jf.Name,
				Detail:   jf.Detail,
				Mapping:  jf.Mapping,
			}
			// Map severity string back to rules.Severity for level conversion.
			f.Severity = severityStringToRules(jf.Severity)
			allFindings = append(allFindings, f)
			located = append(located, locatedFinding{finding: f, uri: srv.Client})
		}
	}

	sarifRules := buildRules(allFindings)
	var results []sarifResult
	for _, lf := range located {
		r := sarifResult{
			RuleID:  lf.finding.RuleID,
			Level:   severityRulesToLevel(lf.finding.Severity),
			Message: sarifMessage{Text: lf.finding.Detail},
		}
		if lf.uri != "" {
			r.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: lf.uri},
				},
			}}
		}
		results = append(results, r)
	}

	doc := sarifLog{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "aspex-scan",
					Version:        toolVersion,
					InformationURI: sarifInfoURI,
					Rules:          sarifRules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// severityStringToRules converts a severity string (from JSON) to rules.Severity.
func severityStringToRules(s string) rules.Severity {
	switch s {
	case "CRITICAL":
		return rules.SeverityCritical
	case "HIGH":
		return rules.SeverityHigh
	case "MEDIUM":
		return rules.SeverityMedium
	case "LOW":
		return rules.SeverityLow
	default:
		return rules.SeverityInfo
	}
}

// WriteSARIFTrace writes a SARIF 2.1.0 document for a trace result.
func WriteSARIFTrace(w io.Writer, version string, flagged []trace.FlaggedEvent) error {
	var allFindings []rules.Finding
	type locatedFinding struct {
		finding rules.Finding
		uri     string
	}
	var located []locatedFinding

	for _, fe := range flagged {
		uri := fe.Event.Server
		if uri == "" {
			uri = fe.Event.Client
		}
		for _, f := range fe.Findings {
			allFindings = append(allFindings, f)
			located = append(located, locatedFinding{finding: f, uri: uri})
		}
	}

	sarifRules := buildRules(allFindings)
	var results []sarifResult
	for _, lf := range located {
		r := sarifResult{
			RuleID:  lf.finding.RuleID,
			Level:   severityRulesToLevel(lf.finding.Severity),
			Message: sarifMessage{Text: lf.finding.Detail},
		}
		if lf.uri != "" {
			r.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: lf.uri},
				},
			}}
		}
		results = append(results, r)
	}

	doc := sarifLog{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "aspex-trace",
					Version:        version,
					InformationURI: sarifInfoURI,
					Rules:          sarifRules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
