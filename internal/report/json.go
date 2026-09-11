package report

import (
	"encoding/json"
	"io"

	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/correlate"
	"github.com/aspex-security/aspex/internal/score"
	"github.com/aspex-security/aspex/internal/trace"
)

// JSONScanOutput is the machine-readable form of a scan result.
type JSONScanOutput struct {
	Version string             `json:"version"`
	Overall score.OverallScore `json:"overall"`
	Servers []JSONServerResult `json:"servers"`

	// Policy path that was applied, if any.
	Policy string `json:"policy,omitempty"`
	// Findings removed by .aspex.yaml ignore entries.
	Suppressed []JSONSuppressed `json:"suppressed,omitempty"`
	// Count of findings hidden by --baseline.
	Baselined int `json:"baselined,omitempty"`
	// Observed runtime activity per server (--with-trace).
	Activity map[string]*correlate.Activity `json:"activity,omitempty"`
	// Cross-server compositions of capabilities. See internal/attackpath.
	AttackPaths []attackpath.AttackChain `json:"attackPaths,omitempty"`
	// Why the overall score was capped, when an attack path lowered it.
	ScoreCapReason string `json:"scoreCapReason,omitempty"`
	// Blast radius: how far an instruction the agent follows could reach, with
	// every reason listed present or absent. Mirrors agentenv.BlastRadius.
	BlastRadius *BlastRadius `json:"blastRadius,omitempty"`
}

// BlastRadius is the qualitative reach of the environment (HIGH | MEDIUM |
// LOW | NONE) and the auditable reasons behind it.
type BlastRadius struct {
	Level string        `json:"level"`
	Why   []BlastReason `json:"why"`
}

// BlastReason is one factor, present or not.
type BlastReason struct {
	Present bool   `json:"present"`
	Text    string `json:"text"`
}

// JSONSuppressed is an accepted risk removed by policy.
type JSONSuppressed struct {
	Server   string `json:"server"`
	RuleID   string `json:"ruleId"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
	Expires  string `json:"expires,omitempty"`
}

// JSONServerResult is one server in the JSON scan output.
type JSONServerResult struct {
	Name       string        `json:"name"`
	Client     string        `json:"client"`
	Score      int           `json:"score"`
	Band       string        `json:"band"`
	StaticOnly bool          `json:"staticOnly"`
	Findings   []JSONFinding `json:"findings"`
}

// JSONFinding is a single finding in JSON output.
type JSONFinding struct {
	RuleID   string `json:"ruleId"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
	Mapping  string `json:"mapping,omitempty"`
}

// WriteJSONScan encodes the scan report as JSON to w.
func WriteJSONScan(w io.Writer, out JSONScanOutput) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// JSONTraceOutput is the machine-readable form of a trace result.
type JSONTraceOutput struct {
	Version string             `json:"version"`
	Flagged []JSONFlaggedEvent `json:"flagged"`
	Total   int                `json:"totalEvents"`
}

// JSONFlaggedEvent is a flagged event in JSON trace output.
type JSONFlaggedEvent struct {
	Timestamp string            `json:"ts"`
	Client    string            `json:"client"`
	Server    string            `json:"server"`
	Event     string            `json:"event"`
	Tool      string            `json:"tool,omitempty"`
	Args      map[string]string `json:"args,omitempty"`
	Findings  []JSONFinding     `json:"findings"`
}

// WriteJSONTrace encodes the trace report as JSON to w.
func WriteJSONTrace(w io.Writer, version string, flagged []trace.FlaggedEvent, total int) error {
	out := JSONTraceOutput{
		Version: version,
		Total:   total,
	}
	for _, fe := range flagged {
		jfe := JSONFlaggedEvent{
			Timestamp: fe.Event.Timestamp.Format("2006-01-02T15:04:05Z"),
			Client:    fe.Event.Client,
			Server:    fe.Event.Server,
			Event:     string(fe.Event.Event),
			Tool:      fe.Event.Tool,
			Args:      fe.Event.Args,
		}
		for _, f := range fe.Findings {
			jfe.Findings = append(jfe.Findings, JSONFinding{
				RuleID:   f.RuleID,
				Name:     f.Name,
				Severity: f.Severity.String(),
				Detail:   f.Detail,
				Fix:      f.Fix,
				Mapping:  f.Mapping,
			})
		}
		out.Flagged = append(out.Flagged, jfe)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
