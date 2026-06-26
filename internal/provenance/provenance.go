// Package provenance traces the likely source of suspicious AI agent tool calls.
//
// The core question in prompt injection forensics is not just "did something
// suspicious happen?" but "where did the instruction come from?" When an AI
// agent reads a file or fetches a URL and then immediately executes a shell
// command or exfiltrates data, the content it consumed is the most likely
// source of the injected instruction.
//
// This package analyzes a sequence of tool call events and, for each
// suspicious (flagged) event, looks backward in the same session for
// "ingestion" events — reads, fetches, browser navigations, resource loads —
// that preceded it. The temporal and contextual proximity of an ingestion
// event to a suspicious call is the primary evidence of instruction injection
// from external content.
//
// Output: for each suspicious finding, an Attribution that names the specific
// ingestion event most likely to have delivered the injected instruction, how
// long before the suspicious call it occurred, and the confidence level.
package provenance

import (
	"sort"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/trace"
)

// maxLookback is how far back (in time) we search for a preceding ingestion event.
const maxLookback = 10 * time.Minute

// maxEventLookback is how many events back we search (whichever limit is hit first).
const maxEventLookback = 20

// Attribution links a suspicious event to the ingestion event most likely to
// have delivered the injected instruction.
type Attribution struct {
	// The suspicious event and its findings.
	SuspiciousEvent logparse.Event
	Findings        []rules.Finding

	// The ingestion event that preceded it.
	IngestionEvent logparse.Event
	IngestionKind  string // "file_read" | "web_fetch" | "resource_read" | "browser_load"
	IngestionSource string // file path, URL, or resource URI

	// Temporal proximity.
	Delta          time.Duration // time between ingestion and suspicious call
	EventsApart    int           // number of events between them

	// Confidence assessment.
	Confidence     string // "high" | "medium" | "low"
	Explanation    string // human-readable explanation of why this is suspicious
}

// Report is the full provenance analysis result.
type Report struct {
	Attributions    []Attribution
	TotalEvents     int
	TotalFlagged    int
	WithProvenance  int // flagged events that have a preceding ingestion event
}

// ingestionTool returns true and a kind label if the tool name looks like a
// content-ingestion operation.
func ingestionTool(toolName string) (bool, string) {
	lower := strings.ToLower(toolName)

	fileReads := []string{
		"read_file", "get_file", "view_file", "cat_file", "read_text",
		"get_contents", "fetch_file", "open_file", "read_multiple_files",
		"get_file_contents", "download_file",
	}
	for _, p := range fileReads {
		if strings.Contains(lower, p) || lower == p {
			return true, "file_read"
		}
	}

	webFetches := []string{
		"fetch", "http_get", "web_fetch", "get_url", "fetch_url",
		"http_request", "make_request", "call_url", "get_page_content",
		"read_url", "download_url", "request",
	}
	for _, p := range webFetches {
		if strings.Contains(lower, p) || lower == p {
			return true, "web_fetch"
		}
	}

	browserLoads := []string{
		"browser_navigate", "browser_load", "navigate_to", "open_url",
		"browser_go_to", "browser_open", "go_to_url", "navigate",
	}
	for _, p := range browserLoads {
		if strings.Contains(lower, p) || lower == p {
			return true, "browser_load"
		}
	}

	resourceReads := []string{
		"get_resource", "read_resource", "access_resource", "load_resource",
		"get_prompt", "use_prompt",
	}
	for _, p := range resourceReads {
		if strings.Contains(lower, p) || lower == p {
			return true, "resource_read"
		}
	}

	return false, ""
}

// extractSource extracts a human-readable source identifier from event args.
func extractSource(ev logparse.Event, kind string) string {
	if len(ev.Args) == 0 {
		return ev.Tool
	}

	// Try common argument names for paths / URLs.
	candidates := []string{"path", "file_path", "filepath", "url", "uri", "src", "source", "location"}
	for _, key := range candidates {
		if v, ok := ev.Args[key]; ok && v != "" {
			return v
		}
	}

	// Fall back: first non-empty value that looks like a path or URL.
	for _, v := range ev.Args {
		if v != "" && len(v) < 200 {
			return v
		}
	}

	return ev.Tool
}

// confidence assesses how confident we are that the ingestion event caused the
// suspicious one, based on timing and event distance.
func confidence(delta time.Duration, eventsApart int, ingestionKind string) (string, string) {
	switch {
	case delta < 30*time.Second && eventsApart <= 3:
		return "high", "Suspicious call occurred within 30 seconds and 3 events of the ingestion — " +
			"extremely tight temporal coupling consistent with immediate instruction execution."

	case delta < 2*time.Minute && eventsApart <= 8:
		explanation := "Suspicious call occurred within 2 minutes of the ingestion."
		if ingestionKind == "web_fetch" || ingestionKind == "browser_load" {
			explanation += " Web content is a primary prompt injection delivery channel."
		} else if ingestionKind == "file_read" {
			explanation += " Files containing injected instructions are a common attack vector."
		}
		return "medium", explanation

	default:
		return "low", "Suspicious call occurred after an ingestion event, but with more temporal " +
			"distance. Less conclusive, but worth reviewing the ingested content."
	}
}

// Analyze performs provenance analysis across all events and findings.
func Analyze(events []logparse.Event, flagged []trace.FlaggedEvent) Report {
	if len(events) == 0 {
		return Report{}
	}

	// Sort events chronologically.
	sorted := make([]logparse.Event, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	// Build index from timestamp+tool to event position.
	posIdx := make(map[string]int, len(sorted))
	for i, ev := range sorted {
		key := evKey(ev)
		posIdx[key] = i
	}

	var attributions []Attribution
	seen := map[string]bool{}

	for _, fe := range flagged {
		if len(fe.Findings) == 0 {
			continue
		}

		// Only attribute HIGH and CRITICAL findings — lower severities produce too much noise.
		hasHighRisk := false
		for _, f := range fe.Findings {
			if f.Severity >= rules.SeverityHigh {
				hasHighRisk = true
				break
			}
		}
		if !hasHighRisk {
			continue
		}

		key := evKey(fe.Event)
		if seen[key] {
			continue
		}

		pos, ok := posIdx[key]
		if !ok {
			// Try to find by tool name in the window (timestamp may be slightly off).
			for i, ev := range sorted {
				if ev.Tool == fe.Event.Tool && ev.Server == fe.Event.Server {
					pos = i
					ok = true
					break
				}
			}
		}
		if !ok {
			continue
		}

		// Look backwards for ingestion events.
		start := pos - maxEventLookback
		if start < 0 {
			start = 0
		}

		var bestIngestion *logparse.Event
		var bestKind string
		var bestDelta time.Duration
		var bestApart int

		for i := pos - 1; i >= start; i-- {
			prev := sorted[i]

			// Must be in the same session (same client, close in time).
			if prev.Client != fe.Event.Client {
				continue
			}

			delta := fe.Event.Timestamp.Sub(prev.Timestamp)
			if delta > maxLookback {
				break // events are too old, stop searching
			}

			isIngestion, kind := ingestionTool(prev.Tool)
			if !isIngestion {
				continue
			}

			eventsApart := pos - i
			// Take the CLOSEST ingestion event (smallest delta).
			if bestIngestion == nil || delta < bestDelta {
				evCopy := prev
				bestIngestion = &evCopy
				bestKind = kind
				bestDelta = delta
				bestApart = eventsApart
			}
		}

		if bestIngestion == nil {
			continue
		}

		seen[key] = true
		source := extractSource(*bestIngestion, bestKind)
		conf, explanation := confidence(bestDelta, bestApart, bestKind)

		attributions = append(attributions, Attribution{
			SuspiciousEvent: fe.Event,
			Findings:        fe.Findings,
			IngestionEvent:  *bestIngestion,
			IngestionKind:   bestKind,
			IngestionSource: source,
			Delta:           bestDelta,
			EventsApart:     bestApart,
			Confidence:      conf,
			Explanation:     explanation,
		})
	}

	// Sort: high confidence first, then by timestamp.
	sort.Slice(attributions, func(i, j int) bool {
		ci, cj := confRank(attributions[i].Confidence), confRank(attributions[j].Confidence)
		if ci != cj {
			return ci > cj
		}
		return attributions[i].SuspiciousEvent.Timestamp.Before(attributions[j].SuspiciousEvent.Timestamp)
	})

	withProv := len(attributions)

	return Report{
		Attributions:   attributions,
		TotalEvents:    len(events),
		TotalFlagged:   len(flagged),
		WithProvenance: withProv,
	}
}

func evKey(ev logparse.Event) string {
	return ev.Timestamp.Format(time.RFC3339Nano) + "/" + ev.Tool + "/" + ev.Server
}

func confRank(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
