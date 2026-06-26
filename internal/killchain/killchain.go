// Package killchain reconstructs multi-step attack patterns from a sequence
// of MCP tool call events. Individual event flagging (e.g. "a credential file
// was accessed") tells you what happened; kill chain analysis tells you whether
// several suspicious events together form a coherent, intentional attack.
//
// This operates on events already annotated with rule findings (from
// trace.AnalyzeEvents) and looks for temporal clusters where the events in
// combination match a known attacker playbook.
package killchain

import (
	"sort"
	"time"

	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/trace"
)

// Chain is a detected multi-step attack pattern.
type Chain struct {
	Name        string     // "Exfiltration Trifecta"
	Severity    string     // "critical" | "high" | "medium"
	Description string     // narrative explanation
	MITRETactic string     // MITRE ATT&CK tactic
	MITRERef    string     // MITRE ATT&CK ref
	Steps       []ChainStep
	WindowStart time.Time
	WindowEnd   time.Time
	Client      string
	Server      string
}

// ChainStep is one event within a detected chain.
type ChainStep struct {
	Timestamp time.Time
	Tool      string
	Server    string
	RuleIDs   []string
	Detail    string // what made this step significant
}

// maxWindow is the maximum time between the first and last event in a chain.
// Events spread further apart are unlikely to be part of a single prompt injection.
const maxWindow = 5 * time.Minute

// Analyze identifies kill chain patterns across all flagged events.
// events must be the full raw event slice; flagged is the result of trace.AnalyzeEvents.
func Analyze(events []logparse.Event, flagged []trace.FlaggedEvent) []Chain {
	if len(events) == 0 {
		return nil
	}

	// Build a findings index keyed by timestamp+tool for fast lookup.
	findingIdx := map[string][]rules.Finding{}
	for _, fe := range flagged {
		key := evKey(fe.Event)
		findingIdx[key] = append(findingIdx[key], fe.Findings...)
	}

	// Sort events chronologically.
	sorted := make([]logparse.Event, len(events))
	copy(sorted, events)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	var chains []Chain
	seen := map[string]bool{}

	detectors := []func([]logparse.Event, map[string][]rules.Finding) []Chain{
		detectExfiltrationTrifecta,
		detectPersistenceEstablishment,
		detectReconToCredential,
		detectLateralMovementSetup,
		detectInjectionSignature,
	}

	for _, detect := range detectors {
		for _, ch := range detect(sorted, findingIdx) {
			key := ch.Name + ch.WindowStart.Format(time.RFC3339) + ch.Client
			if !seen[key] {
				seen[key] = true
				chains = append(chains, ch)
			}
		}
	}

	// Sort: critical first, then chronological.
	sort.Slice(chains, func(i, j int) bool {
		ri, rj := severityRank(chains[i].Severity), severityRank(chains[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return chains[i].WindowStart.Before(chains[j].WindowStart)
	})

	return chains
}

// detectExfiltrationTrifecta finds: sensitive file access → outbound network call
// within the same session window.
func detectExfiltrationTrifecta(events []logparse.Event, idx map[string][]rules.Finding) []Chain {
	var chains []Chain
	n := len(events)
	for i := 0; i < n; i++ {
		ev := events[i]
		findings := idx[evKey(ev)]
		if !hasRule(findings, "AT001") { // sensitive path access
			continue
		}
		// Look for a network call within the window.
		for j := i + 1; j < n; j++ {
			ev2 := events[j]
			if ev2.Timestamp.Sub(ev.Timestamp) > maxWindow {
				break
			}
			findings2 := idx[evKey(ev2)]
			if !hasRule(findings2, "AT002") && !hasRule(findings2, "AT017") { // outbound network / data chain
				continue
			}
			chains = append(chains, Chain{
				Name:     "Credential Exfiltration",
				Severity: "critical",
				Description: "A sensitive credential or key file was read, then an outbound " +
					"network call was made within " + formatWindow(ev.Timestamp, ev2.Timestamp) +
					". This is the signature of a successful prompt-injection exfiltration attack.",
				MITRETactic: "Exfiltration",
				MITRERef:    "TA0010",
				WindowStart: ev.Timestamp,
				WindowEnd:   ev2.Timestamp,
				Client:      ev.Client,
				Server:      ev.Server,
				Steps: []ChainStep{
					{Timestamp: ev.Timestamp, Tool: ev.Tool, Server: ev.Server, RuleIDs: []string{"AT001"}, Detail: "Sensitive file accessed"},
					{Timestamp: ev2.Timestamp, Tool: ev2.Tool, Server: ev2.Server, RuleIDs: []string{"AT002"}, Detail: "Outbound network call made"},
				},
			})
			break
		}
	}
	return chains
}

// detectPersistenceEstablishment finds: shell execution → persistence write
func detectPersistenceEstablishment(events []logparse.Event, idx map[string][]rules.Finding) []Chain {
	var chains []Chain
	n := len(events)
	for i := 0; i < n; i++ {
		ev := events[i]
		if !hasRule(idx[evKey(ev)], "AT003") { // shell command
			continue
		}
		for j := i + 1; j < n; j++ {
			ev2 := events[j]
			if ev2.Timestamp.Sub(ev.Timestamp) > maxWindow {
				break
			}
			if !hasRule(idx[evKey(ev2)], "AT006") && !hasRule(idx[evKey(ev2)], "AT014") {
				continue
			}
			chains = append(chains, Chain{
				Name:     "Persistence Establishment",
				Severity: "critical",
				Description: "Shell command execution followed by a write to a persistence location " +
					"within " + formatWindow(ev.Timestamp, ev2.Timestamp) +
					". This is the attacker's final step: ensuring code runs after reboot.",
				MITRETactic: "Persistence",
				MITRERef:    "TA0003",
				WindowStart: ev.Timestamp,
				WindowEnd:   ev2.Timestamp,
				Client:      ev.Client,
				Server:      ev.Server,
				Steps: []ChainStep{
					{Timestamp: ev.Timestamp, Tool: ev.Tool, Server: ev.Server, RuleIDs: []string{"AT003"}, Detail: "Shell command executed"},
					{Timestamp: ev2.Timestamp, Tool: ev2.Tool, Server: ev2.Server, RuleIDs: []string{"AT006", "AT014"}, Detail: "Wrote to persistence location"},
				},
			})
			break
		}
	}
	return chains
}

// detectReconToCredential finds: mass file enumeration or recon → credential access
func detectReconToCredential(events []logparse.Event, idx map[string][]rules.Finding) []Chain {
	var chains []Chain
	n := len(events)
	for i := 0; i < n; i++ {
		ev := events[i]
		// AT012 = other-user home dir, AT013 = mass file enumeration, AT018 = port scan
		if !hasAnyRule(idx[evKey(ev)], "AT012", "AT013", "AT018") {
			continue
		}
		for j := i + 1; j < n; j++ {
			ev2 := events[j]
			if ev2.Timestamp.Sub(ev.Timestamp) > maxWindow {
				break
			}
			if !hasRule(idx[evKey(ev2)], "AT001") { // credential file access
				continue
			}
			chains = append(chains, Chain{
				Name:     "Reconnaissance to Credential Theft",
				Severity: "high",
				Description: "Filesystem or network reconnaissance was followed by " +
					"sensitive credential file access within " + formatWindow(ev.Timestamp, ev2.Timestamp) +
					". This matches the discovery phase of a targeted exfiltration.",
				MITRETactic: "Discovery → Credential Access",
				MITRERef:    "TA0007 → TA0006",
				WindowStart: ev.Timestamp,
				WindowEnd:   ev2.Timestamp,
				Client:      ev.Client,
				Server:      ev.Server,
				Steps: []ChainStep{
					{Timestamp: ev.Timestamp, Tool: ev.Tool, Server: ev.Server, RuleIDs: []string{"AT013"}, Detail: "Reconnaissance / enumeration"},
					{Timestamp: ev2.Timestamp, Tool: ev2.Tool, Server: ev2.Server, RuleIDs: []string{"AT001"}, Detail: "Credential file accessed"},
				},
			})
			break
		}
	}
	return chains
}

// detectLateralMovementSetup finds: credential read → new MCP server call
// (cross-server data chain — the attacker uses one server to stage and another to exfiltrate)
func detectLateralMovementSetup(events []logparse.Event, idx map[string][]rules.Finding) []Chain {
	var chains []Chain
	n := len(events)
	for i := 0; i < n; i++ {
		ev := events[i]
		if !hasRule(idx[evKey(ev)], "AT001") {
			continue
		}
		for j := i + 1; j < n; j++ {
			ev2 := events[j]
			if ev2.Timestamp.Sub(ev.Timestamp) > maxWindow {
				break
			}
			// Cross-server: different server used after credential read
			if ev2.Server == ev.Server || ev2.Server == "" {
				continue
			}
			if !hasRule(idx[evKey(ev2)], "AT015") && !hasAnyRule(idx[evKey(ev2)], "AT002", "AT017") {
				continue
			}
			chains = append(chains, Chain{
				Name:     "Cross-Server Data Chain",
				Severity: "critical",
				Description: "A credential or sensitive file was read via " + ev.Server +
					", then a different server (" + ev2.Server + ") made an outbound call " +
					"within " + formatWindow(ev.Timestamp, ev2.Timestamp) +
					". The attacker used two servers together to exfiltrate data.",
				MITRETactic: "Exfiltration",
				MITRERef:    "TA0010",
				WindowStart: ev.Timestamp,
				WindowEnd:   ev2.Timestamp,
				Client:      ev.Client,
				Server:      ev.Server + " → " + ev2.Server,
				Steps: []ChainStep{
					{Timestamp: ev.Timestamp, Tool: ev.Tool, Server: ev.Server, RuleIDs: []string{"AT001"}, Detail: "Credential read"},
					{Timestamp: ev2.Timestamp, Tool: ev2.Tool, Server: ev2.Server, RuleIDs: []string{"AT015"}, Detail: "Different server made outbound call"},
				},
			})
			break
		}
	}
	return chains
}

// detectInjectionSignature looks for the classic prompt injection evidence pattern:
// tool calls to a server that wasn't active recently, followed immediately by
// high-risk behavior. This catches the "agent suddenly does something it had no
// reason to do" pattern — the clearest behavioral signature of a successful injection.
func detectInjectionSignature(events []logparse.Event, idx map[string][]rules.Finding) []Chain {
	var chains []Chain
	n := len(events)
	if n < 3 {
		return chains
	}

	// Track server activity for context (what was being used before)
	recentServers := map[string]time.Time{}

	for i := 0; i < n; i++ {
		ev := events[i]
		findings := idx[evKey(ev)]

		// Update server activity
		if ev.Server != "" && !ev.Timestamp.IsZero() {
			recentServers[ev.Server] = ev.Timestamp
		}

		// A high-risk finding on a server that was NOT recently active is suspicious.
		if !hasHighRiskRule(findings) {
			continue
		}
		if ev.Server == "" {
			continue
		}

		// Check if this server was seen in the last 5 minutes before this event
		lastSeen, known := recentServers[ev.Server]
		isNewServer := !known || ev.Timestamp.Sub(lastSeen) > 5*time.Minute

		if !isNewServer {
			continue
		}

		// Look for a second suspicious event from the same unexpected server within the window
		for j := i + 1; j < n; j++ {
			ev2 := events[j]
			if ev2.Timestamp.Sub(ev.Timestamp) > maxWindow {
				break
			}
			if !hasHighRiskRule(idx[evKey(ev2)]) {
				continue
			}
			chains = append(chains, Chain{
				Name:     "Prompt Injection Signature",
				Severity: "high",
				Description: "Server '" + ev.Server + "' became active with high-risk tool calls " +
					"in a context where it had not been recently used. Multiple suspicious " +
					"events followed in rapid succession (" + formatWindow(ev.Timestamp, ev2.Timestamp) +
					"). This behavioral pattern is the primary evidence of a successful prompt injection.",
				MITRETactic: "Initial Access",
				MITRERef:    "AML.T0051",
				WindowStart: ev.Timestamp,
				WindowEnd:   ev2.Timestamp,
				Client:      ev.Client,
				Server:      ev.Server,
				Steps: []ChainStep{
					{Timestamp: ev.Timestamp, Tool: ev.Tool, Server: ev.Server, RuleIDs: ruleIDs(findings), Detail: "First suspicious event — server previously inactive"},
					{Timestamp: ev2.Timestamp, Tool: ev2.Tool, Server: ev2.Server, RuleIDs: ruleIDs(idx[evKey(ev2)]), Detail: "Second suspicious event in rapid succession"},
				},
			})
			break
		}
	}
	return chains
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func evKey(ev logparse.Event) string {
	return ev.Timestamp.Format(time.RFC3339Nano) + "/" + ev.Tool + "/" + ev.Server
}

func hasRule(findings []rules.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func hasAnyRule(findings []rules.Finding, ruleIDs ...string) bool {
	for _, id := range ruleIDs {
		if hasRule(findings, id) {
			return true
		}
	}
	return false
}

func hasHighRiskRule(findings []rules.Finding) bool {
	for _, f := range findings {
		if f.Severity >= rules.SeverityHigh {
			return true
		}
	}
	return false
}

func ruleIDs(findings []rules.Finding) []string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func formatWindow(start, end time.Time) string {
	d := end.Sub(start).Truncate(time.Second)
	if d < time.Second {
		return "< 1s"
	}
	return d.String()
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	}
	return 0
}
