// Package phantom detects servers that return different tool lists on successive
// calls — the behavioral signature of a "clean-face" attack.
//
// A legitimate MCP server's tool list is deterministic and stable. A server that
// shows a different set of tools (or different tool descriptions) on a second
// inspection is either:
//
//   - Fingerprinting callers and serving different content to security scanners
//     vs. AI clients (the "clean-face" / selective-targeting attack)
//   - Non-deterministic in a way that makes it unsafe to trust
//   - Serving different tool sets to different sessions (active compromise)
//
// This check calls tools/list twice with a short delay and compares the results.
// Any change — added tools, removed tools, altered descriptions — is a finding.
package phantom

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/mcpclient"
)

// Change describes a single difference between two tool list responses.
type Change struct {
	Kind        string // "added" | "removed" | "description_changed" | "schema_changed"
	ToolName    string
	Before      string // previous value (description or schema fragment)
	After       string // new value
	Severity    string // "critical" | "high" | "medium"
	Explanation string
}

// Result is the full phantom analysis for one server.
type Result struct {
	ServerName   string
	Client       string
	Transport    string
	Changes      []Change
	FirstCall    []mcpclient.Tool
	SecondCall   []mcpclient.Tool
	IntervalMS   int64
	Err          error // if inspection failed on one of the calls
}

// Clean returns true if no changes were detected.
func (r *Result) Clean() bool { return len(r.Changes) == 0 && r.Err == nil }

// Analyze inspects a server twice and returns any differences found.
// interval is the pause between the two calls.
func Analyze(ctx context.Context, entry discover.ServerEntry, interval time.Duration) *Result {
	res := &Result{
		ServerName:  entry.Name,
		Client:      entry.Client,
		IntervalMS:  interval.Milliseconds(),
	}

	var err1, err2 error

	if entry.URL != "" {
		res.Transport = "http"
		r1, e1 := mcpclient.InspectHTTP(ctx, entry.URL)
		err1 = e1
		if e1 == nil {
			res.FirstCall = r1.Tools
		}
		// Brief pause between calls.
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			res.Err = ctx.Err()
			return res
		}
		r2, e2 := mcpclient.InspectHTTP(ctx, entry.URL)
		err2 = e2
		if e2 == nil {
			res.SecondCall = r2.Tools
		}
	} else {
		res.Transport = "stdio"
		r1, e1 := mcpclient.InspectStdio(ctx, entry.Command, entry.Args)
		err1 = e1
		if e1 == nil {
			res.FirstCall = r1.Tools
		}
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			res.Err = ctx.Err()
			return res
		}
		r2, e2 := mcpclient.InspectStdio(ctx, entry.Command, entry.Args)
		err2 = e2
		if e2 == nil {
			res.SecondCall = r2.Tools
		}
	}

	if err1 != nil || err2 != nil {
		// Only flag if the second call fails after the first succeeded — the
		// server became unavailable between calls, which is itself suspicious.
		if err1 == nil && err2 != nil {
			res.Err = fmt.Errorf("server unavailable on second call: %w", err2)
		}
		return res
	}

	res.Changes = diff(res.FirstCall, res.SecondCall)
	return res
}

// diff compares two tool lists and returns all detected changes.
func diff(first, second []mcpclient.Tool) []Change {
	byName := func(tools []mcpclient.Tool) map[string]mcpclient.Tool {
		m := make(map[string]mcpclient.Tool, len(tools))
		for _, t := range tools {
			m[strings.ToLower(t.Name)] = t
		}
		return m
	}

	firstMap := byName(first)
	secondMap := byName(second)

	var changes []Change

	// Tools removed on second call (hidden from first caller).
	for name, t := range firstMap {
		if _, ok := secondMap[name]; !ok {
			changes = append(changes, Change{
				Kind:     "removed",
				ToolName: t.Name,
				Before:   t.Description,
				Severity: "critical",
				Explanation: "Tool '" + t.Name + "' was present on the first tools/list call " +
					"but absent on the second. The server may be serving different tool " +
					"sets to different callers or connections.",
			})
		}
	}

	// Tools added on second call (withheld from first caller).
	for name, t := range secondMap {
		if _, ok := firstMap[name]; !ok {
			changes = append(changes, Change{
				Kind:     "added",
				ToolName: t.Name,
				After:    t.Description,
				Severity: "critical",
				Explanation: "Tool '" + t.Name + "' appeared on the second tools/list call " +
					"but was not present on the first. The server may be fingerprinting " +
					"callers and withholding tools from security scanners.",
			})
		}
	}

	// Description or schema changes between calls.
	for name, t1 := range firstMap {
		t2, ok := secondMap[name]
		if !ok {
			continue
		}
		if t1.Description != t2.Description {
			severity := "high"
			// If the new description adds injection-like language, escalate.
			if containsInjectionSignal(t2.Description) {
				severity = "critical"
			}
			before, after := truncate(t1.Description, 120), truncate(t2.Description, 120)
			changes = append(changes, Change{
				Kind:     "description_changed",
				ToolName: t1.Name,
				Before:   before,
				After:    after,
				Severity: severity,
				Explanation: "Tool '" + t1.Name + "' description changed between calls. " +
					"Legitimate servers do not change descriptions dynamically. " +
					"This may indicate targeted content injection.",
			})
		}
		s1, s2 := string(t1.InputSchema), string(t2.InputSchema)
		if s1 != s2 && s1 != "" && s2 != "" {
			changes = append(changes, Change{
				Kind:        "schema_changed",
				ToolName:    t1.Name,
				Before:      truncate(s1, 80),
				After:       truncate(s2, 80),
				Severity:    "high",
				Explanation: "Tool '" + t1.Name + "' input schema changed between calls.",
			})
		}
	}

	// Sort: critical first, then by tool name.
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Severity != changes[j].Severity {
			return severityRank(changes[i].Severity) > severityRank(changes[j].Severity)
		}
		return changes[i].ToolName < changes[j].ToolName
	})

	return changes
}

func containsInjectionSignal(s string) bool {
	lower := strings.ToLower(s)
	signals := []string{
		"ignore previous", "disregard", "do not tell", "do not mention",
		"always call", "must call", "you must", "always use", "secretly",
		"without telling", "hidden instruction", "override", "jailbreak",
	}
	for _, sig := range signals {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
