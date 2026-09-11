package rules

import (
	"strings"

	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/inspect"
)

// checkMCP200WritableAgentState flags a server that can write files the agent
// itself trusts in future sessions: its MCP configuration, its hooks, its
// instruction files (CLAUDE.md, .cursorrules), or its memory. This is a risky
// configuration on its own, independent of whether anything can currently feed
// the agent untrusted content. The cross-server composition (external content
// plus this write) is reported separately as attack path AP003; this rule is
// the per-server half that always applies.
//
// Writes that cause code to run at the next session start (MCP config, hooks,
// shell startup) are HIGH; instruction and memory files are MEDIUM.
func checkMCP200WritableAgentState(srv *inspect.Server) []Finding {
	sc := attackpath.DetectServer(srv, attackpath.Options{})
	if len(sc.StateWrites) == 0 {
		return nil
	}
	// Severity is driven by blast radius, not merely by "can write":
	//   global + executes  -> HIGH   (rewrites ~/.claude.json etc.; every session)
	//   global             -> MEDIUM (global instructions/memory)
	//   project + executes -> MEDIUM (this repo's .mcp.json; you opened this repo)
	//   project            -> LOW    (this repo's CLAUDE.md/.cursorrules)
	// Writing files inside a project you already work in is expected; the loud
	// case is a server that can reach user-global agent configuration.
	var globalExec, global, projectExec, project bool
	kinds := map[string]bool{}
	var examples []string
	for _, t := range sc.StateWrites {
		kinds[t.Kind] = true
		switch {
		case t.Global && t.Executes:
			globalExec = true
		case t.Global:
			global = true
		case t.Executes:
			projectExec = true
		default:
			project = true
		}
		if t.Global && len(examples) < 3 { // prefer global paths in the example list
			examples = append([]string{t.Path}, examples...)
		} else if len(examples) < 3 {
			examples = append(examples, t.Path)
		}
	}

	var sev Severity
	var impact string
	switch {
	case globalExec:
		sev, impact = SeverityHigh, "The reachable files include user-global MCP configuration, hooks, or shell startup that run code at the next session start of any project, without any further prompt."
	case global:
		sev, impact = SeverityMedium, "The reachable files include user-global instruction or memory files trusted by every future session."
	case projectExec:
		sev, impact = SeverityMedium, "This repository's own .mcp.json or hooks are writable; a change would load new servers or run hooks the next time the repo is opened."
	case project:
		sev, impact = SeverityLow, "This repository's instruction files (CLAUDE.md, .cursorrules) are writable; a change would steer future sessions in this repo."
	default:
		return nil
	}
	if len(examples) > 3 {
		examples = examples[:3]
	}
	kindList := make([]string, 0, len(kinds))
	for k := range kinds {
		kindList = append(kindList, k)
	}
	var ev []Evidence
	for _, t := range sc.StateWrites {
		if len(ev) < 4 {
			ex := ""
			if t.Executes {
				ex = ", runs at next session start"
			}
			ev = append(ev, Observed("writable root reaches "+t.Path+" ("+t.Kind+ex+")"))
		}
	}
	ev = append(ev, Inferred(impact))
	return []Finding{{
		Evidence: ev,
		RuleID:   "MCP200",
		Name:     "Server can write agent-trusted state",
		Severity: sev,
		Detail: "Write access reaches agent state (" + strings.Join(kindList, ", ") + "), e.g. " +
			strings.Join(examples, ", ") + ". " + impact,
		Fix:     "Scope this server to a directory that holds no MCP config, hooks, instruction, or memory files; keep those under version control so changes are visible.",
		Mapping: "OWASP LLM06, MITRE ATLAS AML.T0051, CWE-732",
	}}
}
