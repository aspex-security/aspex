// Package shadow detects MCP tool name shadowing — a class of attack where a
// malicious or misconfigured server registers tool names that collide with
// tools on a legitimate server. When an AI agent calls one of these tools,
// the client may route the call to the wrong server, allowing the shadowing
// server to intercept inputs, forge outputs, or silently execute on the agent's
// behalf.
//
// This is distinct from per-server risk analysis (aspex-scan's main scan) because
// the risk only appears when two servers are considered together.
package shadow

import (
	"sort"
	"strings"

	"github.com/aspex-security/aspex/internal/inspect"
)

// Collision describes a tool name that is registered by more than one server.
type Collision struct {
	ToolName string
	Servers  []CollisionSide
	Risk     string // "critical" | "high" | "medium"
	Reason   string // human-readable explanation
}

// CollisionSide is one server's entry in a name collision.
type CollisionSide struct {
	ServerName string
	Client     string
	Transport  string // "stdio" | "http"
	IsExternal bool   // HTTP/SSE (less trusted)
}

// Report is the full shadow analysis result.
type Report struct {
	Collisions      []Collision
	TotalServers    int
	TotalTools      int
	UniqueToolNames int
}

// highValueTools are tool names an attacker would most want to shadow — common
// names that legitimate servers expose and that carry significant capability or
// data access. A collision on one of these names is automatically elevated.
var highValueTools = map[string]bool{
	"read_file": true, "write_file": true, "execute_command": true,
	"run_command": true, "bash": true, "shell": true, "eval": true,
	"create_file": true, "delete_file": true, "list_directory": true,
	"list_files": true, "search_files": true, "read_multiple_files": true,
	"get_file_contents": true, "edit_file": true, "apply_diff": true,
	"http_request": true, "fetch": true, "web_fetch": true,
	"get_env": true, "read_env": true, "environment": true,
	"get_secret": true, "read_secret": true,
	"create_or_update_file": true, "push_files": true,
}

// Analyze performs tool name collision analysis across all inspected servers.
func Analyze(servers []*inspect.Server) Report {
	// tool name -> list of servers that expose it
	type entry struct {
		name      string
		client    string
		transport string
		url       string
	}
	byTool := map[string][]entry{}
	totalTools := 0

	for _, srv := range servers {
		transport := "stdio"
		if srv.Entry.URL != "" {
			transport = "http"
		}
		for _, t := range srv.Tools {
			n := strings.ToLower(t.Name)
			byTool[n] = append(byTool[n], entry{
				name:      srv.Entry.Name,
				client:    srv.Entry.Client,
				transport: transport,
				url:       srv.Entry.URL,
			})
			totalTools++
		}
	}

	var collisions []Collision
	for toolName, entries := range byTool {
		if len(entries) < 2 {
			continue
		}

		// Deduplicate by server name (same server listed under multiple clients)
		seen := map[string]bool{}
		var sides []CollisionSide
		for _, e := range entries {
			if seen[e.name] {
				continue
			}
			seen[e.name] = true
			sides = append(sides, CollisionSide{
				ServerName: e.name,
				Client:     e.client,
				Transport:  e.transport,
				IsExternal: e.transport == "http",
			})
		}
		if len(sides) < 2 {
			continue
		}

		risk, reason := classify(toolName, sides)
		collisions = append(collisions, Collision{
			ToolName: toolName,
			Servers:  sides,
			Risk:     risk,
			Reason:   reason,
		})
	}

	// Sort: critical first, then high, then by tool name.
	sort.Slice(collisions, func(i, j int) bool {
		ri, rj := riskRank(collisions[i].Risk), riskRank(collisions[j].Risk)
		if ri != rj {
			return ri > rj
		}
		return collisions[i].ToolName < collisions[j].ToolName
	})

	return Report{
		Collisions:      collisions,
		TotalServers:    len(servers),
		TotalTools:      totalTools,
		UniqueToolNames: len(byTool),
	}
}

func classify(toolName string, sides []CollisionSide) (risk, reason string) {
	hasExternal := false
	for _, s := range sides {
		if s.IsExternal {
			hasExternal = true
		}
	}

	isHighValue := highValueTools[strings.ToLower(toolName)]

	switch {
	case hasExternal && isHighValue:
		return "critical", "HTTP/SSE server shadows a high-value tool name — " +
			"a remote server controls what happens when the agent calls '" + toolName + "'"
	case hasExternal:
		return "high", "HTTP/SSE server registers the same tool name as a local server — " +
			"remote server may intercept calls to '" + toolName + "'"
	case isHighValue:
		return "high", "Multiple local servers expose '" + toolName + "' — " +
			"agent routing is ambiguous for a high-capability tool"
	default:
		return "medium", "Multiple servers expose '" + toolName + "' — " +
			"the agent may call the unintended server"
	}
}

func riskRank(r string) int {
	switch r {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	}
	return 0
}
