// Package inspect defines the normalized model for inspected MCP servers and their tools.
package inspect

import (
	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/mcpclient"
)

// Server holds everything known about one MCP server after inspection.
type Server struct {
	Entry   discover.ServerEntry
	Info    mcpclient.ServerInfo
	Tools   []mcpclient.Tool
	Resources []mcpclient.Resource
	Prompts []mcpclient.Prompt

	// Set if inspection failed.
	InspectErr error
	// StaticOnly is true when the server was analyzed without launching it.
	StaticOnly bool
}

// ToolCount returns the number of tools exposed by this server.
func (s *Server) ToolCount() int { return len(s.Tools) }
