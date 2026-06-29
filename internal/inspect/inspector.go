package inspect

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/mcpclient"
)

// knownRuntimes is the set of executable names that are safe to look up via PATH.
var knownRuntimes = map[string]bool{
	"npx":     true,
	"node":    true,
	"python3": true,
	"python":  true,
	"uvx":     true,
	"deno":    true,
	"bun":     true,
}

// Options controls how inspection is performed.
type Options struct {
	// NoExec skips launching stdio servers; returns static-only results.
	NoExec bool
}

// InspectServer inspects a single server entry and returns a populated Server model.
func InspectServer(ctx context.Context, entry discover.ServerEntry, opts Options) *Server {
	srv := &Server{Entry: entry}

	if entry.URL != "" {
		result, err := mcpclient.InspectHTTP(ctx, entry.URL)
		if err != nil {
			srv.InspectErr = err
			srv.StaticOnly = true
			return srv
		}
		srv.Info = result.ServerInfo
		srv.Tools = result.Tools
		srv.Resources = result.Resources
		srv.Prompts = result.Prompts
		return srv
	}

	if opts.NoExec || entry.Command == "" {
		srv.StaticOnly = true
		return srv
	}

	cmd := entry.Command
	if !filepath.IsAbs(cmd) && !knownRuntimes[cmd] {
		srv.InspectErr = fmt.Errorf("command %q must be an absolute path or a known runtime (npx, node, python3, uvx)", cmd)
		srv.StaticOnly = true
		return srv
	}
	result, err := mcpclient.InspectStdio(ctx, cmd, entry.Args)
	if err != nil {
		srv.InspectErr = err
		srv.StaticOnly = true
		return srv
	}

	srv.Info = result.ServerInfo
	srv.Tools = result.Tools
	srv.Resources = result.Resources
	srv.Prompts = result.Prompts
	return srv
}
