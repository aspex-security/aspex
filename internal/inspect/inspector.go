package inspect

import (
	"context"

	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/mcpclient"
)

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
