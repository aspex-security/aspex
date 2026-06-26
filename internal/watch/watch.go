// Package watch polls MCP client config files for changes and triggers rescans.
package watch

import (
	"context"
	"os"
	"time"

	"github.com/aspex-security/aspex/internal/discover"
)

// fileState holds the last known mtime and size for a file.
type fileState struct {
	mtime time.Time
	size  int64
}

// ConfigWatcher watches MCP client config files for changes and triggers rescans.
type ConfigWatcher struct {
	paths    []string
	poll     time.Duration
	mtimes   map[string]time.Time
}

// New creates a watcher for the given file paths, polling every interval.
func New(paths []string, interval time.Duration) *ConfigWatcher {
	return &ConfigWatcher{
		paths:  paths,
		poll:   interval,
		mtimes: make(map[string]time.Time),
	}
}

// Watch calls onChange whenever any watched file changes (mtime or size change).
// It blocks until ctx is cancelled.
// onChange receives the path that changed.
func (w *ConfigWatcher) Watch(ctx context.Context, onChange func(path string)) {
	states := make(map[string]fileState)

	// Seed initial state.
	for _, p := range w.paths {
		if info, err := os.Stat(p); err == nil {
			states[p] = fileState{mtime: info.ModTime(), size: info.Size()}
		}
	}

	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, p := range w.paths {
				info, err := os.Stat(p)
				if err != nil {
					// File does not exist; clear any recorded state.
					delete(states, p)
					continue
				}
				cur := fileState{mtime: info.ModTime(), size: info.Size()}
				prev, seen := states[p]
				if !seen || cur.mtime != prev.mtime || cur.size != prev.size {
					states[p] = cur
					onChange(p)
				}
			}
		}
	}
}

// ConfigPaths returns all MCP client config paths that currently exist on disk.
// It uses discover.DiscoverAll to find paths; files that exist but contain no
// configured servers are also included via the error list (which records every
// path that was attempted).
func ConfigPaths(clients []string) []string {
	var existing []string
	seen := make(map[string]bool)

	entries, errs := discover.DiscoverAll(clients)

	for _, e := range entries {
		if e.ConfigPath != "" && !seen[e.ConfigPath] {
			seen[e.ConfigPath] = true
			existing = append(existing, e.ConfigPath)
		}
	}

	// errs records paths that were attempted but failed to parse.
	// Include them if the file actually exists on disk.
	for _, de := range errs {
		if de.Path != "" && !seen[de.Path] {
			if _, err := os.Stat(de.Path); err == nil {
				seen[de.Path] = true
				existing = append(existing, de.Path)
			}
		}
	}

	return existing
}
