// Package watch reports changes to MCP client config files and triggers
// rescans. It uses filesystem events (fsnotify) where the OS provides them
// and falls back to polling when a path cannot be watched, so a config that
// lives on a network mount or an unsupported filesystem is still covered.
package watch

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/aspex-security/aspex/internal/discover"
)

type fileState struct {
	mtime time.Time
	size  int64
}

// ConfigWatcher watches MCP client config files for changes.
type ConfigWatcher struct {
	paths    []string
	poll     time.Duration
	debounce time.Duration
}

// New creates a watcher. interval is the polling period for the fallback
// and the debounce window for bursts of events (editors write files several
// times per save).
func New(paths []string, interval time.Duration) *ConfigWatcher {
	return &ConfigWatcher{paths: paths, poll: interval, debounce: 300 * time.Millisecond}
}

// Watch calls onChange with the path whenever a watched file's content may
// have changed. It blocks until ctx is cancelled. Events are debounced and
// confirmed against mtime+size so a no-op write does not trigger a rescan.
func (w *ConfigWatcher) Watch(ctx context.Context, onChange func(path string)) {
	states := make(map[string]fileState)
	for _, p := range w.paths {
		if info, err := os.Stat(p); err == nil {
			states[p] = fileState{info.ModTime(), info.Size()}
		}
	}
	changed := func(p string) bool {
		info, err := os.Stat(p)
		if err != nil {
			_, had := states[p]
			delete(states, p)
			return had // deletion is a change
		}
		cur := fileState{info.ModTime(), info.Size()}
		prev, seen := states[p]
		if !seen || cur != prev {
			states[p] = cur
			return true
		}
		return false
	}

	watched := map[string]bool{}
	fw, err := fsnotify.NewWatcher()
	if err == nil {
		defer fw.Close()
		// Watch the parent directory: editors replace files by rename, which
		// a watch on the file itself would lose.
		for _, p := range w.paths {
			dir := filepath.Dir(p)
			if !watched[dir] {
				if fw.Add(dir) == nil {
					watched[dir] = true
				}
			}
		}
	}
	isWatched := func(p string) bool { return watched[filepath.Dir(p)] }

	pending := map[string]bool{}
	var timer *time.Timer
	fire := make(chan struct{}, 1)
	schedule := func(p string) {
		pending[p] = true
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(w.debounce, func() {
			select {
			case fire <- struct{}{}:
			default:
			}
		})
	}
	want := map[string]bool{}
	for _, p := range w.paths {
		want[filepath.Clean(p)] = true
	}

	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()
	var events <-chan fsnotify.Event
	var errs <-chan error
	if fw != nil {
		events, errs = fw.Events, fw.Errors
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if want[filepath.Clean(ev.Name)] {
				schedule(filepath.Clean(ev.Name))
			}
		case <-errs:
		case <-fire:
			for p := range pending {
				delete(pending, p)
				if changed(p) {
					onChange(p)
				}
			}
		case <-ticker.C:
			// Fallback for paths whose directory could not be watched.
			for _, p := range w.paths {
				if !isWatched(p) && changed(p) {
					onChange(p)
				}
			}
		}
	}
}

// ConfigPaths returns all MCP client config paths that currently exist on disk.
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
