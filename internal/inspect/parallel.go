package inspect

import (
	"context"
	"sync"

	"github.com/aspex-security/aspex/internal/discover"
)

// DefaultConcurrency bounds how many servers are inspected at once. Each
// inspection may launch a subprocess or open an HTTP connection with a 15s
// timeout, so inspecting sequentially made a scan take the SUM of timeouts;
// with a pool it takes roughly the slowest single server.
const DefaultConcurrency = 8

// InspectAll inspects every entry concurrently with a bounded worker pool and
// returns results in the same order as entries. progress, if non-nil, is
// called as each server starts and is serialized so callers need no locking.
func InspectAll(ctx context.Context, entries []discover.ServerEntry, opts Options, progress func(name string)) []*Server {
	n := opts.Concurrency
	if n <= 0 {
		n = DefaultConcurrency
	}
	if n > len(entries) {
		n = len(entries)
	}
	results := make([]*Server, len(entries))
	if len(entries) == 0 {
		return results
	}

	var progressMu sync.Mutex
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, entry := range entries {
		wg.Add(1)
		go func(i int, entry discover.ServerEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = InspectServer(ctx, entry, opts)
			// Report on completion, not on start: with parallel workers a
			// start-of-work callback would show a misleading count and name.
			if progress != nil {
				progressMu.Lock()
				progress(entry.Name)
				progressMu.Unlock()
			}
		}(i, entry)
	}
	wg.Wait()
	return results
}
