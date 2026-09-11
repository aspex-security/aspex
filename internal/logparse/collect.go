package logparse

import (
	"bufio"
	"fmt"
	"time"
)

// SupportedClients lists every client aspex-trace can read logs from.
var SupportedClients = []string{"claude", "claude-code", "cursor", "windsurf", "cline", "roo-cline"}

// CollectEvents reads and normalizes log events from every requested client
// since the given time. An empty clients slice means all supported clients.
// Returns the events, the clients that had at least one event, and any
// per-directory parse errors (non-fatal - callers usually print them as warnings).
func CollectEvents(clients []string, since time.Time) (events []Event, clientsFound []string, errs []error) {
	if len(clients) == 0 {
		clients = SupportedClients
	}
	for _, cl := range clients {
		var dirs []string
		var parse func(string, time.Time) ([]Event, error)
		switch cl {
		case "claude":
			dirs, parse = ClaudeLogPaths(), ParseClaudeLogsDir
		case "claude-code":
			dirs, parse = ClaudeCodeLogPaths(), ParseClaudeCodeProjectsDir
		case "cursor":
			dirs, parse = CursorLogPaths(), ParseCursorLogsDir
		case "windsurf":
			dirs, parse = WindsurfLogPaths(), ParseWindsurfLogsDir
		case "cline":
			dirs, parse = ClineLogPaths(), ParseClineTasksDir
		case "roo-cline":
			dirs, parse = RooCodeLogPaths(), ParseRooCodeTasksDir
		default:
			errs = append(errs, fmt.Errorf("unknown client %q", cl))
			continue
		}
		found := false
		for _, dir := range dirs {
			evs, err := parse(dir, since)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s logs (%s): %w", cl, dir, err))
				continue
			}
			if len(evs) > 0 {
				found = true
			}
			events = append(events, evs...)
		}
		if found {
			clientsFound = append(clientsFound, cl)
		}
	}
	return events, clientsFound, errs
}

// maxLogLine bounds a single log line. Client logs are one JSON object per
// line; a line far larger than this is malformed or hostile. Reading it whole
// would let one bad line exhaust memory, so the tail past the cap is skipped.
const maxLogLine = 8 << 20 // 8 MiB

// readLineCapped reads one line from r, up to maxLogLine bytes. If a line is
// longer, it returns the capped prefix and discards the rest of that line, so
// parsing continues at the next line instead of growing without bound. The
// returned error matches bufio.Reader.ReadString semantics (io.EOF at end).
func readLineCapped(r *bufio.Reader) (string, error) {
	var b []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(b)+len(chunk) <= maxLogLine {
			b = append(b, chunk...)
		} else if len(b) < maxLogLine {
			b = append(b, chunk[:maxLogLine-len(b)]...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return string(b), err
	}
}
