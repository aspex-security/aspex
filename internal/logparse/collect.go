package logparse

import (
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
