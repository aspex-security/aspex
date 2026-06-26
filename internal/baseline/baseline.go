// Package baseline implements behavioral baselining for MCP agent activity.
// It learns normal behavior from a set of events and detects deviations in new events.
package baseline

import (
	"encoding/json"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/logparse"
)

// ServerProfile captures learned normal behavior for one MCP server.
type ServerProfile struct {
	ServerName    string         // MCP server name
	ToolFrequency map[string]int // tool name -> call count in baseline period
	ActiveHours   [24]int        // call counts per hour of day
	AvgArgSize    float64        // average arg size in bytes
	MaxArgSize    int            // max arg size seen
	PathPrefixes  []string       // common file path prefixes accessed
	OutboundHosts []string       // outbound hosts seen (for network tools)
	SampleCount   int            // total events in baseline
}

// Baseline holds profiles for all servers observed in a learn period.
type Baseline struct {
	CreatedAt  string                   // RFC3339 timestamp
	ClientName string
	Profiles   map[string]ServerProfile // keyed by server name
}

// Learn builds a Baseline from a set of events.
func Learn(client string, events []logparse.Event) *Baseline {
	b := &Baseline{
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		ClientName: client,
		Profiles:   make(map[string]ServerProfile),
	}

	// Intermediate accumulators keyed by server name.
	type accumulator struct {
		toolFreq      map[string]int
		activeHours   [24]int
		totalArgSize  int
		maxArgSize    int
		sampleCount   int
		pathPrefixSet map[string]bool
		hostSet       map[string]bool
	}
	accs := make(map[string]*accumulator)

	getAcc := func(server string) *accumulator {
		if a, ok := accs[server]; ok {
			return a
		}
		a := &accumulator{
			toolFreq:      make(map[string]int),
			pathPrefixSet: make(map[string]bool),
			hostSet:       make(map[string]bool),
		}
		accs[server] = a
		return a
	}

	for _, ev := range events {
		a := getAcc(ev.Server)
		a.sampleCount++

		// Hour of day.
		if !ev.Timestamp.IsZero() {
			h := ev.Timestamp.Local().Hour()
			a.activeHours[h]++
		}

		// Tool frequency.
		if ev.Event == logparse.EventToolsCall && ev.Tool != "" {
			a.toolFreq[ev.Tool]++
		}

		// Arg size, paths, hosts.
		argSize := 0
		for _, v := range ev.Args {
			argSize += len(v)
			if isFilePath(v) {
				prefix := pathPrefix(v)
				if prefix != "" {
					a.pathPrefixSet[prefix] = true
				}
			}
			if h := extractHost(v); h != "" {
				a.hostSet[h] = true
			}
		}
		a.totalArgSize += argSize
		if argSize > a.maxArgSize {
			a.maxArgSize = argSize
		}
	}

	for server, a := range accs {
		avg := 0.0
		if a.sampleCount > 0 {
			avg = math.Round(float64(a.totalArgSize)/float64(a.sampleCount)*100) / 100
		}

		paths := make([]string, 0, len(a.pathPrefixSet))
		for p := range a.pathPrefixSet {
			paths = append(paths, p)
		}

		hosts := make([]string, 0, len(a.hostSet))
		for h := range a.hostSet {
			hosts = append(hosts, h)
		}

		p := ServerProfile{
			ServerName:    server,
			ToolFrequency: a.toolFreq,
			ActiveHours:   a.activeHours,
			AvgArgSize:    avg,
			MaxArgSize:    a.maxArgSize,
			PathPrefixes:  paths,
			OutboundHosts: hosts,
			SampleCount:   a.sampleCount,
		}
		b.Profiles[server] = p
	}

	return b
}

// Save writes the baseline as JSON to the given path.
func Save(b *Baseline, path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Load reads a baseline from a JSON file.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// Deviation describes one anomaly vs baseline.
type Deviation struct {
	ServerName string
	Kind       string // "new-tool", "off-hours", "oversized-args", "new-host", "new-path"
	Detail     string
	Severity   string // "high", "medium", "low"
}

// Compare checks events against a baseline and returns deviations.
func Compare(b *Baseline, events []logparse.Event) []Deviation {
	var deviations []Deviation

	for _, ev := range events {
		prof, known := b.Profiles[ev.Server]

		// new-tool: tool call for a tool not seen in baseline.
		if ev.Event == logparse.EventToolsCall && ev.Tool != "" {
			if !known || prof.ToolFrequency[ev.Tool] == 0 {
				deviations = append(deviations, Deviation{
					ServerName: ev.Server,
					Kind:       "new-tool",
					Detail:     "Tool '" + ev.Tool + "' was not seen during baseline for server '" + ev.Server + "'",
					Severity:   "high",
				})
			}
		}

		if !known {
			continue
		}

		// off-hours: call at an hour where ActiveHours[hour] == 0 in baseline.
		if !ev.Timestamp.IsZero() {
			h := ev.Timestamp.Local().Hour()
			if prof.ActiveHours[h] == 0 {
				deviations = append(deviations, Deviation{
					ServerName: ev.Server,
					Kind:       "off-hours",
					Detail:     "Activity at hour " + itoa(h) + " was not seen during baseline for server '" + ev.Server + "'",
					Severity:   "low",
				})
			}
		}

		// oversized-args: arg size > baseline MaxArgSize * 2.
		argSize := 0
		for _, v := range ev.Args {
			argSize += len(v)
		}
		if prof.MaxArgSize > 0 && argSize > prof.MaxArgSize*2 {
			deviations = append(deviations, Deviation{
				ServerName: ev.Server,
				Kind:       "oversized-args",
				Detail:     "Arg size " + itoa(argSize) + " bytes exceeds 2x baseline max of " + itoa(prof.MaxArgSize) + " bytes for server '" + ev.Server + "'",
				Severity:   "medium",
			})
		}

		// new-host and new-path: check arg values.
		for _, v := range ev.Args {
			if h := extractHost(v); h != "" {
				if !containsString(prof.OutboundHosts, h) {
					deviations = append(deviations, Deviation{
						ServerName: ev.Server,
						Kind:       "new-host",
						Detail:     "Outbound host '" + h + "' was not seen during baseline for server '" + ev.Server + "'",
						Severity:   "high",
					})
				}
			}
			if isFilePath(v) {
				prefix := pathPrefix(v)
				if prefix != "" && !matchesAnyPrefix(prof.PathPrefixes, prefix) {
					deviations = append(deviations, Deviation{
						ServerName: ev.Server,
						Kind:       "new-path",
						Detail:     "File path prefix '" + prefix + "' was not seen during baseline for server '" + ev.Server + "'",
						Severity:   "medium",
					})
				}
			}
		}
	}

	return deviations
}

// isFilePath returns true if the value looks like a file path.
func isFilePath(v string) bool {
	return strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~")
}

// pathPrefix extracts the top two directory components as the prefix.
func pathPrefix(v string) string {
	// Expand ~ to literal for prefix matching purposes.
	clean := filepath.Clean(v)
	parts := strings.Split(clean, string(filepath.Separator))
	// Keep up to 3 parts for a meaningful prefix (e.g. /Users/alice or /home/bob/projects).
	end := 3
	if len(parts) < end {
		end = len(parts)
	}
	prefix := strings.Join(parts[:end], string(filepath.Separator))
	if prefix == "" || prefix == "." {
		return ""
	}
	return prefix
}

// extractHost parses a URL-like value and returns its hostname.
func extractHost(v string) string {
	if !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// containsString returns true if slice contains s.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// matchesAnyPrefix returns true if prefix matches or is a sub-prefix of any baseline prefix.
func matchesAnyPrefix(prefixes []string, prefix string) bool {
	for _, p := range prefixes {
		if p == prefix || strings.HasPrefix(prefix, p) {
			return true
		}
	}
	return false
}

// itoa converts an int to a string without fmt.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
