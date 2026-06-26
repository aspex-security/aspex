package logparse

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// WindsurfLogPaths returns MCP log paths for Windsurf on the current OS.
// Windsurf is an Electron-based VS Code fork; it writes logs under its app-support dir.
func WindsurfLogPaths() []string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		return []string{
			filepath.Join(appdata, "Windsurf", "logs"),
		}
	}
	if runtime.GOOS == "darwin" {
		return []string{
			filepath.Join(home, "Library", "Application Support", "Windsurf", "logs"),
			filepath.Join(home, ".codeium", "windsurf", "logs"),
		}
	}
	return []string{
		filepath.Join(home, ".codeium", "windsurf", "logs"),
	}
}

// ParseWindsurfLogsDir walks the Windsurf log directory tree and returns parsed MCP events.
// Windsurf shares the same structured JSON log format as Cursor.
func ParseWindsurfLogsDir(dir string, since time.Time) ([]Event, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var events []Event
	for _, e := range entries {
		if e.IsDir() {
			// Recurse one level — Windsurf sessions are in dated subdirectories.
			subDir := filepath.Join(dir, e.Name())
			subEvs, _ := ParseWindsurfLogsDir(subDir, since)
			events = append(events, subEvs...)
			continue
		}
		name := e.Name()
		if !strings.Contains(name, "mcp") || !strings.HasSuffix(name, ".log") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		evs, _ := ParseWindsurfLogReader(f, since)
		f.Close()
		events = append(events, evs...)
	}
	return events, nil
}

// ParseWindsurfLogReader parses Windsurf MCP logs from an io.Reader.
// The format is identical to Cursor's structured JSON log lines.
func ParseWindsurfLogReader(r io.Reader, since time.Time) ([]Event, error) {
	var events []Event
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		// Reuse the Cursor line parser — same JSON schema.
		ev, ok := parseCursorLine(line, since)
		if ok {
			ev.Client = "windsurf"
			events = append(events, ev)
		}
	}
	return events, scanner.Err()
}
