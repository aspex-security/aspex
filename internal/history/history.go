package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Record holds the parsed summary of a previous scan log.
type Record struct {
	Timestamp time.Time
	Score     int
	Band      string
	Critical  int
	High      int
	Medium    int
	Path      string
}

// jsonOverallScore mirrors the relevant fields of score.OverallScore.
type jsonOverallScore struct {
	Score    int    `json:"Score"`
	Band     string `json:"Band"`
	Critical int    `json:"Critical"`
	High     int    `json:"High"`
	Medium   int    `json:"Medium"`
}

// jsonScanOutput mirrors the relevant fields of report.JSONScanOutput.
type jsonScanOutput struct {
	Version string           `json:"Version"`
	Overall jsonOverallScore `json:"Overall"`
}

// scanDir returns the path to the aspex scans directory.
func scanDir() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, "aspex", "scans"), nil
}

// LoadPrevious returns the most-recent scan log that is NOT currentPath.
// Returns nil, nil if no prior log exists.
func LoadPrevious(currentPath string) (*Record, error) {
	dir, err := scanDir()
	if err != nil {
		return nil, err
	}

	entries, err := filepath.Glob(filepath.Join(dir, "scan-*.json"))
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	// Sort descending so the most recent is first.
	sort.Sort(sort.Reverse(sort.StringSlice(entries)))

	absCurrentPath, _ := filepath.Abs(currentPath)

	for _, p := range entries {
		absP, _ := filepath.Abs(p)
		if absP == absCurrentPath {
			continue
		}

		rec, err := parseRecord(p)
		if err != nil {
			// Skip unparseable files.
			continue
		}
		return rec, nil
	}

	return nil, nil
}

// parseRecord reads a scan JSON file and returns a Record.
func parseRecord(path string) (*Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var out jsonScanOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	// Extract timestamp from filename: scan-YYYYMMDD-HHMMSS.json
	base := filepath.Base(path)
	var ts time.Time
	if len(base) >= len("scan-20060102-150405.json") {
		// base is e.g. "scan-20060102-150405.json"
		timeStr := base[len("scan-"):len(base)-len(".json")]
		ts, _ = time.ParseInLocation("20060102-150405", timeStr, time.Local)
	}

	return &Record{
		Timestamp: ts,
		Score:     out.Overall.Score,
		Band:      out.Overall.Band,
		Critical:  out.Overall.Critical,
		High:      out.Overall.High,
		Medium:    out.Overall.Medium,
		Path:      path,
	}, nil
}

// Delta returns a human-readable delta string like "+12", "-5", or "="
// given a previous record and the current score. Returns "" if prev is nil.
func Delta(prev *Record, current int) string {
	if prev == nil {
		return ""
	}
	d := current - prev.Score
	switch {
	case d > 0:
		return fmt.Sprintf("+%d", d)
	case d < 0:
		return fmt.Sprintf("%d", d)
	default:
		return "="
	}
}

// IsFirstRun returns true if there are no scan logs at all (currentPath excluded).
func IsFirstRun(currentPath string) bool {
	dir, err := scanDir()
	if err != nil {
		return true
	}

	entries, err := filepath.Glob(filepath.Join(dir, "scan-*.json"))
	if err != nil || len(entries) == 0 {
		return true
	}

	absCurrentPath, _ := filepath.Abs(currentPath)
	for _, p := range entries {
		absP, _ := filepath.Abs(p)
		if absP != absCurrentPath {
			return false
		}
	}
	return true
}
