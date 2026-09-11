package history

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/agentenv"
)

// Environment snapshots: one lockfile-shaped file per scan under the user
// cache, so `aspex-scan history` can show how capabilities, attack paths and
// blast radius moved over time. Snapshots never contain secret values (they
// are agentenv lockfiles) and are deduplicated: a scan that produces the
// same environment as the latest snapshot writes nothing.

// Snapshot is one recorded environment.
type Snapshot struct {
	Time time.Time
	Path string
	Env  agentenv.Environment
}

func envDir() (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cacheDir, "aspex", "env"), nil
}

// SaveSnapshot records env unless it equals the most recent snapshot.
// Returns the path written, or "" when nothing changed.
func SaveSnapshot(env agentenv.Environment, version string) (string, error) {
	dir, err := envDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	data, err := agentenv.Marshal(env, version)
	if err != nil {
		return "", err
	}
	if latest, ok := latestSnapshot(dir); ok {
		if prev, err := os.ReadFile(latest); err == nil && string(prev) == string(data) {
			return "", nil
		}
	}
	p := filepath.Join(dir, time.Now().UTC().Format("20060102T150405Z")+".lock")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

func latestSnapshot(dir string) (string, bool) {
	paths, _ := filepath.Glob(filepath.Join(dir, "*.lock"))
	if len(paths) == 0 {
		return "", false
	}
	sort.Strings(paths)
	return paths[len(paths)-1], true
}

// LoadSnapshots returns every snapshot, oldest first.
func LoadSnapshots() ([]Snapshot, error) {
	dir, err := envDir()
	if err != nil {
		return nil, err
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.lock"))
	sort.Strings(paths)
	var out []Snapshot
	for _, p := range paths {
		env, err := agentenv.ReadLock(p)
		if err != nil {
			continue // a corrupt or future-schema snapshot is skipped, not fatal
		}
		stamp := strings.TrimSuffix(filepath.Base(p), ".lock")
		ts, err := time.Parse("20060102T150405Z", stamp)
		if err != nil {
			continue
		}
		out = append(out, Snapshot{Time: ts, Path: p, Env: env})
	}
	return out, nil
}
