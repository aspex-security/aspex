package agentenv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// LockFileName is the default lockfile path, relative to the project.
const LockFileName = ".aspex.lock"

// Lockfile is the on-disk form of an Environment. It is the Environment
// itself plus a header; no volatile fields (timestamps, durations, scores)
// are included, so re-locking an unchanged setup produces an identical file.
type Lockfile struct {
	Schema      string      `json:"$schema"`
	Generator   string      `json:"generator"`
	Environment Environment `json:"environment"`
}

// Marshal renders the lockfile deterministically (sorted keys, two-space
// indent, trailing newline) so it diffs well in version control.
func Marshal(env Environment, version string) ([]byte, error) {
	lf := Lockfile{
		Schema:      fmt.Sprintf("aspex-lock/v%d", SchemaVersion),
		Generator:   "aspex " + version,
		Environment: env,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(lf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteLock writes the lockfile atomically (temp file + rename).
func WriteLock(path string, env Environment, version string) error {
	data, err := Marshal(env, version)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadLock parses a lockfile. Unknown future schema versions are rejected
// rather than silently misread.
func ReadLock(path string) (Environment, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Environment{}, err
	}
	return Unmarshal(data)
}

// Unmarshal parses lockfile bytes.
func Unmarshal(data []byte) (Environment, error) {
	var lf Lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return Environment{}, fmt.Errorf("lockfile is not valid JSON: %w", err)
	}
	if lf.Environment.SchemaVersion > SchemaVersion {
		return Environment{}, fmt.Errorf("lockfile schema %d is newer than this aspex understands (%d); upgrade aspex", lf.Environment.SchemaVersion, SchemaVersion)
	}
	if lf.Environment.SchemaVersion == 0 {
		return Environment{}, fmt.Errorf("not an aspex lockfile (missing schema_version)")
	}
	env := lf.Environment
	sortEnv(&env)
	return env, nil
}
