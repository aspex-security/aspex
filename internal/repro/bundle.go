package repro

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/killchain"
	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/provenance"
	"github.com/aspex-security/aspex/internal/trace"
)

// SchemaVersion of the bundle manifest.
const SchemaVersion = 1

// Manifest describes a bundle.
type Manifest struct {
	Schema      string    `json:"$schema"`
	Version     int       `json:"schema_version"`
	Generator   string    `json:"generator"`
	Created     time.Time `json:"created"`
	Session     string    `json:"session,omitempty"`
	Window      string    `json:"window,omitempty"`
	Redaction   Stats     `json:"redaction"`
	Files       []string  `json:"files"`
	Description string    `json:"description"`
	// Analysis at export time, so replay can report differences.
	Findings    int `json:"findings"`
	KillChains  int `json:"killchains"`
	AttackPaths int `json:"attack_paths"`
}

// Inputs for a bundle.
type Inputs struct {
	Events  []logparse.Event
	Env     agentenv.Environment
	Session string
	Window  string
	Version string
}

// Files in a bundle, fixed names so replay knows what to read.
const (
	FileManifest    = "manifest.json"
	FileEnvironment = "environment.asbom.json"
	FileEvents      = "events.json"
	FileFindings    = "findings.json"
	FilePaths       = "attack-paths.json"
	FileReadme      = "README.md"
)

// Create writes a bundle into dir (created; must be empty or absent).
// Events are redacted; the environment is the lockfile-shaped model, which
// carries no secret values by construction. Nothing else is copied.
func Create(dir string, in Inputs) (Manifest, error) {
	if err := safeOutputDir(dir); err != nil {
		return Manifest{}, err
	}
	events, stats := RedactEvents(in.Events)
	flagged := trace.AnalyzeEvents(events)
	chains := killchain.Analyze(events, flagged)
	prov := provenance.Analyze(events, flagged)

	m := Manifest{
		Schema: fmt.Sprintf("aspex-repro/v%d", SchemaVersion), Version: SchemaVersion, Generator: "aspex " + in.Version,
		Created: time.Now().UTC(), Session: in.Session, Window: in.Window, Redaction: stats,
		Description: "Aspex reproduction bundle: redacted trace events, the environment model, and the analysis at export time. Replay with `aspex trace replay <dir>`; nothing in here is executed.",
		Findings:    len(flagged), KillChains: len(chains), AttackPaths: len(in.Env.AttackPaths),
		Files: []string{FileManifest, FileEnvironment, FileEvents, FileFindings, FilePaths, FileReadme},
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return m, err
	}
	write := func(name string, v interface{}) error {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644)
	}
	envDoc := struct {
		Schema      string               `json:"$schema"`
		Environment agentenv.Environment `json:"environment"`
	}{fmt.Sprintf("aspex-asbom/v%d", agentenv.SchemaVersion), in.Env}
	findings := struct {
		Flagged    []trace.FlaggedEvent     `json:"flagged"`
		KillChains []killchain.Chain        `json:"killchains"`
		Provenance []provenance.Attribution `json:"provenance"`
	}{flagged, chains, prov.Attributions}
	for name, v := range map[string]interface{}{FileManifest: m, FileEnvironment: envDoc, FileEvents: events, FileFindings: findings, FilePaths: in.Env.AttackPaths} {
		if err := write(name, v); err != nil {
			return m, err
		}
	}
	readme := fmt.Sprintf(`# Aspex reproduction bundle

Created %s by %s. Session: %s. Window: %s.

Contents
- manifest.json: what is here and what redaction did (%d secrets redacted, %d content arguments dropped, %d credential-file contents dropped)
- environment.asbom.json: the agent environment model (servers, capabilities, hooks, skills, attack paths). Never contains secret values.
- events.json: %d trace events with secret-shaped values redacted and content bodies removed
- findings.json: trace findings, kill chains and provenance at export time
- attack-paths.json: the compositions Aspex reported

Replay: aspex trace replay <this directory>
Replay re-runs Aspex's analysis over these files. It does not execute any recorded tool, command or network call.

Privacy: review events.json before sharing. Server names, tool names, paths and URLs are kept because they are what the analysis reasons about; file contents and secret-shaped values are not.
`, m.Created.Format(time.RFC3339), m.Generator, orDash(in.Session), orDash(in.Window), stats.SecretsRedacted, stats.ContentDropped, stats.CredentialContent, len(events))
	if err := os.WriteFile(filepath.Join(dir, FileReadme), []byte(readme), 0o644); err != nil {
		return m, err
	}
	return m, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// safeOutputDir refuses paths that would overwrite something unexpected.
func safeOutputDir(dir string) error {
	if dir == "" || dir == "/" || dir == "." {
		return errors.New("refusing to write a bundle to " + dir)
	}
	if st, err := os.Lstat(dir); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to write through a symlink: " + dir)
		}
		if !st.IsDir() {
			return errors.New(dir + " exists and is not a directory")
		}
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.Name() != FileManifest && !strings.HasSuffix(e.Name(), ".json") && e.Name() != FileReadme {
				return errors.New(dir + " is not empty; choose a new directory")
			}
		}
	}
	return nil
}

// Replay re-runs the analysis over a bundle. It reads only the fixed file
// names inside dir, refuses symlinks and oversized files, and executes
// nothing. The result compares the regenerated analysis with what the bundle
// recorded so a reviewer can see whether current rules still agree.
type Replay struct {
	Manifest    Manifest                 `json:"manifest"`
	Events      []logparse.Event         `json:"-"`
	Env         agentenv.Environment     `json:"-"`
	Flagged     []trace.FlaggedEvent     `json:"flagged"`
	KillChains  []killchain.Chain        `json:"killchains"`
	Provenance  provenance.Report        `json:"provenance"`
	AttackPaths []attackpath.AttackChain `json:"attack_paths"`
	// Deltas versus export time.
	FindingsDelta   int `json:"findings_delta"`
	KillChainsDelta int `json:"killchains_delta"`
	PathsDelta      int `json:"attack_paths_delta"`
}

const maxBundleFile = 64 << 20

func readBundleFile(dir, name string, v interface{}) error {
	p := filepath.Join(dir, name)
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to follow symlink " + name)
	}
	if st.Size() > maxBundleFile {
		return fmt.Errorf("%s is larger than %d bytes; refusing", name, maxBundleFile)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Load reads and re-analyzes a bundle.
func Load(dir string) (Replay, error) {
	var r Replay
	if err := readBundleFile(dir, FileManifest, &r.Manifest); err != nil {
		return r, fmt.Errorf("manifest: %w", err)
	}
	if r.Manifest.Version > SchemaVersion || r.Manifest.Version == 0 {
		return r, fmt.Errorf("bundle schema %d not supported (this aspex reads up to %d)", r.Manifest.Version, SchemaVersion)
	}
	for _, f := range r.Manifest.Files {
		if strings.Contains(f, "/") || strings.Contains(f, "\\") || strings.Contains(f, "..") {
			return r, fmt.Errorf("manifest lists an unsafe file name %q", f)
		}
	}
	if err := readBundleFile(dir, FileEvents, &r.Events); err != nil {
		return r, fmt.Errorf("events: %w", err)
	}
	var envDoc struct {
		Environment agentenv.Environment `json:"environment"`
	}
	if err := readBundleFile(dir, FileEnvironment, &envDoc); err != nil {
		return r, fmt.Errorf("environment: %w", err)
	}
	r.Env = envDoc.Environment
	// Re-redact defensively: a hand-edited bundle must not carry secrets forward.
	r.Events, _ = RedactEvents(r.Events)
	r.Flagged = trace.AnalyzeEvents(r.Events)
	r.KillChains = killchain.Analyze(r.Events, r.Flagged)
	r.Provenance = provenance.Analyze(r.Events, r.Flagged)
	r.AttackPaths = r.Env.AttackPaths
	r.FindingsDelta = len(r.Flagged) - r.Manifest.Findings
	r.KillChainsDelta = len(r.KillChains) - r.Manifest.KillChains
	r.PathsDelta = len(r.AttackPaths) - r.Manifest.AttackPaths
	return r, nil
}
