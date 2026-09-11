package agentenv

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/hooks"
	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/skills"
)

// projectFiles are the source-controlled files that define a project's agent
// environment. A revision-to-revision diff reads exactly these, from both
// sides, so the machine's own user-level state never enters the comparison.
var projectFiles = []struct {
	rel, client, kind string
}{
	{".mcp.json", discover.ClientClaudeCode, "mcp-config"},
	{".cursor/mcp.json", discover.ClientCursor, "mcp-config"},
	{".vscode/mcp.json", discover.ClientVSCode, "mcp-config"},
	{".claude/settings.json", "", "hooks"},
	{".claude/settings.local.json", "", "hooks"},
	{"CLAUDE.md", "", "instructions"},
	{".claude/CLAUDE.md", "", "instructions"},
	{".cursorrules", "", "instructions"},
	{"AGENTS.md", "", "instructions"},
	{".windsurfrules", "", "instructions"},
}

// projectRuleDirs hold one instruction file per rule.
var projectRuleDirs = []string{".cursor/rules", ".windsurf/rules"}

// FileSource yields file content by project-relative path; ok=false when the
// file does not exist on that side. List enumerates paths under a directory.
type FileSource interface {
	Read(rel string) ([]byte, bool)
	List(dirRel string) []string
}

// dirSource reads a working tree.
type dirSource struct{ root string }

func (d dirSource) Read(rel string) ([]byte, bool) {
	b, err := os.ReadFile(filepath.Join(d.root, rel))
	return b, err == nil
}

func (d dirSource) List(dirRel string) []string {
	var out []string
	filepath.Walk(filepath.Join(d.root, dirRel), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(d.root, p)
			out = append(out, rel)
		}
		return nil
	})
	return out
}

// gitSource reads a revision without checking it out.
type gitSource struct{ root, rev string }

func (g gitSource) Read(rel string) ([]byte, bool) {
	out, err := exec.Command("git", "-C", g.root, "show", g.rev+":"+rel).Output()
	return out, err == nil
}

func (g gitSource) List(dirRel string) []string {
	out, err := exec.Command("git", "-C", g.root, "ls-tree", "-r", "--name-only", g.rev, "--", dirRel).Output()
	if err != nil {
		return nil
	}
	var files []string
	for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if ln != "" {
			files = append(files, ln)
		}
	}
	return files
}

// BuildProject builds the environment defined by a project's own files, read
// through src. Servers are analyzed statically (never launched): a diff must
// not execute code from either revision. root is only used to resolve
// relative filesystem roots in configs.
func BuildProject(ctx context.Context, root string, src FileSource, home string) Environment {
	var entries []discover.ServerEntry
	local := &LocalState{}
	for _, pf := range projectFiles {
		data, ok := src.Read(pf.rel)
		if !ok {
			continue
		}
		full := filepath.Join(root, pf.rel)
		switch pf.kind {
		case "mcp-config":
			if es, err := discover.ParseConfigBytes(pf.client, full, data); err == nil {
				entries = append(entries, es...)
			}
		case "hooks":
			local.Hooks = append(local.Hooks, hooks.ParseBytes(data, pf.rel, "project")...)
		}
		// Relative paths: both sides of a revision diff share the root, and
		// the entity should read as ".mcp.json", not an absolute temp path.
		local.Instructions = append(local.Instructions, Instruction{Path: pf.rel, Kind: pf.kind, Scope: "project", Hash: shortHash(data)})
	}
	for _, dir := range projectRuleDirs {
		for _, rel := range src.List(dir) {
			if data, ok := src.Read(rel); ok {
				local.Instructions = append(local.Instructions, Instruction{Path: rel, Kind: "instructions", Scope: "project", Hash: shortHash(data)})
			}
		}
	}
	// Skills: every directory under .claude/skills with a SKILL.md.
	bySkill := map[string]map[string][]byte{}
	for _, rel := range src.List(".claude/skills") {
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 4 { // .claude/skills/<name>/<file>
			continue
		}
		dir := strings.Join(parts[:3], "/")
		inner := strings.Join(parts[3:], "/")
		if bySkill[dir] == nil {
			bySkill[dir] = map[string][]byte{}
		}
		if data, ok := src.Read(rel); ok {
			bySkill[dir][inner] = data
		}
	}
	for dir, files := range bySkill {
		md, ok := files["SKILL.md"]
		if !ok {
			continue
		}
		scripts := map[string][]byte{}
		for rel, data := range files {
			if rel != "SKILL.md" && skills.IsScript(rel, false) {
				scripts[rel] = data
			}
		}
		local.Skills = append(local.Skills, skills.FromContents(dir, "project", md, scripts))
	}
	inspected := inspect.InspectAll(ctx, entries, inspect.Options{NoExec: true}, nil)
	return Build(inspected, Options{Home: home, Cwd: root, Local: local})
}

// BuildWorkingTree builds the project environment from files on disk.
func BuildWorkingTree(ctx context.Context, root, home string) Environment {
	return BuildProject(ctx, root, dirSource{root}, home)
}

// BuildRevision builds the project environment at a git revision.
func BuildRevision(ctx context.Context, root, rev, home string) (Environment, error) {
	if err := exec.Command("git", "-C", root, "rev-parse", "--verify", rev+"^{commit}").Run(); err != nil {
		return Environment{}, fmt.Errorf("unknown git revision %q", rev)
	}
	return BuildProject(ctx, root, gitSource{root, rev}, home), nil
}

// GitRoot returns the repository root for dir, or "" when not in a repo.
func GitRoot(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
