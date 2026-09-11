// Package skills discovers agent skills: directories holding a SKILL.md whose
// frontmatter names the skill and whose body instructs the agent. A skill is
// persistent instruction the agent trusts, often with scripts it can run, so
// it is part of the environment's security-relevant state alongside MCP
// servers and hooks.
//
// Discovery is deliberately narrow: only the well-known skill roots for
// Claude Code (user, project, installed plugins). Content is hashed, never
// stored; URLs and script names are extracted for the environment model.
package skills

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Skill is one discovered skill.
type Skill struct {
	Name         string   `json:"name"`
	Path         string   `json:"path"`   // directory holding SKILL.md
	Scope        string   `json:"scope"`  // "user" | "project" | "plugin"
	Client       string   `json:"client"` // "claude-code"
	ContentHash  string   `json:"content_hash"`
	Scripts      []string `json:"scripts,omitempty"`      // executable or script files inside the skill dir
	Destinations []string `json:"destinations,omitempty"` // hosts referenced in SKILL.md
	Executes     bool     `json:"executes"`               // ships scripts or instructs running commands
	Description  string   `json:"description,omitempty"`
}

// Discover lists skills under the user home, the project cwd, and installed
// plugins. Missing roots are skipped silently. Output is sorted by path.
func Discover(home, cwd string) []Skill {
	var out []Skill
	out = append(out, scanRoot(filepath.Join(home, ".claude", "skills"), "user")...)
	if cwd != "" {
		out = append(out, scanRoot(filepath.Join(cwd, ".claude", "skills"), "project")...)
	}
	for _, p := range pluginRoots(filepath.Join(home, ".claude", "plugins", "installed_plugins.json")) {
		out = append(out, scanRoot(filepath.Join(p, "skills"), "plugin")...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func pluginRoots(manifest string) []string {
	data, err := os.ReadFile(manifest)
	if err != nil {
		return nil
	}
	var m struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, installs := range m.Plugins {
		for _, in := range installs {
			if in.InstallPath != "" && !seen[in.InstallPath] {
				seen[in.InstallPath] = true
				out = append(out, in.InstallPath)
			}
		}
	}
	return out
}

func scanRoot(root, scope string) []Skill {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []Skill
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if sk, ok := Load(dir, scope); ok {
			out = append(out, sk)
		}
	}
	return out
}

var (
	urlRe      = regexp.MustCompile(`https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})`)
	execHintRe = regexp.MustCompile(`(?i)\b(run|execute|invoke)\b[^.\n]{0,40}\b(bash|sh|python|node|npx|command|script|cli)\b|` + "```(bash|sh|zsh|shell)")
	scriptExt  = map[string]bool{".sh": true, ".bash": true, ".zsh": true, ".py": true, ".js": true, ".mjs": true, ".ts": true, ".rb": true, ".pl": true}
)

// Load reads one skill directory. ok is false when there is no SKILL.md.
func Load(dir, scope string) (Skill, bool) {
	body, err := os.ReadFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		return Skill{}, false
	}
	sk := Skill{Path: dir, Scope: scope, Client: "claude-code"}
	sk.Name, sk.Description = frontmatter(string(body))
	if sk.Name == "" {
		sk.Name = filepath.Base(dir)
	}
	h := sha256.New()
	h.Write(body)

	// Scripts: any script-like file in the directory tree, hashed into the
	// content hash so a changed script changes the skill.
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Base(p) == "SKILL.md" {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if scriptExt[strings.ToLower(filepath.Ext(p))] || info.Mode()&0o111 != 0 {
			sk.Scripts = append(sk.Scripts, rel)
			if data, err := os.ReadFile(p); err == nil {
				h.Write([]byte(rel))
				h.Write(data)
			}
		}
		return nil
	})
	sort.Strings(sk.Scripts)
	sk.ContentHash = hex.EncodeToString(h.Sum(nil))[:16]

	seen := map[string]bool{}
	for _, m := range urlRe.FindAllStringSubmatch(string(body), -1) {
		host := strings.ToLower(m[1])
		if !seen[host] {
			seen[host] = true
			sk.Destinations = append(sk.Destinations, host)
		}
	}
	sort.Strings(sk.Destinations)
	sk.Executes = len(sk.Scripts) > 0 || execHintRe.MatchString(string(body))
	return sk, true
}

// frontmatter pulls name and description from a leading --- block. Minimal by
// design: skills are YAML-ish but we only need two scalar fields, and a
// misparsed frontmatter must never stop discovery.
func frontmatter(s string) (name, desc string) {
	if !strings.HasPrefix(s, "---") {
		return "", ""
	}
	end := strings.Index(s[3:], "\n---")
	if end < 0 {
		return "", ""
	}
	block := s[3 : 3+end]
	lines := strings.Split(block, "\n")
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "name:"):
			name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "name:")), `"'`)
		case strings.HasPrefix(t, "description:"):
			v := strings.TrimSpace(strings.TrimPrefix(t, "description:"))
			if v == ">-" || v == ">" || v == "|" || v == "" {
				// folded block: gather indented continuation lines
				var parts []string
				for j := i + 1; j < len(lines); j++ {
					if strings.TrimSpace(lines[j]) == "" || !strings.HasPrefix(lines[j], " ") {
						break
					}
					parts = append(parts, strings.TrimSpace(lines[j]))
				}
				v = strings.Join(parts, " ")
			}
			desc = strings.Trim(v, `"'`)
		}
	}
	return name, desc
}
