package agentenv

import (
	"fmt"
	"strings"

	"github.com/aspex-security/aspex/internal/attackpath"
)

// Path-breaking controls. Given an attack path (a composition), the concrete
// configuration changes that would remove it, each expressed as a hypothetical
// change the simulator can evaluate. One engine feeds scan, explain, diff,
// tighten, PR review, the MCP interface and the explorer, so the advice reads
// the same everywhere and is never "apply least privilege".

// Control is one path-breaking change.
type Control struct {
	Text   string             `json:"text"`   // concrete, human: "restrict filesystem to ~/projects/acme"
	Change HypotheticalChange `json:"change"` // what to simulate
	// Breaks is true when this single control removes the path on its own.
	Breaks bool `json:"breaks_path"`
}

// ControlsFor derives the controls that break a chain, from its composition.
// projectRoot is the narrow root to suggest for filesystem restrictions; "" uses a placeholder.
func ControlsFor(env Environment, ch attackpath.AttackChain, projectRoot string) []Control {
	if projectRoot == "" {
		projectRoot = "<project directory>"
	}
	byName := map[string]Server{}
	for _, s := range env.Servers {
		byName[s.Name] = s
	}
	var out []Control
	add := func(text string, c HypotheticalChange) {
		for _, x := range out {
			if x.Change.Kind == c.Kind && x.Change.Server == c.Server && x.Change.Tool == c.Tool {
				return
			}
		}
		out = append(out, Control{Text: text, Change: c, Breaks: true})
	}
	for _, name := range ch.Servers {
		s, ok := byName[name]
		if !ok {
			continue
		}
		caps := capSet(s)
		switch ch.ID {
		case "AP001", "AP002":
			if caps["file-read"] && (s.Scope == "sensitive" || s.Scope == "unknown") {
				add(fmt.Sprintf("restrict %s to %s instead of %s", name, projectRoot, rootsOr(s)), HypotheticalChange{Kind: RestrictFilesystem, Server: name, Roots: []string{projectRoot}})
			}
			if caps["credential-read"] || caps["env-read"] {
				add(fmt.Sprintf("remove %s (explicit credential or environment access)", name), HypotheticalChange{Kind: RemoveServer, Server: name})
			}
			if s.EgressOpen || caps["external-send"] || caps["email-send"] || caps["browser"] {
				add(fmt.Sprintf("deny network egress for %s (or allowlist its destinations)", name), HypotheticalChange{Kind: DenyNetwork, Server: name})
			}
			if caps["shell-exec"] {
				add(fmt.Sprintf("remove %s or run it in a sandbox without network", name), HypotheticalChange{Kind: RemoveServer, Server: name})
			}
		case "AP003":
			if len(s.StateWrites) > 0 {
				add(fmt.Sprintf("restrict %s to a directory holding no agent config, hooks or instructions (e.g. %s)", name, projectRoot), HypotheticalChange{Kind: RestrictFilesystem, Server: name, Roots: []string{projectRoot}})
			}
			if caps["shell-exec"] {
				add(fmt.Sprintf("remove %s (a shell can rewrite any agent state)", name), HypotheticalChange{Kind: RemoveServer, Server: name})
			}
			if caps["untrusted-ingress"] || caps["browser"] {
				add(fmt.Sprintf("remove %s so external content cannot enter the context", name), HypotheticalChange{Kind: RemoveServer, Server: name})
			}
		case "AP004":
			if caps["memory-write"] {
				add(fmt.Sprintf("remove %s (persistent memory)", name), HypotheticalChange{Kind: RemoveServer, Server: name})
			}
			if caps["untrusted-ingress"] || caps["browser"] {
				add(fmt.Sprintf("remove %s so external content cannot reach memory", name), HypotheticalChange{Kind: RemoveServer, Server: name})
			}
		case "AP005":
			if caps["shell-exec"] {
				add(fmt.Sprintf("remove %s or run it in a sandbox without network access", name), HypotheticalChange{Kind: RemoveServer, Server: name})
			}
			if s.EgressOpen || caps["browser"] {
				add(fmt.Sprintf("deny network egress for %s", name), HypotheticalChange{Kind: DenyNetwork, Server: name})
			}
		case "AP006":
			if caps["shell-exec"] {
				add(fmt.Sprintf("remove %s", name), HypotheticalChange{Kind: RemoveServer, Server: name})
			}
			if caps["untrusted-ingress"] || caps["browser"] {
				add(fmt.Sprintf("remove %s so external content cannot reach the shell", name), HypotheticalChange{Kind: RemoveServer, Server: name})
			}
		}
	}
	return out
}

// Evaluate runs each control through the simulator and marks whether it
// removes the chain on its own. Controls that do not break the path alone are
// kept but marked, so the user sees the honest picture.
func Evaluate(in Inputs, ch attackpath.AttackChain, controls []Control) []Control {
	key := ch.ID + "|" + strings.Join(ch.Servers, ",")
	for i := range controls {
		sim := Simulate(in, []HypotheticalChange{controls[i].Change})
		still := false
		for _, p := range sim.After.AttackPaths {
			if p.ID+"|"+strings.Join(p.Servers, ",") == key {
				still = true
			}
		}
		controls[i].Breaks = !still
	}
	return controls
}

// FirstControl returns the most targeted control text for a chain, for
// one-line contexts (PR comments, watch output). Restriction beats removal.
func FirstControl(env Environment, ch attackpath.AttackChain, projectRoot string) string {
	cs := ControlsFor(env, ch, projectRoot)
	for _, c := range cs {
		if c.Change.Kind == RestrictFilesystem || c.Change.Kind == DenyNetwork {
			return c.Text
		}
	}
	if len(cs) > 0 {
		return cs[0].Text
	}
	return ch.Remediation
}
