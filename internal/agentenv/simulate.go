package agentenv

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aspex-security/aspex/internal/inspect"
	"github.com/aspex-security/aspex/internal/mcpclient"
)

// Counterfactual analysis: what would the security posture be if the
// environment were changed? The real configuration is never touched. A
// simulation clones the inspected inputs, applies hypothetical changes,
// rebuilds the environment through the same pipeline as a real scan, and
// compares before with after using the same engine as verify and diff.

// SimSchemaVersion is the simulate --json schema version.
const SimSchemaVersion = 1

// ChangeKind enumerates supported hypothetical changes.
type ChangeKind string

const (
	RemoveServer       ChangeKind = "remove-server"
	RestrictFilesystem ChangeKind = "restrict-filesystem" // Server (or "" for all filesystem servers) to Roots
	DenyNetwork        ChangeKind = "deny-network"        // Server or "*"
	RemoveTool         ChangeKind = "remove-tool"         // Server.Tool
	RemoveHook         ChangeKind = "remove-hook"         // Event (or Event:hash)
	RemoveSkill        ChangeKind = "remove-skill"        // Name
	AddServer          ChangeKind = "add-server"          // AddServer carries the entry
)

// HypotheticalChange is one edit to evaluate.
type HypotheticalChange struct {
	Kind   ChangeKind `json:"kind"`
	Server string     `json:"server,omitempty"`
	Tool   string     `json:"tool,omitempty"`
	Roots  []string   `json:"roots,omitempty"`
	Hook   string     `json:"hook,omitempty"`
	Skill  string     `json:"skill,omitempty"`
	// Added is only used with AddServer.
	Added *inspect.Server `json:"-"`
}

// Describe renders the change for humans.
func (c HypotheticalChange) Describe() string {
	switch c.Kind {
	case RemoveServer:
		return "remove server " + c.Server
	case RestrictFilesystem:
		who := c.Server
		if who == "" {
			who = "every filesystem server"
		}
		return "restrict " + who + " to " + strings.Join(c.Roots, ", ")
	case DenyNetwork:
		if c.Server == "*" || c.Server == "" {
			return "deny network egress for every server"
		}
		return "deny network egress for " + c.Server
	case RemoveTool:
		return "remove tool " + c.Server + "." + c.Tool
	case RemoveHook:
		return "remove " + c.Hook + " hook"
	case RemoveSkill:
		return "remove skill " + c.Skill
	case AddServer:
		if c.Added != nil {
			return "add server " + c.Added.Entry.Name
		}
		return "add server"
	}
	return string(c.Kind)
}

// CapabilityDelta is a per-server capability change.
type CapabilityDelta struct {
	Server  string   `json:"server"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	// Roots and scope before -> after, when they changed.
	RootsBefore []string `json:"roots_before,omitempty"`
	RootsAfter  []string `json:"roots_after,omitempty"`
}

// Simulation is the result.
type Simulation struct {
	SchemaVersion int                  `json:"schema_version"`
	Changes       []HypotheticalChange `json:"changes"`
	Before        Environment          `json:"before"`
	After         Environment          `json:"after"`
	Drift         Drift                `json:"drift"`
	Capabilities  []CapabilityDelta    `json:"capability_changes"`
	// Unmatched lists changes that referred to nothing in the environment.
	Unmatched []string `json:"unmatched,omitempty"`
}

// Inputs are what a scan produced: the inspected servers plus the options
// used to build the environment. Simulation reuses them so before and after
// go through identical code.
type Inputs struct {
	Servers []*inspect.Server
	Options Options
}

// Simulate applies changes to a copy of the inputs and compares.
func Simulate(in Inputs, changes []HypotheticalChange) Simulation {
	before := Build(in.Servers, in.Options)
	sim := Simulation{SchemaVersion: SimSchemaVersion, Changes: changes, Before: before}

	// Clone servers (pointers to copies) so nothing reaches the caller's data.
	servers := make([]*inspect.Server, 0, len(in.Servers))
	for _, s := range in.Servers {
		cp := *s
		cp.Tools = append([]mcpclient.Tool(nil), s.Tools...)
		cp.Entry.Args = append([]string(nil), s.Entry.Args...)
		servers = append(servers, &cp)
	}
	opts := in.Options
	// Deep-copy the hypothetical maps so the caller's Options are untouched.
	opts.AttackPath.RootsOverride = copyRoots(in.Options.AttackPath.RootsOverride)
	opts.AttackPath.DenyNetwork = copyBools(in.Options.AttackPath.DenyNetwork)
	opts.AttackPath.RemoveTools = copyBools(in.Options.AttackPath.RemoveTools)
	if opts.Local != nil {
		l := *opts.Local
		l.Hooks = append(l.Hooks[:0:0], l.Hooks...)
		l.Skills = append(l.Skills[:0:0], l.Skills...)
		opts.Local = &l
	} else if !opts.SkipLocalState {
		// Snapshot the local state now so hook/skill removals can apply to it.
		l := discoverLocal(in.Options)
		opts.Local = &l
	}

	names := map[string]bool{}
	for _, s := range servers {
		names[s.Entry.Name] = true
	}
	for _, ch := range changes {
		switch ch.Kind {
		case RemoveServer:
			if !names[ch.Server] {
				sim.Unmatched = append(sim.Unmatched, ch.Describe())
				continue
			}
			var kept []*inspect.Server
			for _, s := range servers {
				if s.Entry.Name != ch.Server {
					kept = append(kept, s)
				}
			}
			servers = kept
		case RestrictFilesystem:
			if opts.AttackPath.RootsOverride == nil {
				opts.AttackPath.RootsOverride = map[string][]string{}
			}
			if ch.Server == "" {
				matched := false
				for _, s := range before.Servers {
					if s.Scope != "" { // has filesystem access
						opts.AttackPath.RootsOverride[s.Name] = ch.Roots
						matched = true
					}
				}
				if !matched {
					sim.Unmatched = append(sim.Unmatched, ch.Describe())
				}
			} else if names[ch.Server] {
				opts.AttackPath.RootsOverride[ch.Server] = ch.Roots
			} else {
				sim.Unmatched = append(sim.Unmatched, ch.Describe())
			}
		case DenyNetwork:
			if opts.AttackPath.DenyNetwork == nil {
				opts.AttackPath.DenyNetwork = map[string]bool{}
			}
			target := ch.Server
			if target == "" {
				target = "*"
			}
			if target != "*" && !names[target] {
				sim.Unmatched = append(sim.Unmatched, ch.Describe())
				continue
			}
			opts.AttackPath.DenyNetwork[target] = true
		case RemoveTool:
			if opts.AttackPath.RemoveTools == nil {
				opts.AttackPath.RemoveTools = map[string]bool{}
			}
			found := false
			for _, s := range servers {
				if s.Entry.Name == ch.Server {
					for _, t := range s.Tools {
						if t.Name == ch.Tool {
							found = true
						}
					}
				}
			}
			if !found {
				sim.Unmatched = append(sim.Unmatched, ch.Describe())
				continue
			}
			opts.AttackPath.RemoveTools[ch.Server+"."+ch.Tool] = true
		case RemoveHook:
			if opts.Local == nil {
				sim.Unmatched = append(sim.Unmatched, ch.Describe())
				continue
			}
			var kept = opts.Local.Hooks[:0:0]
			removed := false
			for _, h := range opts.Local.Hooks {
				if h.Event == ch.Hook || h.Event+":"+shortHash([]byte(h.Command)) == ch.Hook {
					removed = true
					continue
				}
				kept = append(kept, h)
			}
			if !removed {
				sim.Unmatched = append(sim.Unmatched, ch.Describe())
			}
			opts.Local.Hooks = kept
		case RemoveSkill:
			if opts.Local == nil {
				sim.Unmatched = append(sim.Unmatched, ch.Describe())
				continue
			}
			var kept = opts.Local.Skills[:0:0]
			removed := false
			for _, sk := range opts.Local.Skills {
				if sk.Name == ch.Skill {
					removed = true
					continue
				}
				kept = append(kept, sk)
			}
			if !removed {
				sim.Unmatched = append(sim.Unmatched, ch.Describe())
			}
			opts.Local.Skills = kept
		case AddServer:
			if ch.Added != nil {
				cp := *ch.Added
				servers = append(servers, &cp)
			}
		}
	}

	after := Build(servers, opts)
	sim.After = after
	sim.Drift = Compare(before, after)
	sim.Capabilities = capabilityDeltas(before, after)
	return sim
}

func capabilityDeltas(before, after Environment) []CapabilityDelta {
	bm := map[string]Server{}
	for _, s := range before.Servers {
		bm[s.Name] = s
	}
	am := map[string]Server{}
	for _, s := range after.Servers {
		am[s.Name] = s
	}
	var out []CapabilityDelta
	names := map[string]bool{}
	for n := range bm {
		names[n] = true
	}
	for n := range am {
		names[n] = true
	}
	var sorted []string
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	for _, n := range sorted {
		b, hadB := bm[n]
		a, hadA := am[n]
		d := CapabilityDelta{Server: n}
		switch {
		case hadB && !hadA:
			d.Removed = b.Capabilities
		case !hadB && hadA:
			d.Added = a.Capabilities
		default:
			d.Added, d.Removed = diffStrings(b.Capabilities, a.Capabilities)
			if !equalStrings(b.Roots, a.Roots) {
				d.RootsBefore, d.RootsAfter = b.Roots, a.Roots
			}
		}
		if len(d.Added)+len(d.Removed)+len(d.RootsAfter) > 0 {
			out = append(out, d)
		}
	}
	return out
}

func copyRoots(m map[string][]string) map[string][]string {
	if m == nil {
		return nil
	}
	out := map[string][]string{}
	for k, v := range m {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func copyBools(m map[string]bool) map[string]bool {
	if m == nil {
		return nil
	}
	out := map[string]bool{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ParseChange turns a CLI-style spec into a change.
//
//	remove-server=NAME | restrict-filesystem=[SERVER=]ROOT[,ROOT] |
//	deny-network=[SERVER|*] | remove-tool=SERVER.TOOL | remove-hook=EVENT |
//	remove-skill=NAME
func ParseChange(kind ChangeKind, value string) (HypotheticalChange, error) {
	c := HypotheticalChange{Kind: kind}
	switch kind {
	case RemoveServer:
		c.Server = value
	case RestrictFilesystem:
		if i := strings.Index(value, "="); i > 0 {
			c.Server, value = value[:i], value[i+1:]
		}
		for _, r := range strings.Split(value, ",") {
			if r = strings.TrimSpace(r); r != "" {
				c.Roots = append(c.Roots, r)
			}
		}
		if len(c.Roots) == 0 {
			return c, fmt.Errorf("restrict-filesystem needs at least one root")
		}
	case DenyNetwork:
		c.Server = value
	case RemoveTool:
		i := strings.LastIndex(value, ".")
		if i <= 0 || i == len(value)-1 {
			return c, fmt.Errorf("remove-tool needs SERVER.TOOL, got %q", value)
		}
		c.Server, c.Tool = value[:i], value[i+1:]
	case RemoveHook:
		c.Hook = value
	case RemoveSkill:
		c.Skill = value
	default:
		return c, fmt.Errorf("unknown change kind %q", kind)
	}
	if value == "" && kind != DenyNetwork {
		return c, fmt.Errorf("%s needs a value", kind)
	}
	return c, nil
}
