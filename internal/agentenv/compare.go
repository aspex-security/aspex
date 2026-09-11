package agentenv

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aspex-security/aspex/internal/attackpath"
	"github.com/aspex-security/aspex/internal/rules"
)

// Change kinds. Stable strings; they appear in JSON.
const (
	ServerAdded         = "SERVER ADDED"
	ServerRemoved       = "SERVER REMOVED"
	ServerIdentity      = "SERVER IDENTITY CHANGED"
	ToolAdded           = "NEW TOOL"
	ToolRemoved         = "REMOVED TOOL"
	ToolDescription     = "TOOL DESCRIPTION CHANGED"
	ToolSchema          = "TOOL SCHEMA CHANGED"
	CapabilityAdded     = "CAPABILITY ADDED"
	CapabilityRemoved   = "CAPABILITY REMOVED"
	ScopeExpanded       = "FILESYSTEM SCOPE EXPANDED"
	ScopeRestricted     = "FILESYSTEM SCOPE RESTRICTED"
	EgressOpened        = "NETWORK EGRESS OPENED"
	EgressConstrainedK  = "NETWORK EGRESS CONSTRAINED"
	StateWriteAdded     = "AGENT STATE NEWLY WRITABLE"
	StateWriteRemoved   = "AGENT STATE NO LONGER WRITABLE"
	HookAdded           = "HOOK ADDED"
	HookRemoved         = "HOOK REMOVED"
	HookModified        = "HOOK MODIFIED"
	SkillAdded          = "SKILL ADDED"
	SkillRemoved        = "SKILL REMOVED"
	SkillModified       = "SKILL MODIFIED"
	InstructionChanged  = "PERSISTENT INSTRUCTION CHANGED"
	InstructionAdded    = "PERSISTENT INSTRUCTION ADDED"
	InstructionRemoved  = "PERSISTENT INSTRUCTION REMOVED"
	ResourceReachable   = "SENSITIVE RESOURCE NEWLY REACHABLE"
	ResourceUnreachable = "SENSITIVE RESOURCE NO LONGER REACHABLE"
)

// Classification of a change's security meaning.
const (
	ClassInformational    = "informational"
	ClassSecurityRelevant = "security-relevant"
	ClassSuspicious       = "suspicious"
)

// Change is one security-meaningful difference between two environments.
type Change struct {
	Kind     string `json:"kind"`
	Class    string `json:"class"`  // informational | security-relevant | suspicious
	Entity   string `json:"entity"` // "github-mcp", "github-mcp.search", hook event, skill name
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
	Impact   string `json:"impact"`             // the security meaning, one or two sentences
	Reason   string `json:"reason,omitempty"`   // why it was classified as it was
	Severity string `json:"severity,omitempty"` // for attack paths and hooks: critical..low
}

// Drift is the result of comparing two environments.
type Drift struct {
	Changes      []Change                 `json:"changes"`
	PathsAdded   []attackpath.AttackChain `json:"attack_paths_added"`
	PathsRemoved []attackpath.AttackChain `json:"attack_paths_removed"`
	BlastBefore  BlastRadius              `json:"blast_radius_before"`
	BlastAfter   BlastRadius              `json:"blast_radius_after"`
	StaticBefore bool                     `json:"static_before"`
	StaticAfter  bool                     `json:"static_after"`
}

// Empty reports whether nothing security-relevant changed. Informational
// changes alone still count as drift; callers decide how loud to be.
func (d Drift) Empty() bool {
	return len(d.Changes) == 0 && len(d.PathsAdded) == 0 && len(d.PathsRemoved) == 0
}

// Worst returns the highest classification present: "" | informational |
// security-relevant | suspicious, considering attack paths as
// security-relevant (critical/high paths as suspicious-level urgency).
func (d Drift) Worst() string {
	worst := ""
	rank := func(c string) int {
		switch c {
		case ClassSuspicious:
			return 3
		case ClassSecurityRelevant:
			return 2
		case ClassInformational:
			return 1
		}
		return 0
	}
	for _, c := range d.Changes {
		if rank(c.Class) > rank(worst) {
			worst = c.Class
		}
	}
	if len(d.PathsAdded) > 0 && rank(worst) < 2 {
		worst = ClassSecurityRelevant
	}
	return worst
}

// SecurityRelevant returns only the changes that are not informational.
func (d Drift) SecurityRelevant() []Change {
	var out []Change
	for _, c := range d.Changes {
		if c.Class != ClassInformational {
			out = append(out, c)
		}
	}
	return out
}

// Compare produces the security-impact drift from before to after.
func Compare(before, after Environment) Drift {
	d := Drift{
		BlastBefore: before.BlastRadius, BlastAfter: after.BlastRadius,
		StaticBefore: before.Static, StaticAfter: after.Static,
	}
	d.Changes = append(d.Changes, compareServers(before, after)...)
	d.Changes = append(d.Changes, compareHooks(before, after)...)
	d.Changes = append(d.Changes, compareSkills(before, after)...)
	d.Changes = append(d.Changes, compareInstructions(before, after)...)
	d.Changes = append(d.Changes, compareResources(before, after)...)
	d.PathsAdded, d.PathsRemoved = comparePaths(before, after)

	sort.SliceStable(d.Changes, func(i, j int) bool {
		ri, rj := classRank(d.Changes[i].Class), classRank(d.Changes[j].Class)
		if ri != rj {
			return ri > rj
		}
		if d.Changes[i].Entity != d.Changes[j].Entity {
			return d.Changes[i].Entity < d.Changes[j].Entity
		}
		return d.Changes[i].Kind < d.Changes[j].Kind
	})
	if d.Changes == nil {
		d.Changes = []Change{}
	}
	if d.PathsAdded == nil {
		d.PathsAdded = []attackpath.AttackChain{}
	}
	if d.PathsRemoved == nil {
		d.PathsRemoved = []attackpath.AttackChain{}
	}
	return d
}

func classRank(c string) int {
	switch c {
	case ClassSuspicious:
		return 3
	case ClassSecurityRelevant:
		return 2
	}
	return 1
}

// dangerousCaps are capabilities whose appearance is security-relevant on
// its own, regardless of composition.
var dangerousCaps = map[string]string{
	"shell-exec":        "command execution",
	"network-send":      "network egress",
	"credential-read":   "credential access",
	"env-read":          "environment variable access",
	"file-write":        "file write",
	"db-write":          "database write",
	"persistence-write": "persistence",
	"package-install":   "package installation",
	"memory-write":      "memory write",
	"email-send":        "email sending",
	"external-send":     "sending data to an external service",
	"browser":           "browser control",
	"untrusted-ingress": "external content entering the agent's context",
}

func compareServers(before, after Environment) []Change {
	var out []Change
	key := func(s Server) string { return s.Client + "\x00" + s.Name }
	bm := map[string]Server{}
	for _, s := range before.Servers {
		bm[key(s)] = s
	}
	am := map[string]Server{}
	for _, s := range after.Servers {
		am[key(s)] = s
	}
	for k, s := range am {
		if _, ok := bm[k]; !ok {
			out = append(out, Change{
				Kind: ServerAdded, Class: classForCaps(s.Capabilities, ClassInformational), Entity: s.Name,
				After:  strings.Join(s.Capabilities, ", "),
				Impact: "New server " + s.Name + " brings " + describeCaps(s.Capabilities) + " into the environment.",
			})
			out = append(out, toolTextChanges(Server{}, s)...) // fresh tools: only suspicious descriptions are worth a line
		}
	}
	for k, s := range bm {
		if _, ok := am[k]; !ok {
			out = append(out, Change{
				Kind: ServerRemoved, Class: ClassInformational, Entity: s.Name,
				Before: strings.Join(s.Capabilities, ", "),
				Impact: "Server " + s.Name + " removed; its capabilities (" + describeCaps(s.Capabilities) + ") are gone.",
			})
		}
	}
	for k, a := range am {
		b, ok := bm[k]
		if !ok {
			continue
		}
		out = append(out, compareServer(b, a)...)
	}
	return out
}

func compareServer(b, a Server) []Change {
	var out []Change
	if b.Identity != a.Identity {
		cls := ClassInformational
		reason := ""
		if b.Pinned && !a.Pinned {
			cls, reason = ClassSecurityRelevant, "version pin removed: the command now resolves to whatever is latest"
		}
		out = append(out, Change{
			Kind: ServerIdentity, Class: cls, Entity: a.Name,
			Before: cmdline(b), After: cmdline(a), Reason: reason,
			Impact: "What runs for " + a.Name + " changed. Review the new command line; capability changes, if any, are listed separately.",
		})
	}
	// Tools
	bt := map[string]Tool{}
	for _, t := range b.Tools {
		bt[t.Name] = t
	}
	at := map[string]Tool{}
	for _, t := range a.Tools {
		at[t.Name] = t
	}
	addedCaps, removedCaps := diffStrings(b.Capabilities, a.Capabilities)
	for name, t := range at {
		if _, ok := bt[name]; !ok {
			cls, reason := ClassInformational, ""
			if txt, why := rules.ClassifyText(t.Description); txt == rules.TextSuspicious {
				cls, reason = ClassSuspicious, why
			} else if len(addedCaps) > 0 {
				cls, reason = ClassSecurityRelevant, "arrives with new capabilities: "+strings.Join(addedCaps, ", ")
			}
			out = append(out, Change{
				Kind: ToolAdded, Class: cls, Entity: a.Name + "." + name, After: t.Description, Reason: reason,
				Impact: "A tool the agent can now call. " + capImpact(addedCaps),
			})
		}
	}
	for name := range bt {
		if _, ok := at[name]; !ok {
			out = append(out, Change{Kind: ToolRemoved, Class: ClassInformational, Entity: a.Name + "." + name,
				Impact: "The agent can no longer call this tool."})
		}
	}
	out = append(out, toolTextChanges(b, a)...)

	for _, c := range addedCaps {
		cls := ClassInformational
		if _, ok := dangerousCaps[c]; ok {
			cls = ClassSecurityRelevant
		}
		out = append(out, Change{
			Kind: CapabilityAdded, Class: cls, Entity: a.Name, After: c,
			Impact: a.Name + " gained " + describeCaps([]string{c}) + ".",
		})
	}
	for _, c := range removedCaps {
		out = append(out, Change{Kind: CapabilityRemoved, Class: ClassInformational, Entity: a.Name, Before: c,
			Impact: a.Name + " lost " + describeCaps([]string{c}) + "."})
	}
	// Scope
	if b.Scope != a.Scope || !equalStrings(b.Roots, a.Roots) {
		if scopeRank(a.Scope) > scopeRank(b.Scope) || len(a.Roots) > len(b.Roots) && scopeRank(a.Scope) >= scopeRank(b.Scope) {
			out = append(out, Change{
				Kind: ScopeExpanded, Class: ClassSecurityRelevant, Entity: a.Name,
				Before: rootsOr(b), After: rootsOr(a),
				Impact: scopeImpact(a.Scope),
			})
		} else if b.Scope != "" && a.Scope != "" {
			out = append(out, Change{
				Kind: ScopeRestricted, Class: ClassInformational, Entity: a.Name,
				Before: rootsOr(b), After: rootsOr(a),
				Impact: "Fewer files are reachable through " + a.Name + ".",
			})
		}
	}
	if !b.EgressOpen && a.EgressOpen {
		out = append(out, Change{Kind: EgressOpened, Class: ClassSecurityRelevant, Entity: a.Name,
			Impact: a.Name + " can now reach any network destination; anything in the agent's context can leave through it."})
	} else if b.EgressOpen && !a.EgressOpen && len(a.Capabilities) > 0 {
		out = append(out, Change{Kind: EgressConstrainedK, Class: ClassInformational, Entity: a.Name,
			Impact: a.Name + " is now limited to specific destinations."})
	}
	// Agent state writes
	bs := map[string]attackpath.AgentStateTarget{}
	for _, t := range b.StateWrites {
		bs[t.Path] = t
	}
	as := map[string]bool{}
	for _, t := range a.StateWrites {
		as[t.Path] = true
		if _, ok := bs[t.Path]; !ok {
			sev := "medium"
			impact := "A modification would be trusted by future sessions."
			if t.Executes {
				sev = "high"
				impact = "A modification would run code at the next session start without any further prompt."
			}
			out = append(out, Change{Kind: StateWriteAdded, Class: ClassSecurityRelevant, Entity: a.Name, After: t.Path + " (" + t.Kind + ")", Severity: sev, Impact: impact})
		}
	}
	for p, t := range bs {
		if !as[p] {
			out = append(out, Change{Kind: StateWriteRemoved, Class: ClassInformational, Entity: a.Name, Before: p + " (" + t.Kind + ")",
				Impact: a.Name + " can no longer modify this agent-state file."})
		}
	}
	return out
}

// toolTextChanges classifies description and schema changes of tools present
// in both, plus suspicious descriptions on brand-new servers (b empty).
func toolTextChanges(b, a Server) []Change {
	var out []Change
	bt := map[string]Tool{}
	for _, t := range b.Tools {
		bt[t.Name] = t
	}
	for _, t := range a.Tools {
		prev, existed := bt[t.Name]
		if !existed {
			if b.Name == "" { // new server: flag only suspicious descriptions
				if cls, why := rules.ClassifyText(t.Description); cls == rules.TextSuspicious {
					out = append(out, Change{Kind: ToolAdded, Class: ClassSuspicious, Entity: a.Name + "." + t.Name, After: t.Description, Reason: why,
						Impact: "This tool's description reads like an instruction to the model, not a description of a tool."})
				}
			}
			continue
		}
		if prev.Description != t.Description {
			cls, reason := ClassInformational, ""
			switch c, why := rules.ClassifyText(t.Description); c {
			case rules.TextSuspicious:
				cls, reason = ClassSuspicious, why
			case rules.TextSecurityRelevant:
				cls, reason = ClassSecurityRelevant, why
			}
			// Text that only appeared in the new version is what matters.
			if cls == ClassInformational {
				if c, why := rules.ClassifyText(addedText(prev.Description, t.Description)); c != rules.TextInformational {
					cls, reason = string(c), why
				}
			}
			impact := "A tool description is what the model reads to decide when and how to call the tool. Review the new text."
			if cls == ClassSuspicious {
				impact = "The new description instructs the model rather than describing the tool. This is the shape of a tool-poisoning or rug-pull change."
			}
			out = append(out, Change{Kind: ToolDescription, Class: cls, Entity: a.Name + "." + t.Name, Before: prev.Description, After: t.Description, Reason: reason, Impact: impact})
		}
		if prev.SchemaHash != t.SchemaHash && (prev.SchemaHash != "" || t.SchemaHash != "") {
			out = append(out, Change{Kind: ToolSchema, Class: ClassInformational, Entity: a.Name + "." + t.Name,
				Impact: "The tool's input schema changed. New parameters may widen what the model can pass (paths, URLs, commands)."})
		}
	}
	return out
}

func compareHooks(before, after Environment) []Change {
	var out []Change
	key := func(h Hook) string { return h.Source + "\x00" + h.Event + "\x00" + h.Matcher }
	bm := map[string][]Hook{}
	for _, h := range before.Hooks {
		bm[key(h)] = append(bm[key(h)], h)
	}
	am := map[string][]Hook{}
	for _, h := range after.Hooks {
		am[key(h)] = append(am[key(h)], h)
	}
	for k, hs := range am {
		prev := bm[k]
		for _, h := range hs {
			if idx := indexHash(prev, h.Hash); idx >= 0 {
				continue // unchanged
			}
			if len(prev) > 0 && len(prev) == len(hs) {
				p := prev[0]
				out = append(out, Change{Kind: HookModified, Class: hookClass(h), Entity: h.Event + " hook", Before: p.Command, After: h.Command, Severity: h.Severity, Reason: h.Judgment,
					Impact: "The command that runs automatically on " + h.Event + " changed."})
			} else {
				out = append(out, Change{Kind: HookAdded, Class: hookClass(h), Entity: h.Event + " hook", After: h.Command, Severity: h.Severity, Reason: h.Judgment,
					Impact: "A new command runs automatically on every " + h.Event + " event, without a prompt."})
			}
		}
	}
	for k, hs := range bm {
		cur := am[k]
		for _, h := range hs {
			if indexHash(cur, h.Hash) < 0 && len(cur) < len(hs) {
				out = append(out, Change{Kind: HookRemoved, Class: ClassInformational, Entity: h.Event + " hook", Before: h.Command,
					Impact: "This automatic command no longer runs."})
			}
		}
	}
	return out
}

func hookClass(h Hook) string {
	switch h.Severity {
	case "critical", "high":
		return ClassSuspicious
	case "medium":
		return ClassSecurityRelevant
	}
	return ClassSecurityRelevant // any new automatic command is worth a look
}

func compareSkills(before, after Environment) []Change {
	var out []Change
	bm := map[string]Skill{}
	for _, s := range before.Skills {
		bm[s.Path] = s
	}
	am := map[string]Skill{}
	for _, s := range after.Skills {
		am[s.Path] = s
	}
	for p, s := range am {
		b, ok := bm[p]
		switch {
		case !ok:
			cls := ClassInformational
			if s.Executes {
				cls = ClassSecurityRelevant
			}
			out = append(out, Change{Kind: SkillAdded, Class: cls, Entity: s.Name, After: skillSummary(s),
				Impact: "A new persistent instruction bundle the agent will follow when it matches."})
		case b.ContentHash != s.ContentHash:
			cls := ClassSecurityRelevant
			reason := "instruction or script content changed"
			if !b.Executes && s.Executes {
				reason = "the skill now ships scripts or instructs running commands"
			}
			newDest, _ := diffStrings(b.Destinations, s.Destinations)
			if len(newDest) > 0 {
				reason += "; new destinations: " + strings.Join(newDest, ", ")
			}
			out = append(out, Change{Kind: SkillModified, Class: cls, Entity: s.Name, Before: skillSummary(b), After: skillSummary(s), Reason: reason,
				Impact: "Skill content is trusted instruction. A change here steers future sessions."})
		}
	}
	for p, s := range bm {
		if _, ok := am[p]; !ok {
			out = append(out, Change{Kind: SkillRemoved, Class: ClassInformational, Entity: s.Name, Before: skillSummary(s), Impact: "Skill removed."})
		}
	}
	return out
}

func compareInstructions(before, after Environment) []Change {
	var out []Change
	bm := map[string]Instruction{}
	for _, i := range before.Instructions {
		bm[i.Path] = i
	}
	am := map[string]Instruction{}
	for _, i := range after.Instructions {
		am[i.Path] = i
	}
	for p, i := range am {
		b, ok := bm[p]
		switch {
		case !ok:
			out = append(out, Change{Kind: InstructionAdded, Class: ClassInformational, Entity: p, Impact: "A new " + i.Kind + " file is now loaded by the agent."})
		case b.Hash != i.Hash:
			cls := ClassSecurityRelevant
			impact := "Persistent " + i.Kind + " changed; future sessions follow the new content."
			if i.Kind == "hooks" || i.Kind == "mcp-config" {
				impact = "Persistent " + i.Kind + " changed; this file can start servers or run commands at the next session."
			}
			out = append(out, Change{Kind: InstructionChanged, Class: cls, Entity: p, Impact: impact})
		}
	}
	for p, i := range bm {
		if _, ok := am[p]; !ok {
			out = append(out, Change{Kind: InstructionRemoved, Class: ClassInformational, Entity: p, Impact: i.Kind + " file no longer present."})
		}
	}
	return out
}

func compareResources(before, after Environment) []Change {
	var out []Change
	bm := map[string]Resource{}
	for _, r := range before.SensitiveResources {
		bm[r.Path] = r
	}
	am := map[string]Resource{}
	for _, r := range after.SensitiveResources {
		am[r.Path] = r
	}
	for p, r := range am {
		if _, ok := bm[p]; !ok {
			out = append(out, Change{Kind: ResourceReachable, Class: ClassSecurityRelevant, Entity: p, After: r.Access + " via " + strings.Join(r.Via, ", "),
				Impact: resourceImpact(r)})
		}
	}
	for p, r := range bm {
		if _, ok := am[p]; !ok {
			out = append(out, Change{Kind: ResourceUnreachable, Class: ClassInformational, Entity: p, Before: r.Access + " via " + strings.Join(r.Via, ", "),
				Impact: "No server reaches this any more."})
		}
	}
	return out
}

func resourceImpact(r Resource) string {
	switch r.Kind {
	case "credentials":
		return "Credential material is now within the agent's reach; combined with any egress it is an exfiltration path."
	case "agent-state":
		return "The agent can now modify state it trusts in future sessions."
	case "database":
		return "Database contents are now within the agent's reach."
	}
	return "A sensitive resource is now reachable."
}

func comparePaths(before, after Environment) (added, removed []attackpath.AttackChain) {
	key := func(c attackpath.AttackChain) string { return c.ID + "\x00" + strings.Join(c.Servers, ",") }
	bm := map[string]attackpath.AttackChain{}
	for _, c := range before.AttackPaths {
		bm[key(c)] = c
	}
	am := map[string]attackpath.AttackChain{}
	for _, c := range after.AttackPaths {
		am[key(c)] = c
	}
	for k, c := range am {
		if _, ok := bm[k]; !ok {
			added = append(added, c)
		}
	}
	for k, c := range bm {
		if _, ok := am[k]; !ok {
			removed = append(removed, c)
		}
	}
	sortChains := func(cs []attackpath.AttackChain) {
		sort.Slice(cs, func(i, j int) bool {
			if sevRank(cs[i].Severity) != sevRank(cs[j].Severity) {
				return sevRank(cs[i].Severity) > sevRank(cs[j].Severity)
			}
			return key(cs[i]) < key(cs[j])
		})
	}
	sortChains(added)
	sortChains(removed)
	return added, removed
}

// ---- helpers ---------------------------------------------------------------

func classForCaps(caps []string, base string) string {
	for _, c := range caps {
		if _, ok := dangerousCaps[c]; ok {
			return ClassSecurityRelevant
		}
	}
	return base
}

func describeCaps(caps []string) string {
	if len(caps) == 0 {
		return "no classified capabilities"
	}
	var parts []string
	for _, c := range caps {
		if d, ok := dangerousCaps[c]; ok {
			parts = append(parts, d)
		} else {
			parts = append(parts, strings.ReplaceAll(c, "-", " "))
		}
	}
	return strings.Join(parts, ", ")
}

func capImpact(added []string) string {
	if len(added) == 0 {
		return "No new capability class; the server could already do this kind of thing."
	}
	return "Brings " + describeCaps(added) + "."
}

func cmdline(s Server) string {
	if s.URL != "" {
		return s.URL
	}
	return strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
}

func rootsOr(s Server) string {
	if len(s.Roots) == 0 {
		if s.Scope == "" {
			return "(no filesystem access)"
		}
		return "(undeclared: " + s.Scope + ")"
	}
	return strings.Join(s.Roots, ", ") + " (" + s.Scope + ")"
}

func scopeRank(s string) int {
	switch s {
	case "sensitive":
		return 3
	case "unknown":
		return 2
	case "project":
		return 1
	}
	return 0
}

func scopeImpact(scope string) string {
	if scope == "sensitive" {
		return "The reachable files now include the home directory: ~/.ssh, ~/.aws, browser profiles, and every agent config file."
	}
	return "More files are reachable than before."
}

func skillSummary(s Skill) string {
	parts := []string{"hash " + s.ContentHash}
	if len(s.Scripts) > 0 {
		parts = append(parts, fmt.Sprintf("%d script(s)", len(s.Scripts)))
	}
	if len(s.Destinations) > 0 {
		parts = append(parts, "reaches "+strings.Join(s.Destinations, ", "))
	}
	return strings.Join(parts, ", ")
}

func indexHash(hs []Hook, hash string) int {
	for i, h := range hs {
		if h.Hash == hash {
			return i
		}
	}
	return -1
}

func diffStrings(before, after []string) (added, removed []string) {
	bm := map[string]bool{}
	for _, s := range before {
		bm[s] = true
	}
	am := map[string]bool{}
	for _, s := range after {
		am[s] = true
		if !bm[s] {
			added = append(added, s)
		}
	}
	for _, s := range before {
		if !am[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// addedText returns the words present in after but not before, so a
// classifier looks only at what a change introduced.
func addedText(before, after string) string {
	bw := map[string]bool{}
	for _, w := range strings.Fields(before) {
		bw[w] = true
	}
	var out []string
	for _, w := range strings.Fields(after) {
		if !bw[w] {
			out = append(out, w)
		}
	}
	return strings.Join(out, " ")
}
