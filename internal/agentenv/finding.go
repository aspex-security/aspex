package agentenv

import (
	"strings"

	"github.com/aspex-security/aspex/internal/attackpath"
)

// Finding explanations: the stable definition of an attack-path ID, plus how
// it applies in the current environment (evidence, assumptions, what breaks
// it). This is what `aspex explain AP003` prints and what the explorer's
// inspector shows, so a finding ID becomes a linkable concept.

// Definition is the environment-independent description of a path ID.
type Definition struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Composition string   `json:"composition"` // the two capabilities
	Severity    string   `json:"severity"`    // how severity is decided
	Why         string   `json:"why"`         // why the composition matters
	Assumptions []string `json:"assumptions"` // what Aspex assumes when reporting it
	NotClaimed  []string `json:"not_claimed"` // what it never asserts
	FalsePos    []string `json:"false_positive_notes"`
	Kind        string   `json:"kind"` // "potential attack path"
}

var definitions = map[string]Definition{
	"AP001": {ID: "AP001", Name: "Potential sensitive data exfiltration path", Kind: "potential attack path",
		Composition: "a server can read local files (file-read) + a server can send data off the machine (network-send, external-send, email-send, browser)",
		Severity:    "critical when the read reaches home or credential directories and the egress is unconstrained; high for project-scoped reads or fixed channels (GitHub, Slack, email); medium or low when both are limited",
		Why:         "Anything the agent reads enters its context; anything in its context can be sent by any tool that reaches the network. An instruction from a prompt, document or tool result can chain the two.",
		Assumptions: []string{"the agent follows an instruction it receives (the trust boundary is the agent's context)", "the filesystem server's allowed roots are those in its config arguments; undeclared roots are treated as home at lower confidence", "a tool that takes a URL parameter or matches network tokens can reach the destination it names"},
		NotClaimed:  []string{"that any file was read", "that anything was transmitted", "that an instruction to do so ever arrived"},
		FalsePos:    []string{"a filesystem server scoped to a project directory next to a fixed channel is medium, not a false positive; accept it in .aspex.yaml with a reason if the project holds no secrets", "an allowlisted egress lowers severity two steps; declare the allowlist in the tool schema or description"}},
	"AP002": {ID: "AP002", Name: "Potential credential exfiltration path", Kind: "potential attack path",
		Composition: "a server exposes explicit secret or environment access (credential-read, env-read) + a server can send data off the machine",
		Severity:    "same scale as AP001, starting from critical",
		Why:         "A tool whose purpose is to read secrets removes even the need to know a path; combined with egress it is a one-instruction leak.",
		Assumptions: []string{"tools named or described as reading env, secrets, keychains or credentials do so"},
		NotClaimed:  []string{"that a secret was read or sent"},
		FalsePos:    []string{"a credential tool that vends short-lived, scoped tokens is still reported; the composition exists even if the blast radius is smaller"}},
	"AP003": {ID: "AP003", Name: "Potential persistent agent compromise path", Kind: "potential attack path",
		Composition: "external content can enter the agent's context (untrusted-ingress, browser) + a writable root reaches files future sessions trust (MCP config, hooks, CLAUDE.md, .cursorrules, memory, shell startup)",
		Severity:    "critical when a reachable file executes at the next session start (.mcp.json, ~/.claude.json, hooks, shell rc files); high for instruction files",
		Why:         "A modification made in one session shapes every later one. If the writable state is MCP config or a hook, the next session starts arbitrary code without any further instruction.",
		Assumptions: []string{"the writable root's reach is computed from its allowed roots against the known agent-state file locations", "user-global state has a larger blast radius than a project's own files"},
		NotClaimed:  []string{"that any agent-state file was modified", "that the ingress content contained an instruction"},
		FalsePos:    []string{"a project-scoped filesystem server reaches the project's own .mcp.json; that is a real, medium-to-critical composition (the repo can reconfigure the agent), accept it with a reason if the repo is trusted", "the writable half alone is MCP200, a configuration finding, not a path"}},
	"AP004": {ID: "AP004", Name: "Potential memory poisoning path", Kind: "potential attack path",
		Composition: "external content can enter the agent's context + a memory server persists what the agent remembers",
		Severity:    "medium: memories steer later sessions but do not execute code",
		Why:         "Web search results or fetched pages could plant facts the agent will trust later.",
		Assumptions: []string{"memory servers persist across sessions"},
		NotClaimed:  []string{"that any memory was written"},
		FalsePos:    []string{"a memory server used only by the user's own prompts still composes with any ingress; scope or remove ingress if this matters"}},
	"AP005": {ID: "AP005", Name: "Potential remote control path", Kind: "potential attack path",
		Composition: "command execution (shell-exec) + unconstrained network egress",
		Severity:    "critical; high when egress is allowlisted",
		Why:         "Execution plus an outbound channel is the shape of remote control over the machine.",
		Assumptions: []string{"a shell can run anything the user can"},
		NotClaimed:  []string{"that any command ran at an instruction's request"},
		FalsePos:    []string{"a sandboxed shell without network is not detected as such; if yours is, accept AP005 with that reason"}},
	"AP006": {ID: "AP006", Name: "Potential untrusted content to command execution path", Kind: "potential attack path",
		Composition: "external content can enter the agent's context + command execution, in an environment with no open egress",
		Severity:    "high",
		Why:         "Without egress the path cannot exfiltrate directly, but an instruction can still run commands.",
		Assumptions: []string{"reported only when AP005 does not already cover the shell"},
		NotClaimed:  []string{"that a command ran"},
		FalsePos:    []string{"a shell used only for the project build still composes with any ingress"}},
}

// Lookup returns the definition for a path ID.
func Lookup(id string) (Definition, bool) {
	d, ok := definitions[strings.ToUpper(id)]
	return d, ok
}

// FindingExplanation combines the definition with the current environment.
type FindingExplanation struct {
	Definition Definition               `json:"definition"`
	Present    bool                     `json:"present_in_environment"`
	Instances  []attackpath.AttackChain `json:"instances"`
	Evidence   []LabeledEvidence        `json:"evidence"`
	Controls   []Control                `json:"what_breaks_it"`
}

// LabeledEvidence is one statement with its evidence level.
type LabeledEvidence struct {
	Level string `json:"level"` // OBSERVED CONFIGURATION | INFERRED | NOT OBSERVED
	Text  string `json:"text"`
}

// ExplainFinding answers "what is APnnn and why does Aspex report it here".
func ExplainFinding(env Environment, id string, projectRoot string) (FindingExplanation, bool) {
	def, ok := Lookup(id)
	if !ok {
		return FindingExplanation{}, false
	}
	fe := FindingExplanation{Definition: def}
	for _, p := range env.AttackPaths {
		if p.ID == def.ID {
			fe.Present = true
			fe.Instances = append(fe.Instances, p)
		}
	}
	if fe.Present {
		seen := map[string]bool{}
		for _, p := range fe.Instances {
			for _, ev := range p.Evidence {
				text := ev.Server
				if ev.Tool != "" {
					text += "." + ev.Tool
				}
				text += ": " + ev.Detail
				if !seen[text] {
					seen[text] = true
					fe.Evidence = append(fe.Evidence, LabeledEvidence{Level: "OBSERVED CONFIGURATION", Text: text})
				}
			}
		}
		fe.Evidence = append(fe.Evidence, LabeledEvidence{Level: "INFERRED", Text: "these capabilities can be composed by the agent; an instruction it processes could chain them"})
		for _, n := range def.NotClaimed {
			fe.Evidence = append(fe.Evidence, LabeledEvidence{Level: "NOT OBSERVED", Text: n})
		}
		for _, p := range fe.Instances {
			for _, c := range ControlsFor(env, p, projectRoot) {
				dup := false
				for _, x := range fe.Controls {
					if x.Text == c.Text {
						dup = true
					}
				}
				if !dup {
					fe.Controls = append(fe.Controls, c)
				}
			}
		}
	}
	return fe, true
}
