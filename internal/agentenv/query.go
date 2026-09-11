package agentenv

import (
	"fmt"
	"regexp"
	"strings"
)

// Deterministic security queries over an Environment. A free-form question
// is first reduced to a bounded Query (source, verb, target) by keyword
// matching; the answer is then computed from the graph, never guessed. If a
// question cannot be reduced, Parse says so and lists the supported shapes.

// Node kinds a query can name.
type Node string

const (
	NodeUntrustedContent Node = "UNTRUSTED_CONTENT" // prompt injection, README, web page, issue, email
	NodeUser             Node = "USER"
	NodeCredentials      Node = "CREDENTIALS"     // ~/.ssh, ~/.aws, keychains, env secrets
	NodeSensitiveFiles   Node = "SENSITIVE_FILES" // anything under home
	NodeProjectFiles     Node = "PROJECT_FILES"
	NodeDatabase         Node = "DATABASE"
	NodeExternal         Node = "EXTERNAL_DESTINATION"
	NodeExec             Node = "COMMAND_EXECUTION"
	NodeAgentState       Node = "AGENT_STATE" // config, hooks, instructions
	NodeMemory           Node = "MEMORY"
	NodeBrowser          Node = "BROWSER"
	NodeEnvSecrets       Node = "ENV_SECRETS"
)

// Verb is what the question asks about the target.
type Verb string

const (
	VerbReach     Verb = "REACH"   // can X be read / accessed
	VerbExfil     Verb = "EXFIL"   // can X leave the machine
	VerbDestroy   Verb = "DESTROY" // can X be deleted / modified destructively
	VerbExecute   Verb = "EXECUTE" // can commands run
	VerbPersist   Verb = "PERSIST" // can external content change what future sessions trust
	VerbInfluence Verb = "INFLUENCE"
)

// Query is a bounded question.
type Query struct {
	Source Node `json:"source"`
	Verb   Verb `json:"verb"`
	Target Node `json:"target"`
	// Interpretation restates the question in the model's terms so the user
	// can see whether it was understood.
	Interpretation string `json:"interpretation"`
}

// Condition is one requirement for the path, met or not, with evidence.
type Condition struct {
	Met      bool   `json:"met"`
	Text     string `json:"text"`
	Evidence string `json:"evidence,omitempty"`
}

// Answer is the result of a query.
type Answer struct {
	Query      Query       `json:"query"`
	Verdict    string      `json:"verdict"` // YES | NO COMPLETE PATH | NOT APPLICABLE
	Summary    string      `json:"summary"`
	Path       []string    `json:"path,omitempty"` // hop by hop when YES
	Conditions []Condition `json:"conditions"`
	NotProven  []string    `json:"not_proven,omitempty"` // what the model cannot show
	Missing    []string    `json:"missing,omitempty"`    // capabilities absent when NO
	Confidence string      `json:"confidence"`           // high | medium | low
	Servers    []string    `json:"servers,omitempty"`
}

var (
	reCred     = regexp.MustCompile(`(?i)\b(aws|ssh|credential|secret|token|api ?key|password|keychain|private key|gpg|kube ?config|\.aws|\.ssh)`)
	reEnv      = regexp.MustCompile(`(?i)\b(env(ironment)? var|environment variable|\benv\b|\$[A-Z_]+)`)
	reDB       = regexp.MustCompile(`(?i)\b(database|db\b|sql|postgres|table|production data|customer data|records?)\b`)
	reExecT    = regexp.MustCompile(`(?i)\b(command|shell|bash|terminal|arbitrary code|run code|execute code|process)`)
	reState    = regexp.MustCompile(`(?i)\b(instructions?|claude\.md|cursorrules|config(uration)?|settings|hooks?|persistent state|mcp\.json|skills?)\b`)
	reMemory   = regexp.MustCompile(`(?i)\b(memory|memories|remember)\b`)
	reBrowser  = regexp.MustCompile(`(?i)\b(browser|cookies?|session|tabs?)\b`)
	reProject  = regexp.MustCompile(`(?i)\b(source( code| files)?|repo(sitory)?|project files?|the codebase|working tree)\b`)
	reFiles    = regexp.MustCompile(`(?i)\b(files?|filesystem|home directory|documents|downloads)\b`)
	reExfil    = regexp.MustCompile(`(?i)\b(exfiltrat\w*|leak\w*|steal\w*|send\w*|upload\w*|transmit\w*|disclos\w*|expos\w*|post\w*|ship\w*|out of|leave the machine|to (a|an|the)? ?(attacker|internet|external))`)
	reDestroy  = regexp.MustCompile(`(?i)\b(delete|drop|destroy|wipe|truncate|overwrite|corrupt|remove|modify|update|write to|alter|change)\b`)
	reExecV    = regexp.MustCompile(`(?i)\b(execute|run|spawn|launch)\b`)
	rePersist  = regexp.MustCompile(`(?i)\b(persist\w*|survive|future sessions?|next session|rewrite|poison\w*|influence|tamper)\b`)
	reReach    = regexp.MustCompile(`(?i)\b(read|access|reach|see|open|view|get to|touch)\b`)
	reExternal = regexp.MustCompile(`(?i)\b(external content|untrusted|malicious|prompt injection|injected|readme|web ?page|website|document|issue|pull request|email|attacker|third[- ]party|tool result)\b`)
	reUserSrc  = regexp.MustCompile(`(?i)\b(i|me|the user|my prompt)\b`)
)

// Parse reduces a question to a Query. ok is false when no target could be
// identified; the caller should show SupportedQuestions.
func Parse(q string) (Query, bool) {
	var out Query
	// Target: first match in priority order. Credentials beat generic files.
	switch {
	case reCred.MatchString(q):
		out.Target = NodeCredentials
	case reEnv.MatchString(q):
		out.Target = NodeEnvSecrets
	case reDB.MatchString(q):
		out.Target = NodeDatabase
	case reMemory.MatchString(q):
		out.Target = NodeMemory
	case reState.MatchString(q):
		out.Target = NodeAgentState
	case reBrowser.MatchString(q):
		out.Target = NodeBrowser
	case reExecT.MatchString(q):
		out.Target = NodeExec
	case reProject.MatchString(q):
		out.Target = NodeProjectFiles
	case reFiles.MatchString(q):
		out.Target = NodeSensitiveFiles
	default:
		return out, false
	}
	// Verb.
	switch {
	case reExfil.MatchString(q):
		out.Verb = VerbExfil
	case out.Target == NodeExec || (reExecV.MatchString(q) && !reReach.MatchString(q)):
		out.Verb = VerbExecute
		out.Target = NodeExec
	case rePersist.MatchString(q) || (reDestroy.MatchString(q) && (out.Target == NodeAgentState || out.Target == NodeMemory)):
		out.Verb = VerbPersist
		if out.Target != NodeMemory {
			out.Target = NodeAgentState
		}
	case reDestroy.MatchString(q):
		out.Verb = VerbDestroy
	default:
		out.Verb = VerbReach
	}
	// Source.
	switch {
	case reExternal.MatchString(q):
		out.Source = NodeUntrustedContent
	case reUserSrc.MatchString(q) && !reExternal.MatchString(q):
		out.Source = NodeUser
	default:
		out.Source = NodeUntrustedContent // the security question is always about what an instruction could do
	}
	out.Interpretation = interpret(out)
	return out, true
}

func interpret(q Query) string {
	src := "an instruction the agent follows (from a prompt, document, or tool result)"
	if q.Source == NodeUser {
		src = "the user"
	}
	tgt := map[Node]string{
		NodeCredentials: "credential material (~/.ssh, ~/.aws, keychains, secret stores)",
		NodeEnvSecrets:  "environment variables and secrets", NodeDatabase: "database contents",
		NodeExec: "commands on this machine", NodeAgentState: "what future sessions trust (config, hooks, instructions)",
		NodeMemory: "the agent's persistent memory", NodeBrowser: "the browser session", NodeSensitiveFiles: "files on this machine",
	}[q.Target]
	switch q.Verb {
	case VerbExfil:
		return fmt.Sprintf("Can %s cause %s to leave this machine?", src, tgt)
	case VerbDestroy:
		return fmt.Sprintf("Can %s destructively modify %s?", src, tgt)
	case VerbExecute:
		return fmt.Sprintf("Can %s run %s?", src, tgt)
	case VerbPersist:
		return fmt.Sprintf("Can %s change %s?", src, tgt)
	}
	return fmt.Sprintf("Can %s reach %s?", src, tgt)
}

// SupportedQuestions lists the shapes Parse understands.
var SupportedQuestions = []string{
	`"Can external content reach my AWS credentials?"`,
	`"Can this agent exfiltrate SSH keys?"`,
	`"Can this agent delete production data?"`,
	`"Can a malicious README run commands on my machine?"`,
	`"Can external content change my agent's instructions or hooks?"`,
	`"Can this agent poison its memory?"`,
	`"Can the agent read environment variables and send them somewhere?"`,
}

// Explain answers a question against the environment.
func Explain(env Environment, question string) (Answer, bool) {
	q, ok := Parse(question)
	if !ok {
		return Answer{}, false
	}
	return Answer_(env, q), true
}

// Answer_ answers a typed query. Exported with an underscore to keep the
// natural name for the result type; callers usually go through Explain.
func Answer_(env Environment, q Query) Answer {
	a := Answer{Query: q, Confidence: confidenceOf(env)}
	switch q.Verb {
	case VerbExfil:
		return answerExfil(env, q, a)
	case VerbExecute:
		return answerExecute(env, q, a)
	case VerbDestroy:
		return answerDestroy(env, q, a)
	case VerbPersist:
		return answerPersist(env, q, a)
	}
	return answerReach(env, q, a)
}

// ---- per-verb reasoning ----------------------------------------------------

type reader struct {
	server, tool, what string
	strong             bool // sensitive scope or explicit credential cap (vs unknown scope)
	indirect           bool // via command execution rather than a read tool
}

// readersOf finds servers able to read the target class.
func readersOf(env Environment, target Node) []reader {
	var out []reader
	for _, s := range env.Servers {
		caps := capSet(s)
		switch target {
		case NodeCredentials, NodeSensitiveFiles:
			if caps["file-read"] && (s.Scope == "sensitive" || s.Scope == "unknown") {
				what := "reads files under " + firstRoot(s)
				if target == NodeCredentials {
					what = "reads credential files such as ~/.ssh and ~/.aws (root " + firstRoot(s) + ")"
				}
				out = append(out, reader{s.Name, toolFor(s, "read"), what, s.Scope == "sensitive", false})
			}
			if caps["credential-read"] && target == NodeCredentials {
				out = append(out, reader{s.Name, toolFor(s, "cred"), "reads credential stores directly", true, false})
			}
			if caps["shell-exec"] {
				out = append(out, reader{s.Name, toolFor(s, "exec"), "can run `cat ~/.ssh/id_rsa` or any equivalent", true, true})
			}
		case NodeEnvSecrets:
			if caps["env-read"] || caps["credential-read"] {
				out = append(out, reader{s.Name, toolFor(s, "env"), "reads environment variables", true, false})
			}
			if caps["shell-exec"] {
				out = append(out, reader{s.Name, toolFor(s, "exec"), "can run `env` or `printenv`", true, true})
			}
		case NodeDatabase:
			if caps["data-read"] && isDatabase(s) {
				out = append(out, reader{s.Name, toolFor(s, "query"), "queries the database", true, false})
			}
		case NodeBrowser:
			if caps["browser"] {
				out = append(out, reader{s.Name, toolFor(s, "browser"), "controls the browser session", true, false})
			}
		case NodeProjectFiles:
			if caps["file-read"] {
				out = append(out, reader{s.Name, toolFor(s, "read"), "reads project files", true, false})
			}
		}
	}
	return out
}

type egress struct {
	server, tool, dest string
	open               bool
}

func egressesOf(env Environment) []egress {
	var out []egress
	for _, s := range env.Servers {
		caps := capSet(s)
		switch {
		case s.EgressOpen:
			out = append(out, egress{s.Name, toolFor(s, "net"), "any network destination", true})
		case caps["network-send"]:
			out = append(out, egress{s.Name, toolFor(s, "net"), "allowlisted destinations", false})
		case caps["external-send"] || caps["email-send"]:
			dest := strings.Join(s.Destinations, ", ")
			if dest == "" {
				dest = "an external service"
			}
			out = append(out, egress{s.Name, toolFor(s, "send"), dest, false})
		}
	}
	return out
}

func ingressOf(env Environment) []string {
	var out []string
	for _, s := range env.Servers {
		caps := capSet(s)
		if caps["untrusted-ingress"] || caps["browser"] {
			out = append(out, s.Name)
		}
	}
	return out
}

func answerReach(env Environment, q Query, a Answer) Answer {
	readers := readersOf(env, q.Target)
	a.Conditions = append(a.Conditions, ingressCondition(env, q))
	if len(readers) == 0 {
		a.Verdict = "NO COMPLETE PATH"
		a.Summary = "No configured server can reach " + targetNoun(q.Target) + "."
		a.Conditions = append(a.Conditions, Condition{Met: false, Text: "a server can read " + targetNoun(q.Target)})
		a.Missing = missingFor(q.Target, env)
		return a
	}
	r := pick(readers)
	a.Verdict = "YES"
	a.Summary = "A plausible path exists: " + r.server + " " + r.what + "."
	a.Conditions = append(a.Conditions, Condition{Met: true, Text: "a server can read " + targetNoun(q.Target), Evidence: hop(r.server, r.tool, "read") + ": " + r.what})
	a.Path = []string{sourceLabel(q.Source), "agent context", hop(r.server, r.tool, "read"), targetNoun(q.Target)}
	a.Servers = []string{r.server}
	a.NotProven = []string{"no runtime evidence that " + targetNoun(q.Target) + " was actually read; aspex-trace shows what was called"}
	if !r.strong {
		a.Confidence = lower(a.Confidence)
		a.Conditions = append(a.Conditions, Condition{Met: true, Text: "filesystem scope is undeclared; treated as reaching the home directory", Evidence: r.server + " has no allowed roots in its config"})
	}
	return a
}

func answerExfil(env Environment, q Query, a Answer) Answer {
	readers := readersOf(env, q.Target)
	egresses := egressesOf(env)
	a.Conditions = append(a.Conditions, ingressCondition(env, q))
	readOK := len(readers) > 0
	egOK := len(egresses) > 0
	var r reader
	var e egress
	if readOK {
		r = pick(readers)
		a.Conditions = append(a.Conditions, Condition{Met: true, Text: "a server can read " + targetNoun(q.Target), Evidence: hop(r.server, r.tool, "read") + ": " + r.what})
	} else {
		a.Conditions = append(a.Conditions, Condition{Met: false, Text: "a server can read " + targetNoun(q.Target)})
	}
	if egOK {
		e = pickEgress(egresses)
		a.Conditions = append(a.Conditions, Condition{Met: true, Text: "a server can send data off this machine", Evidence: hop(e.server, e.tool, "network") + " reaches " + e.dest})
	} else {
		a.Conditions = append(a.Conditions, Condition{Met: false, Text: "a server can send data off this machine"})
	}
	if readOK && egOK {
		a.Verdict = "YES"
		a.Summary = fmt.Sprintf("A potential exfiltration path exists: %s reads %s, %s can send it to %s.", r.server, targetNoun(q.Target), e.server, e.dest)
		a.Path = []string{targetNoun(q.Target), hop(r.server, r.tool, "read"), "agent context", hop(e.server, e.tool, "network"), e.dest}
		a.Servers = uniqSorted([]string{r.server, e.server})
		a.NotProven = []string{"no runtime evidence that " + targetNoun(q.Target) + " was transmitted; payloads are not in the logs", "whether an instruction to do so ever reached the agent"}
		if !e.open {
			a.Conditions = append(a.Conditions, Condition{Met: true, Text: "egress is a fixed channel, not arbitrary; data could still leave through it", Evidence: e.server + " -> " + e.dest})
			a.Confidence = lower(a.Confidence)
		}
		if !r.strong {
			a.Confidence = lower(a.Confidence)
		}
		return a
	}
	a.Verdict = "NO COMPLETE PATH"
	switch {
	case !readOK && !egOK:
		a.Summary = "Neither half exists: no server reads " + targetNoun(q.Target) + " and no server sends data out."
	case !readOK:
		a.Summary = "Egress exists (" + e.server + " -> " + e.dest + ") but no server can read " + targetNoun(q.Target) + "."
	default:
		a.Summary = r.server + " can read " + targetNoun(q.Target) + " but no server can send data off this machine."
	}
	a.Missing = missingFor(q.Target, env)
	if !egOK {
		a.Missing = append(a.Missing, "network egress or an external channel (fetch, browser, GitHub, Slack, email)")
	}
	return a
}

func answerExecute(env Environment, q Query, a Answer) Answer {
	a.Conditions = append(a.Conditions, ingressCondition(env, q))
	var via []string
	var evidence []string
	for _, s := range env.Servers {
		if capSet(s)["shell-exec"] {
			via = append(via, s.Name)
			evidence = append(evidence, hop(s.Name, toolFor(s, "exec"), "shell-exec"))
		}
	}
	for _, h := range env.Hooks {
		via = append(via, h.Event+" hook")
		evidence = append(evidence, "hook runs `"+truncate(h.Command, 50)+"` on "+h.Event)
	}
	for _, sk := range env.Skills {
		if sk.Executes {
			via = append(via, "skill "+sk.Name)
			evidence = append(evidence, "skill "+sk.Name+" ships scripts or instructs running commands")
		}
	}
	if len(via) == 0 {
		a.Verdict = "NO COMPLETE PATH"
		a.Summary = "No server exposes command execution, and no hooks or executing skills are configured."
		a.Conditions = append(a.Conditions, Condition{Met: false, Text: "a server, hook, or skill can run commands"})
		a.Missing = []string{"shell-exec capability (a shell, terminal, or code-execution tool)"}
		return a
	}
	a.Verdict = "YES"
	a.Summary = "Command execution is reachable via " + strings.Join(uniqSorted(via), ", ") + "."
	a.Conditions = append(a.Conditions, Condition{Met: true, Text: "a server, hook, or skill can run commands", Evidence: strings.Join(evidence, "; ")})
	a.Path = []string{sourceLabel(q.Source), "agent context", evidence[0], "process on this machine"}
	a.Servers = uniqSorted(via)
	a.NotProven = []string{"no runtime evidence of a command run at an instruction's request; see aspex-trace"}
	// Hooks run regardless of instruction; note when the only route is a hook.
	if len(env.Servers) > 0 && !anyExec(env) {
		a.Conditions = append(a.Conditions, Condition{Met: true, Text: "execution comes from hooks or skills, not from an MCP tool the agent chooses to call", Evidence: "an instruction cannot choose what a hook runs; it can only trigger the event"})
		a.Confidence = lower(a.Confidence)
	}
	return a
}

func answerDestroy(env Environment, q Query, a Answer) Answer {
	a.Conditions = append(a.Conditions, ingressCondition(env, q))
	switch q.Target {
	case NodeDatabase:
		var readers, writers []string
		for _, s := range env.Servers {
			c := capSet(s)
			if isDatabase(s) && c["data-read"] {
				readers = append(readers, s.Name)
			}
			if c["db-write"] {
				writers = append(writers, s.Name)
			}
		}
		if len(writers) > 0 {
			a.Verdict = "YES"
			a.Summary = "Destructive database capability is present: " + strings.Join(writers, ", ") + " can write."
			a.Conditions = append(a.Conditions, Condition{Met: true, Text: "a server can write to the database", Evidence: strings.Join(writers, ", ")})
			a.Path = []string{sourceLabel(q.Source), "agent context", writers[0] + " write/execute", "database"}
			a.Servers = writers
			a.NotProven = []string{"whether the database user has DELETE/DROP grants; Aspex sees the tool, not the grant"}
			return a
		}
		a.Verdict = "NO COMPLETE PATH"
		a.Conditions = append(a.Conditions, Condition{Met: len(readers) > 0, Text: "database access", Evidence: strings.Join(readers, ", ")})
		a.Conditions = append(a.Conditions, Condition{Met: false, Text: "a write-capable database tool (UPDATE, DELETE, arbitrary SQL)"})
		if len(readers) > 0 {
			a.Summary = "Database access is read-only in the tools exposed (" + strings.Join(readers, ", ") + "). No destructive path identified."
		} else {
			a.Summary = "No database server is configured."
		}
		a.Missing = []string{"UPDATE", "DELETE", "arbitrary SQL", "a destructive tool"}
		if anyExec(env) {
			a.Conditions = append(a.Conditions, Condition{Met: true, Text: "command execution exists; a database client on this machine could be driven from a shell", Evidence: strings.Join(execServers(env), ", ")})
			a.Summary += " Note: command execution exists, so a shell could reach any database client installed locally."
		}
		return a
	default:
		// Destructive file/state modification: any write-capable server over the target.
		var writers []string
		for _, s := range env.Servers {
			c := capSet(s)
			if c["file-write"] && (q.Target != NodeCredentials || s.Scope != "project") {
				writers = append(writers, s.Name)
			}
			if c["shell-exec"] {
				writers = append(writers, s.Name)
			}
		}
		if len(writers) == 0 {
			a.Verdict = "NO COMPLETE PATH"
			a.Summary = "No server can write to " + targetNoun(q.Target) + "."
			a.Conditions = append(a.Conditions, Condition{Met: false, Text: "a server can write or delete " + targetNoun(q.Target)})
			a.Missing = []string{"file-write or shell-exec capability over " + targetNoun(q.Target)}
			return a
		}
		writers = uniqSorted(writers)
		a.Verdict = "YES"
		a.Summary = strings.Join(writers, ", ") + " can write to or delete " + targetNoun(q.Target) + "."
		a.Conditions = append(a.Conditions, Condition{Met: true, Text: "a server can write or delete " + targetNoun(q.Target), Evidence: strings.Join(writers, ", ")})
		a.Path = []string{sourceLabel(q.Source), "agent context", writers[0] + " write", targetNoun(q.Target)}
		a.Servers = writers
		a.NotProven = []string{"no runtime evidence of a destructive write; see aspex-trace"}
		return a
	}
}

func answerPersist(env Environment, q Query, a Answer) Answer {
	ing := ingressCondition(env, q)
	a.Conditions = append(a.Conditions, ing)
	var writers []string
	var evidence []string
	for _, s := range env.Servers {
		c := capSet(s)
		if q.Target == NodeMemory {
			if c["memory-write"] {
				writers = append(writers, s.Name)
				evidence = append(evidence, s.Name+" persists memory")
			}
			continue
		}
		if len(s.StateWrites) > 0 {
			writers = append(writers, s.Name)
			t := s.StateWrites[0]
			ex := ""
			if t.Executes {
				ex = ", runs code at next start"
			}
			evidence = append(evidence, fmt.Sprintf("%s can write %s (%s%s)", s.Name, t.Path, t.Kind, ex))
		}
		if c["shell-exec"] {
			writers = append(writers, s.Name)
			evidence = append(evidence, s.Name+" can run any command, including editing agent config")
		}
	}
	if len(writers) == 0 {
		a.Verdict = "NO COMPLETE PATH"
		a.Summary = "No server can write " + targetNoun(q.Target) + "."
		a.Conditions = append(a.Conditions, Condition{Met: false, Text: "a server can write " + targetNoun(q.Target)})
		a.Missing = []string{"write access to agent config, hooks, instruction files, or memory"}
		return a
	}
	writers = uniqSorted(writers)
	a.Conditions = append(a.Conditions, Condition{Met: true, Text: "a server can write " + targetNoun(q.Target), Evidence: strings.Join(evidence, "; ")})
	a.Verdict = "YES"
	a.Summary = strings.Join(writers, ", ") + " can modify " + targetNoun(q.Target) + "; a change made in one session shapes every later one."
	a.Path = []string{sourceLabel(q.Source), "agent context", evidence[0], "next session trusts the modified state"}
	a.Servers = writers
	a.NotProven = []string{"no evidence any such write happened; compare with aspex-scan verify against your lockfile"}
	if !ing.Met {
		a.Confidence = lower(a.Confidence)
	}
	return a
}

// ---- helpers ---------------------------------------------------------------

func ingressCondition(env Environment, q Query) Condition {
	if q.Source == NodeUser {
		return Condition{Met: true, Text: "the user issues the instruction"}
	}
	ing := ingressOf(env)
	if len(ing) > 0 {
		return Condition{Met: true, Text: "external content enters the agent's context", Evidence: "via " + strings.Join(ing, ", ") + "; also any pasted document or prompt"}
	}
	return Condition{Met: true, Text: "external content enters the agent's context", Evidence: "no MCP server brings web or issue content in, but a pasted document, README, or prompt still can"}
}

func capSet(s Server) map[string]bool {
	m := map[string]bool{}
	for _, c := range s.Capabilities {
		m[c] = true
	}
	return m
}

func isDatabase(s Server) bool {
	l := strings.ToLower(s.Package + " " + s.Command + " " + strings.Join(s.Args, " ") + " " + s.Name)
	return strings.Contains(l, "postgres") || strings.Contains(l, "sql") || strings.Contains(l, "mongo") || strings.Contains(l, "database") || strings.Contains(l, "redis") || capSet(s)["db-write"]
}

func anyExec(env Environment) bool { return len(execServers(env)) > 0 }

func execServers(env Environment) []string {
	var out []string
	for _, s := range env.Servers {
		if capSet(s)["shell-exec"] {
			out = append(out, s.Name)
		}
	}
	return out
}

// toolFor names a representative tool for a capability class, or the class
// itself in static mode where no tool list exists.
func toolFor(s Server, class string) string {
	var toks []string
	switch class {
	case "read":
		toks = []string{"read_file", "read_text_file", "read", "cat", "get_file", "read_multiple_files"}
	case "exec":
		toks = []string{"start_process", "execute_command", "run_command", "shell", "bash", "execute", "exec", "run"}
	case "net":
		toks = []string{"fetch", "browser_navigate", "navigate", "http_request", "request", "download", "get_url"}
	case "send":
		toks = []string{"create_issue", "create_pull_request", "send_message", "post_message", "send_email", "create_comment", "add_comment"}
	case "query":
		toks = []string{"query", "execute_sql", "run_query", "read_query", "write_query", "sql"}
	case "env":
		toks = []string{"get_env", "env", "getenv", "environment"}
	case "cred":
		toks = []string{"get_secret", "get_credential", "keychain", "read_secret"}
	case "browser":
		toks = []string{"browser_navigate", "navigate", "click", "screenshot"}
	case "write":
		toks = []string{"write_file", "edit_file", "create_file", "write", "save_file"}
	case "memory":
		toks = []string{"create_entities", "store", "remember", "add_observations", "save_memory", "memory_store"}
	}
	for _, tk := range toks {
		for _, t := range s.Tools {
			if t.Name == tk {
				return t.Name
			}
		}
	}
	for _, tk := range toks {
		for _, t := range s.Tools {
			if strings.Contains(t.Name, tk) {
				return t.Name
			}
		}
	}
	if len(s.Tools) > 0 {
		return s.Tools[0].Name
	}
	return ""
}

// hop names a server.tool, or "server (capability, inferred)" when no tool
// list exists (static scan).
func hop(server, tool, class string) string {
	if tool == "" {
		return server + " (" + class + ", inferred)"
	}
	return server + "." + tool
}

func firstRoot(s Server) string {
	if len(s.Roots) > 0 {
		return s.Roots[0]
	}
	return "an undeclared root"
}

func pick(rs []reader) reader {
	for _, r := range rs {
		if r.strong && !r.indirect {
			return r
		}
	}
	for _, r := range rs {
		if r.strong {
			return r
		}
	}
	return rs[0]
}

func pickEgress(es []egress) egress {
	for _, e := range es {
		if e.open {
			return e
		}
	}
	return es[0]
}

func targetNoun(n Node) string {
	switch n {
	case NodeCredentials:
		return "credentials (~/.ssh, ~/.aws, keychains)"
	case NodeEnvSecrets:
		return "environment variables"
	case NodeDatabase:
		return "the database"
	case NodeExec:
		return "commands"
	case NodeAgentState:
		return "agent config, hooks, or instructions"
	case NodeMemory:
		return "the agent's memory"
	case NodeBrowser:
		return "the browser session"
	case NodeProjectFiles:
		return "project files"
	}
	return "files on this machine"
}

func sourceLabel(n Node) string {
	if n == NodeUser {
		return "user instruction"
	}
	return "instruction from external content (prompt, document, tool result)"
}

func missingFor(target Node, env Environment) []string {
	switch target {
	case NodeCredentials, NodeSensitiveFiles:
		return []string{"a filesystem tool whose allowed roots include the home directory", "a credential-reading tool", "command execution"}
	case NodeEnvSecrets:
		return []string{"an environment-reading tool", "command execution"}
	case NodeDatabase:
		return []string{"a database server"}
	case NodeBrowser:
		return []string{"a browser automation server"}
	}
	return nil
}

func confidenceOf(env Environment) string {
	if env.Static {
		return "medium"
	}
	return "high"
}

func lower(c string) string {
	switch c {
	case "high":
		return "medium"
	case "medium":
		return "low"
	}
	return "low"
}
