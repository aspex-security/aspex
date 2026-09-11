package trace

import (
	"fmt"
	"time"

	"github.com/aspex-security/aspex/internal/logparse"
)

// Evidence levels. Every conclusion aspex-trace draws from a sequence of
// events is labeled with how well the log supports it:
//
//	OBSERVED  the log contains this event; the statement is a fact about the log
//	INFERRED  a relationship between observed events, drawn from order and timing
//	POSSIBLE  a consequence the observed events would allow but the log cannot show
//
// "A happened before B" is observed. "A caused B" is at best inferred.
// "Credentials left the machine" is possible unless the payload is in the log.
const (
	Observed = "OBSERVED"
	Inferred = "INFERRED"
	Possible = "POSSIBLE"
)

// Evidence is one labeled statement supporting a conclusion.
type Evidence struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

// ObservedEvent renders an event as an OBSERVED statement.
func ObservedEvent(ev logparse.Event, what string) Evidence {
	ts := ""
	if !ev.Timestamp.IsZero() {
		ts = ev.Timestamp.Format("15:04:05") + " "
	}
	return Evidence{Level: Observed, Text: fmt.Sprintf("%s%s.%s %s", ts, ev.Server, ev.Tool, what)}
}

// InferredRelation states that two observed events may be related, and why.
func InferredRelation(delta time.Duration, sameSession bool, why string) Evidence {
	ctx := "in the same session"
	if !sameSession {
		ctx = "in different sessions"
	}
	return Evidence{Level: Inferred, Text: fmt.Sprintf("the two calls are %s apart %s; %s", delta.Truncate(time.Second), ctx, why)}
}

// PossibleConsequence states what the observed events would allow, and what
// the log lacks to establish it.
func PossibleConsequence(text string) Evidence {
	return Evidence{Level: Possible, Text: text}
}
