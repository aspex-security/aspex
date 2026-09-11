package rules

import (
	"regexp"
	"strings"
)

// TextClass is how a piece of tool or prompt text should be treated when it
// appears or changes: plain prose, prose that touches security-relevant
// things, or text that reads like an instruction aimed at the model.
type TextClass string

const (
	TextInformational    TextClass = "informational"
	TextSecurityRelevant TextClass = "security-relevant"
	TextSuspicious       TextClass = "suspicious"
)

var sensitiveMention = regexp.MustCompile(`(?i)(~/\.ssh|\.ssh/|\.aws/|\.gnupg|\.kube/|\.env\b|id_rsa|credentials?|api[_ -]?keys?|secrets?|passwords?|tokens?|keychain|/etc/passwd|/etc/shadow)`)
var actionMention = regexp.MustCompile(`(?i)\b(before (answering|responding|proceeding)|first,? (read|inspect|run|execute|send|upload)|also (send|upload|post|read)|then (send|upload|post)|curl\s|wget\s|base64|/dev/tcp|exfiltrat|silently|do not (tell|mention|inform)|without (telling|informing|asking))\b`)

// ClassifyText judges free text from a server (a tool description, a prompt).
// It is deliberately conservative: injection phrasing or a hidden-action
// pattern is suspicious; a mere mention of credentials or paths is
// security-relevant; anything else is informational. The reason names the
// matched fragment so a reviewer can see why.
func ClassifyText(text string) (TextClass, string) {
	if strings.TrimSpace(text) == "" {
		return TextInformational, ""
	}
	for _, pat := range injectionPhrasePatterns {
		if m := pat.FindString(text); m != "" {
			return TextSuspicious, "instruction-override phrasing: " + trimFrag(m)
		}
	}
	if m := actionMention.FindString(text); m != "" {
		if s := sensitiveMention.FindString(text); s != "" {
			return TextSuspicious, "directs an action involving " + trimFrag(s) + ": " + trimFrag(m)
		}
		return TextSecurityRelevant, "directs a hidden or out-of-band action: " + trimFrag(m)
	}
	if m := sensitiveMention.FindString(text); m != "" {
		return TextSecurityRelevant, "mentions " + trimFrag(m)
	}
	return TextInformational, ""
}

func trimFrag(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}
