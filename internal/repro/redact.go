// Package repro packages a suspicious investigation into a bundle that can be
// analyzed again offline, by someone else, without executing anything: the
// trace events (redacted), the environment (a lockfile-shaped BOM, which never
// holds secret values), the findings and attack paths Aspex produced, and a
// manifest. Replay re-runs the analysis over the bundle; it never runs the
// recorded tools, commands or network calls.
package repro

import (
	"regexp"
	"strings"

	"github.com/aspex-security/aspex/internal/logparse"
)

// Secret-shaped values. Conservative on purpose: a false redaction costs a
// little context; a missed token costs a credential.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bghp_[A-Za-z0-9]{20,}\b`),                                          // GitHub PAT
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),                                  // GitHub fine-grained
	regexp.MustCompile(`\bgh[oursp]_[A-Za-z0-9]{20,}\b`),                                    // GitHub app tokens
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`),                                         // OpenAI-style
	regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{16,}\b`),                                     // Anthropic
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),                                  // Slack
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                                              // AWS access key id
	regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*\S+`),                            // AWS secret in ini/env
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,}\b`),                                        // Google API key
	regexp.MustCompile(`\bya29\.[0-9A-Za-z_-]{20,}\b`),                                      // Google OAuth
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`), // JWT
	regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}`),                    // Authorization headers
	regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*["']?[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}\b`),
	regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`),
	regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{30,}\b`),
}

// credentialPathHints mark arguments whose *content* must never be exported.
var credentialPathHints = []string{".ssh/", ".aws/", ".gnupg/", ".kube/", ".docker/config", ".netrc", ".npmrc", ".pypirc", ".env", "credentials", "id_rsa", "id_ed25519", "keychain", "token.json", "secrets"}

// contentKeys are argument names that carry file or message bodies.
var contentKeys = map[string]bool{"content": true, "text": true, "body": true, "data": true, "new_string": true, "old_string": true, "message": true, "input": true, "stdin": true, "payload": true, "value": true}

const redacted = "[REDACTED]"

// RedactString removes secret-shaped substrings.
func RedactString(s string) (string, int) {
	n := 0
	for _, re := range secretPatterns {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			n++
			// Keep the recognizable prefix (ghp_, AKIA, Bearer) so the shape is
			// still visible; drop the value.
			if i := strings.IndexAny(m, "_-. :="); i > 0 && i < 12 {
				return m[:i+1] + redacted
			}
			return redacted
		})
	}
	return s, n
}

// Stats summarizes what redaction did, so the user can see it before sharing.
type Stats struct {
	SecretsRedacted   int `json:"secrets_redacted"`
	ContentDropped    int `json:"content_arguments_dropped"`
	CredentialContent int `json:"credential_file_contents_dropped"`
	Events            int `json:"events"`
}

// RedactEvents returns copies of events safe to share: secret-shaped values
// removed everywhere, content-bearing arguments replaced by a length marker,
// and any argument that carries the body of a credential file dropped. Raw
// log lines are never exported.
func RedactEvents(events []logparse.Event) ([]logparse.Event, Stats) {
	var st Stats
	out := make([]logparse.Event, 0, len(events))
	for _, ev := range events {
		cp := ev
		cp.Raw = ""
		cp.Args = nil
		// An event touches credentials when a path argument points at a
		// credential location, or when a content argument itself looks like
		// credential material (ini keys, PEM blocks).
		touchesCred := false
		for k, v := range ev.Args {
			lv := strings.ToLower(v)
			if !contentKeys[strings.ToLower(k)] {
				for _, h := range credentialPathHints {
					if strings.Contains(lv, h) {
						touchesCred = true
					}
				}
			} else if strings.Contains(lv, "aws_secret_access_key") || strings.Contains(lv, "private key-----") || strings.Contains(lv, "password") || strings.Contains(lv, "api_key") {
				touchesCred = true
			}
		}
		if len(ev.Args) > 0 {
			cp.Args = map[string]string{}
		}
		for k, v := range ev.Args {
			kl := strings.ToLower(k)
			switch {
			case contentKeys[kl] && touchesCred:
				cp.Args[k] = "[credential file content dropped]"
				st.CredentialContent++
			case contentKeys[kl]:
				cp.Args[k] = "[content dropped, " + itoa(len(v)) + " bytes]"
				st.ContentDropped++
			default:
				r, n := RedactString(v)
				st.SecretsRedacted += n
				cp.Args[k] = r
			}
		}
		if cp.Server != "" {
			cp.Server, _ = RedactString(cp.Server)
		}
		out = append(out, cp)
	}
	st.Events = len(out)
	return out, st
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
