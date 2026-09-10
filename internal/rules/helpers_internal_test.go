package rules

import "testing"

func TestContainsToken(t *testing.T) {
	cases := []struct {
		name, tok string
		want      bool
	}{
		{"repl", "repl", true},
		{"python_repl", "repl", true},
		{"repl2", "repl", true},
		{"start-repl", "repl", true},
		{"slack_reply_to_thread", "repl", false}, // the Slack false positive
		{"replace_text", "repl", false},
		{"replicate_db", "repl", false},
		{"run_python3", "run_python", true},
		{"eval_code_v2", "eval_code", true},
		{"reevaluate", "eval", false},
	}
	for _, c := range cases {
		if got := containsToken(c.name, c.tok); got != c.want {
			t.Errorf("containsToken(%q, %q) = %v, want %v", c.name, c.tok, got, c.want)
		}
	}
}

func TestContainsHiddenUnicode(t *testing.T) {
	const zwsp = "​"
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"plain", "Get the weather forecast.", false},
		{"single zwsp at boundary is legitimate markdown noise", "Get the forecast." + zwsp + " Fast.", false},
		{"two zwsp at boundaries still tolerated", zwsp + "Get the forecast." + zwsp, false},
		{"three zwsp is smuggling", "a" + zwsp + " b" + zwsp + " c" + zwsp + " d", true},
		{"zwsp inside a word", "fore" + zwsp + "cast", true},
		{"other format char always flagged", "Get the forecast.‎", true},
		{"private use always flagged", "Get  forecast", true},
	}
	for _, c := range cases {
		if got := containsHiddenUnicode(c.in); got != c.want {
			t.Errorf("%s: containsHiddenUnicode = %v, want %v", c.name, got, c.want)
		}
	}
}
