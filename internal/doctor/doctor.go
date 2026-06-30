// Package doctor implements the fast health check for AI agent setups.
package doctor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/version"
)

const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
)

type Finding struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

type ClientResult struct {
	Client      string `json:"client"`
	Found       bool   `json:"found"`
	ServerCount int    `json:"server_count"`
}

type JSONOutput struct {
	Version  string        `json:"version"`
	Clients  []ClientResult `json:"clients"`
	Findings []Finding     `json:"findings"`
	Summary  struct {
		Critical int `json:"critical"`
		Warning  int `json:"warning"`
	} `json:"summary"`
}

var dangerousEnvPatterns = []string{
	"SECRET", "TOKEN", "KEY", "PASSWORD", "PASSWD", "CREDENTIAL",
	"API_KEY", "PRIVATE_KEY", "ACCESS_KEY",
}

var envFalsePositives = map[string]bool{
	"COLORTERM":                             true,
	"TERM_PROGRAM":                          true,
	"SSH_AUTH_SOCK":                         true,
	"DISPLAY":                               true,
	"LESS":                                  true,
	"PAGER":                                 true,
	"USE_STAGING_OAUTH":                     true,
	"USE_LOCAL_OAUTH":                       true,
	"CLAUDE_CODE_OAUTH_SCOPES":              true,
	"CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH":     true,
	"CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH": true,
	"MCP_GATEWAY_OAUTH_PROVIDERS_URL":       true,
}

func IsDangerousEnvKey(key string) bool {
	if envFalsePositives[key] {
		return false
	}
	upper := strings.ToUpper(key)
	if strings.HasSuffix(upper, "_URL") {
		return false
	}
	for _, pat := range dangerousEnvPatterns {
		if strings.Contains(upper, pat) {
			return true
		}
	}
	return false
}

func Run(jsonMode, noColor bool) error {
	allClientNames := []string{
		"claude", "cursor", "vscode", "windsurf",
		"cline", "roo-cline", "continue", "zed",
	}

	home, _ := os.UserHomeDir()

	var findings []Finding
	var clientResults []ClientResult

	for _, client := range allClientNames {
		entries, _ := discover.DiscoverAll([]string{client})
		configExists := len(entries) > 0
		if !configExists {
			configExists = clientConfigExists(client)
		}
		if configExists || len(entries) > 0 {
			clientResults = append(clientResults, ClientResult{
				Client:      client,
				Found:       true,
				ServerCount: len(entries),
			})
		} else {
			clientResults = append(clientResults, ClientResult{
				Client: client,
				Found:  false,
			})
		}
	}

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) < 1 {
			continue
		}
		if IsDangerousEnvKey(parts[0]) {
			findings = append(findings, Finding{
				Category: "environment",
				Severity: SeverityCritical,
				Title:    parts[0] + " exposed in shell env",
				Detail:   parts[0] + " - exposed in shell env - inherited by all MCP server processes",
			})
		}
	}

	allEntries, _ := discover.DiscoverAll(allClientNames)
	checkedConfigs := map[string]bool{}
	for _, entry := range allEntries {
		if checkedConfigs[entry.ConfigPath] {
			continue
		}
		checkedConfigs[entry.ConfigPath] = true
		findings = append(findings, checkConfigSecrets(entry.Client, entry.ConfigPath)...)
	}

	for _, entry := range allEntries {
		for _, arg := range entry.Args {
			if isBroadPath(arg, home) {
				sev := SeverityCritical
				detail := fmt.Sprintf("%s / %s - allowed path is %q - broad filesystem access", entry.Client, entry.Name, arg)
				if arg == home || arg == "~" {
					detail = fmt.Sprintf("%s / %s - allowed path is home dir - broad access", entry.Client, entry.Name)
				} else if arg == "/" {
					detail = fmt.Sprintf("%s / %s - allowed path is \"/\" - full root access", entry.Client, entry.Name)
				}
				findings = append(findings, Finding{
					Category: "filesystem",
					Severity: sev,
					Title:    fmt.Sprintf("%s / %s broad path", entry.Client, entry.Name),
					Detail:   detail,
				})
				break
			}
		}
	}

	for _, entry := range allEntries {
		if entry.URL == "" {
			continue
		}
		if strings.HasPrefix(entry.URL, "http://") {
			findings = append(findings, Finding{
				Category: "network",
				Severity: SeverityCritical,
				Title:    fmt.Sprintf("%s / %s uses plaintext HTTP", entry.Client, entry.Name),
				Detail:   fmt.Sprintf("%s / %s - remote server uses HTTP (not HTTPS)", entry.Client, entry.Name),
			})
		} else if !hasAuthToken(entry) {
			findings = append(findings, Finding{
				Category: "network",
				Severity: SeverityWarning,
				Title:    fmt.Sprintf("%s / %s no auth on remote server", entry.Client, entry.Name),
				Detail:   fmt.Sprintf("%s / %s - HTTPS remote server has no token-like env key", entry.Client, entry.Name),
			})
		}
	}

	if jsonMode {
		return outputJSON(clientResults, findings)
	}
	outputText(clientResults, findings, allEntries, noColor)
	return nil
}

func clientConfigExists(client string) bool {
	home, _ := os.UserHomeDir()
	paths := map[string][]string{
		"claude":   {filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")},
		"cursor":   {filepath.Join(home, ".cursor", "mcp.json")},
		"windsurf": {filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")},
		"continue": {filepath.Join(home, ".continue", "config.json")},
	}
	for _, p := range paths[client] {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func isBroadPath(arg, home string) bool {
	cleaned := filepath.Clean(arg)
	if cleaned == "/" {
		return true
	}
	if arg == "~" || arg == home {
		return true
	}
	if strings.HasPrefix(arg, "~/") && len(arg) <= 3 {
		return true
	}
	parts := strings.Split(cleaned, string(filepath.Separator))
	if len(parts) == 3 && parts[1] == "Volumes" {
		return true
	}
	return false
}

func hasAuthToken(entry discover.ServerEntry) bool {
	for _, k := range entry.EnvKeys {
		if IsDangerousEnvKey(k) {
			return true
		}
	}
	return strings.Contains(entry.URL, "@")
}

func checkConfigSecrets(client, configPath string) []Finding {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	return walkForEnvSecrets(client, configPath, raw, seen)
}

func walkForEnvSecrets(client, configPath string, v interface{}, seen map[string]bool) []Finding {
	var findings []Finding
	switch node := v.(type) {
	case map[string]interface{}:
		if envBlock, ok := node["env"]; ok {
			if envMap, ok := envBlock.(map[string]interface{}); ok {
				for k, val := range envMap {
					if seen[k] {
						continue
					}
					if IsDangerousEnvKey(k) {
						valStr, _ := val.(string)
						if valStr != "" {
							seen[k] = true
							findings = append(findings, Finding{
								Category: "config-secrets",
								Severity: SeverityCritical,
								Title:    fmt.Sprintf("%s - %s hardcoded in config", client, k),
								Detail:   fmt.Sprintf("%s - %s hardcoded in env block in %s", client, k, configPath),
							})
						}
					}
				}
			}
		}
		for _, child := range node {
			findings = append(findings, walkForEnvSecrets(client, configPath, child, seen)...)
		}
	case []interface{}:
		for _, child := range node {
			findings = append(findings, walkForEnvSecrets(client, configPath, child, seen)...)
		}
	}
	return findings
}

func AnyCategory(findings []Finding, cat string) bool {
	for _, f := range findings {
		if f.Category == cat {
			return true
		}
	}
	return false
}

func CountBySeverity(findings []Finding, sev string) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func FilterByCategory(findings []Finding, cat string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Category == cat {
			out = append(out, f)
		}
	}
	return out
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiPurple = "\033[35m"
	ansiWhite  = "\033[97m"
)

func colorFn(noColor bool, codes ...string) string {
	if noColor {
		return ""
	}
	return strings.Join(codes, "")
}

func outputText(clientResults []ClientResult, findings []Finding, allEntries []discover.ServerEntry, noColor bool) {
	c := func(codes ...string) string { return colorFn(noColor, codes...) }

	fmt.Printf("\n  %s◆%s  aspex-scan doctor  %sv%s%s\n\n",
		c(ansiPurple, ansiBold), c(ansiReset),
		c(ansiDim), version.Version, c(ansiReset),
	)

	dash := func(n int) string { return strings.Repeat("─", n) }

	fmt.Printf("  %sClients %s%s%s\n", c(ansiBold, ansiWhite), c(ansiDim), dash(50), c(ansiReset))
	var notFound []string
	for _, cr := range clientResults {
		if !cr.Found {
			notFound = append(notFound, cr.Client)
			continue
		}
		fmt.Printf("  %s✓%s  %-12s  %sconfig OK%s  ·  %d servers\n",
			c(ansiGreen), c(ansiReset), cr.Client, c(ansiDim), c(ansiReset), cr.ServerCount)
	}
	if len(notFound) > 0 {
		fmt.Printf("  %s·  not detected: %s%s\n", c(ansiDim), strings.Join(notFound, ", "), c(ansiReset))
	}
	fmt.Println()

	fmt.Printf("  %sEnvironment %s%s%s\n", c(ansiBold, ansiWhite), c(ansiDim), dash(46), c(ansiReset))
	envFindings := FilterByCategory(findings, "environment")
	for _, f := range envFindings {
		fmt.Printf("  %s✗%s  %s\n", c(ansiRed), c(ansiReset), f.Detail)
	}
	if len(envFindings) == 0 {
		fmt.Printf("  %s✓%s  %sNo risky tokens found in environment%s\n", c(ansiGreen), c(ansiReset), c(ansiDim), c(ansiReset))
	}
	fmt.Println()

	fmt.Printf("  %sConfig secrets %s%s%s\n", c(ansiBold, ansiWhite), c(ansiDim), dash(43), c(ansiReset))
	configFindings := FilterByCategory(findings, "config-secrets")
	for _, f := range configFindings {
		fmt.Printf("  %s✗%s  %s\n", c(ansiRed), c(ansiReset), f.Title)
	}
	if len(configFindings) == 0 {
		fmt.Printf("  %s✓%s  %sNo secrets hardcoded in config env blocks%s\n", c(ansiGreen), c(ansiReset), c(ansiDim), c(ansiReset))
	}
	fmt.Println()

	fmt.Printf("  %sFilesystem exposure %s%s%s\n", c(ansiBold, ansiWhite), c(ansiDim), dash(38), c(ansiReset))
	fsFindings := FilterByCategory(findings, "filesystem")
	for _, f := range fsFindings {
		fmt.Printf("  %s✗%s  %s\n", c(ansiRed), c(ansiReset), f.Detail)
	}
	if len(fsFindings) == 0 {
		fmt.Printf("  %s✓%s  %sNo broad filesystem paths detected%s\n", c(ansiGreen), c(ansiReset), c(ansiDim), c(ansiReset))
	}
	fmt.Println()

	fmt.Printf("  %sNetwork %s%s%s\n", c(ansiBold, ansiWhite), c(ansiDim), dash(50), c(ansiReset))
	netFindings := FilterByCategory(findings, "network")
	for _, f := range netFindings {
		sym := c(ansiRed) + "✗" + c(ansiReset)
		if f.Severity == SeverityWarning {
			sym = c(ansiYellow) + "⚠" + c(ansiReset)
		}
		fmt.Printf("  %s  %s\n", sym, f.Detail)
	}
	if len(netFindings) == 0 {
		fmt.Printf("  %s✓%s  %sAll remote servers use HTTPS with auth%s\n", c(ansiGreen), c(ansiReset), c(ansiDim), c(ansiReset))
	}
	fmt.Println()

	fmt.Printf("  %s%s%s\n", c(ansiDim), dash(60), c(ansiReset))
	crit := CountBySeverity(findings, SeverityCritical)
	warn := CountBySeverity(findings, SeverityWarning)

	critStr := fmt.Sprintf("%d critical", crit)
	if crit > 0 && !noColor {
		critStr = ansiRed + critStr + ansiReset
	}
	warnStr := fmt.Sprintf("%d warnings", warn)
	if warn > 0 && !noColor {
		warnStr = ansiYellow + warnStr + ansiReset
	}

	fmt.Printf("  %s  ·  %s  ·  %srun aspex-scan for full rule-based analysis%s\n\n",
		critStr, warnStr, c(ansiDim), c(ansiReset))
}

func outputJSON(clientResults []ClientResult, findings []Finding) error {
	out := JSONOutput{
		Version:  version.Version,
		Clients:  clientResults,
		Findings: findings,
	}
	out.Summary.Critical = CountBySeverity(findings, SeverityCritical)
	out.Summary.Warning = CountBySeverity(findings, SeverityWarning)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
