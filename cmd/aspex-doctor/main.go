// aspex-doctor - fast local health check for your AI agent setup.
// Runs ~2 seconds and gives a visual overview of potential issues across 5 check categories.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aspex-security/aspex/internal/discover"
	"github.com/aspex-security/aspex/internal/version"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// severity levels
const (
	severityCritical = "critical"
	severityWarning  = "warning"
)

// Finding is a single health check result.
type Finding struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

// ClientResult summarizes one client's discovery.
type ClientResult struct {
	Client      string `json:"client"`
	Found       bool   `json:"found"`
	ServerCount int    `json:"server_count"`
}

// JSONOutput is the full --json output structure.
type JSONOutput struct {
	Version  string        `json:"version"`
	Clients  []ClientResult `json:"clients"`
	Findings []Finding     `json:"findings"`
	Summary  struct {
		Critical int `json:"critical"`
		Warning  int `json:"warning"`
	} `json:"summary"`
}

// dangerous patterns matched against env var key names (uppercase)
var dangerousEnvPatterns = []string{
	"SECRET", "TOKEN", "KEY", "PASSWORD", "PASSWD", "CREDENTIAL",
	"API_KEY", "PRIVATE_KEY", "ACCESS_KEY", "AUTH",
}

// false-positive env var names to skip
var envFalsePositives = map[string]bool{
	"COLORTERM":    true,
	"TERM_PROGRAM": true,
	"SSH_AUTH_SOCK": true,
	"DISPLAY":      true,
	"LESS":         true,
	"PAGER":        true,
}

func isDangerousEnvKey(key string) bool {
	if envFalsePositives[key] {
		return false
	}
	upper := strings.ToUpper(key)
	for _, pat := range dangerousEnvPatterns {
		if strings.Contains(upper, pat) {
			return true
		}
	}
	return false
}

func rootCmd() *cobra.Command {
	var jsonMode bool
	var noColor bool

	cmd := &cobra.Command{
		Use:     "aspex-doctor",
		Short:   "Fast local health check for your AI agent setup",
		Version: version.Version,
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Getenv("NO_COLOR") != "" {
				noColor = true
			}
			return run(jsonMode, noColor)
		},
	}

	cmd.Flags().BoolVar(&jsonMode, "json", false, "Output results as JSON")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color output")

	return cmd
}

func run(jsonMode, noColor bool) error {
	allClientNames := []string{
		"claude", "cursor", "vscode", "windsurf",
		"cline", "roo-cline", "continue", "zed",
	}

	home, _ := os.UserHomeDir()

	var findings []Finding
	var clientResults []ClientResult

	// ── Check 1: Clients ──────────────────────────────────────────
	for _, client := range allClientNames {
		entries, _ := discover.DiscoverAll([]string{client})
		// Determine if config file exists by checking if we got entries or if the path exists
		configExists := len(entries) > 0
		if !configExists {
			// Check if config file path exists even if empty
			configExists = clientConfigExists(client)
		}
		if configExists || len(entries) > 0 {
			clientResults = append(clientResults, ClientResult{
				Client:      client,
				Found:       true,
				ServerCount: len(entries),
			})
		} else {
			// Only include clients that might be expected (all of them for visibility, but
			// per spec: only show where config exists OR has servers - skip not-found ones
			// from text output but still track for JSON)
			clientResults = append(clientResults, ClientResult{
				Client: client,
				Found:  false,
			})
		}
	}

	// ── Check 2: Environment secrets ──────────────────────────────
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) < 1 {
			continue
		}
		key := parts[0]
		if isDangerousEnvKey(key) {
			findings = append(findings, Finding{
				Category: "environment",
				Severity: severityCritical,
				Title:    key + " exposed in shell env",
				Detail:   key + " - exposed in shell env - inherited by all MCP server processes",
			})
		}
	}
	if !anyCategory(findings, "environment") {
		// sentinel: no env findings - handled in display
	}

	// ── Check 3: Config secrets ───────────────────────────────────
	allEntries, _ := discover.DiscoverAll(allClientNames)
	// Track which config paths we've already checked for env secrets
	checkedConfigs := map[string]bool{}
	for _, entry := range allEntries {
		if checkedConfigs[entry.ConfigPath] {
			continue
		}
		checkedConfigs[entry.ConfigPath] = true
		configFindings := checkConfigSecrets(entry.Client, entry.ConfigPath)
		findings = append(findings, configFindings...)
	}

	// ── Check 4: Filesystem exposure ──────────────────────────────
	for _, entry := range allEntries {
		for _, arg := range entry.Args {
			if isBroadPath(arg, home) {
				sev := severityCritical
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
				break // one finding per server
			}
		}
	}

	// ── Check 5: Network ─────────────────────────────────────────
	for _, entry := range allEntries {
		if entry.URL == "" {
			continue
		}
		if strings.HasPrefix(entry.URL, "http://") {
			findings = append(findings, Finding{
				Category: "network",
				Severity: severityCritical,
				Title:    fmt.Sprintf("%s / %s uses plaintext HTTP", entry.Client, entry.Name),
				Detail:   fmt.Sprintf("%s / %s - remote server uses HTTP (not HTTPS)", entry.Client, entry.Name),
			})
		} else {
			// Check for missing auth: no token-like key in EnvKeys and no credentials in URL
			if !hasAuthToken(entry) {
				findings = append(findings, Finding{
					Category: "network",
					Severity: severityWarning,
					Title:    fmt.Sprintf("%s / %s no auth on remote server", entry.Client, entry.Name),
					Detail:   fmt.Sprintf("%s / %s - HTTPS remote server has no token-like env key", entry.Client, entry.Name),
				})
			}
		}
	}

	// ── Output ────────────────────────────────────────────────────
	if jsonMode {
		return outputJSON(clientResults, findings)
	}
	outputText(clientResults, findings, allEntries, noColor)
	return nil
}

func clientConfigExists(client string) bool {
	home, _ := os.UserHomeDir()
	// Map a subset of clients to known paths for existence check
	paths := map[string][]string{
		"claude":    {filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")},
		"cursor":    {filepath.Join(home, ".cursor", "mcp.json")},
		"windsurf":  {filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")},
		"continue":  {filepath.Join(home, ".continue", "config.json")},
	}
	for _, p := range paths[client] {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func isBroadPath(arg, home string) bool {
	// Normalize
	cleaned := filepath.Clean(arg)
	if cleaned == "/" {
		return true
	}
	if arg == "~" || arg == home {
		return true
	}
	// Expanded ~
	if strings.HasPrefix(arg, "~/") && len(arg) <= 3 {
		return true
	}
	// Root of a volume (e.g. /Volumes/SomeDisk)
	parts := strings.Split(cleaned, string(filepath.Separator))
	if len(parts) == 3 && parts[1] == "Volumes" {
		return true
	}
	return false
}

func hasAuthToken(entry discover.ServerEntry) bool {
	// Check EnvKeys for token-like names
	for _, k := range entry.EnvKeys {
		if isDangerousEnvKey(k) {
			return true
		}
	}
	// Check URL for embedded credentials
	if strings.Contains(entry.URL, "@") {
		return true
	}
	return false
}

func checkConfigSecrets(client, configPath string) []Finding {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}

	// Parse the raw JSON to find env blocks
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var findings []Finding
	// Walk the JSON looking for "env" objects
	findings = append(findings, walkForEnvSecrets(client, configPath, raw)...)
	return findings
}

func walkForEnvSecrets(client, configPath string, v interface{}) []Finding {
	var findings []Finding
	switch node := v.(type) {
	case map[string]interface{}:
		if envBlock, ok := node["env"]; ok {
			if envMap, ok := envBlock.(map[string]interface{}); ok {
				for k, val := range envMap {
					if isDangerousEnvKey(k) {
						valStr, _ := val.(string)
						if valStr != "" {
							// Don't print value - just flag the key
							findings = append(findings, Finding{
								Category: "config-secrets",
								Severity: severityCritical,
								Title:    fmt.Sprintf("%s - %s hardcoded in config", client, k),
								Detail:   fmt.Sprintf("%s - %s hardcoded in env block in %s", client, k, configPath),
							})
						}
					}
				}
			}
		}
		for _, child := range node {
			findings = append(findings, walkForEnvSecrets(client, configPath, child)...)
		}
	case []interface{}:
		for _, child := range node {
			findings = append(findings, walkForEnvSecrets(client, configPath, child)...)
		}
	}
	return findings
}

func anyCategory(findings []Finding, cat string) bool {
	for _, f := range findings {
		if f.Category == cat {
			return true
		}
	}
	return false
}

func countBySeverity(findings []Finding, sev string) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

func filterByCategory(findings []Finding, cat string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Category == cat {
			out = append(out, f)
		}
	}
	return out
}

// ── Text output ───────────────────────────────────────────────────────────────

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

func color(noColor bool, codes ...string) string {
	if noColor {
		return ""
	}
	return strings.Join(codes, "")
}

func outputText(clientResults []ClientResult, findings []Finding, allEntries []discover.ServerEntry, noColor bool) {
	c := func(codes ...string) string { return color(noColor, codes...) }

	fmt.Printf("\n  %s◆%s  Aspex Doctor  %sv%s%s\n\n",
		c(ansiPurple, ansiBold),
		c(ansiReset),
		c(ansiDim), version.Version, c(ansiReset),
	)

	sep := strings.Repeat("─", 60)

	// ── Clients ──
	fmt.Printf("  %sClients %s%s%s\n", c(ansiBold, ansiWhite), c(ansiDim), sep[:52], c(ansiReset))
	for _, cr := range clientResults {
		// Only show clients where config was found or that have servers
		if !cr.Found {
			fmt.Printf("  %s✗%s  %-12s  %sconfig not found%s\n",
				c(ansiRed), c(ansiReset),
				cr.Client,
				c(ansiDim), c(ansiReset),
			)
			continue
		}
		fmt.Printf("  %s✓%s  %-12s  %sconfig OK%s  ·  %d servers\n",
			c(ansiGreen), c(ansiReset),
			cr.Client,
			c(ansiDim), c(ansiReset),
			cr.ServerCount,
		)
	}
	fmt.Println()

	// ── Environment ──
	fmt.Printf("  %sEnvironment %s%s%s\n", c(ansiBold, ansiWhite), c(ansiDim), sep[:48], c(ansiReset))
	envFindings := filterByCategory(findings, "environment")
	for _, f := range envFindings {
		fmt.Printf("  %s✗%s  %s\n", c(ansiRed), c(ansiReset), f.Detail)
	}
	if len(envFindings) == 0 {
		fmt.Printf("  %s✓%s  %sNo risky tokens found in environment%s\n",
			c(ansiGreen), c(ansiReset), c(ansiDim), c(ansiReset))
	}
	fmt.Println()

	// ── Config secrets ──
	fmt.Printf("  %sConfig secrets %s%s%s\n", c(ansiBold, ansiWhite), c(ansiDim), sep[:44], c(ansiReset))
	configFindings := filterByCategory(findings, "config-secrets")
	for _, f := range configFindings {
		fmt.Printf("  %s✗%s  %s\n", c(ansiRed), c(ansiReset), f.Title)
	}
	if len(configFindings) == 0 {
		fmt.Printf("  %s✓%s  %sNo secrets hardcoded in config env blocks%s\n",
			c(ansiGreen), c(ansiReset), c(ansiDim), c(ansiReset))
	}
	fmt.Println()

	// ── Filesystem exposure ──
	fmt.Printf("  %sFilesystem exposure %s%s%s\n", c(ansiBold, ansiWhite), c(ansiDim), sep[:40], c(ansiReset))
	fsFindings := filterByCategory(findings, "filesystem")
	for _, f := range fsFindings {
		fmt.Printf("  %s✗%s  %s\n", c(ansiRed), c(ansiReset), f.Detail)
	}
	if len(fsFindings) == 0 {
		fmt.Printf("  %s✓%s  %sNo broad filesystem paths detected%s\n",
			c(ansiGreen), c(ansiReset), c(ansiDim), c(ansiReset))
	}
	fmt.Println()

	// ── Network ──
	fmt.Printf("  %sNetwork %s%s%s\n", c(ansiBold, ansiWhite), c(ansiDim), sep[:52], c(ansiReset))
	netFindings := filterByCategory(findings, "network")
	for _, f := range netFindings {
		sym := c(ansiRed) + "✗" + c(ansiReset)
		if f.Severity == severityWarning {
			sym = c(ansiYellow) + "⚠" + c(ansiReset)
		}
		fmt.Printf("  %s  %s\n", sym, f.Detail)
	}
	if len(netFindings) == 0 {
		fmt.Printf("  %s✓%s  %sAll remote servers use HTTPS with auth%s\n",
			c(ansiGreen), c(ansiReset), c(ansiDim), c(ansiReset))
	}
	fmt.Println()

	// ── Summary ──
	fmt.Printf("  %s%s%s\n", c(ansiDim), sep, c(ansiReset))
	crit := countBySeverity(findings, severityCritical)
	warn := countBySeverity(findings, severityWarning)

	critStr := fmt.Sprintf("%d critical", crit)
	if crit > 0 && !noColor {
		critStr = ansiRed + critStr + ansiReset
	}
	warnStr := fmt.Sprintf("%d warnings", warn)
	if warn > 0 && !noColor {
		warnStr = ansiYellow + warnStr + ansiReset
	}

	fmt.Printf("  %s  ·  %s  ·  %srun aspex-scan for full rule-based analysis%s\n\n",
		critStr, warnStr, c(ansiDim), c(ansiReset),
	)
}

// ── JSON output ───────────────────────────────────────────────────────────────

func outputJSON(clientResults []ClientResult, findings []Finding) error {
	out := JSONOutput{
		Version:  version.Version,
		Clients:  clientResults,
		Findings: findings,
	}
	out.Summary.Critical = countBySeverity(findings, severityCritical)
	out.Summary.Warning = countBySeverity(findings, severityWarning)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
