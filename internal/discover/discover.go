// Package discover locates MCP client configuration files on the local machine.
package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Client names.
const (
	ClientClaudeDesktop = "claude"
	ClientClaudeCode    = "claude-code" // Claude Code CLI / desktop app: ~/.claude.json, project .mcp.json, installed plugins
	ClientCursor        = "cursor"
	ClientVSCode        = "vscode"
	ClientWindsurf      = "windsurf"
	ClientCline         = "cline"
	ClientRooCline      = "roo-cline" // Roo Code (fork of Cline), ext ID: RooVSCode.roo-cline
	ClientContinue      = "continue"  // Continue.dev
	ClientZed           = "zed"       // Zed editor context servers
)

// ServerEntry represents one MCP server entry from a client config.
type ServerEntry struct {
	Name       string
	Client     string
	ConfigPath string
	Command    string
	Args       []string
	EnvKeys    []string // key names only, never values
	// PlaintextEnvKeys is the subset of EnvKeys whose value is a literal in the
	// config file, not a $(...)/${...} reference and not empty. Values are never
	// stored; only which keys hold a literal. Lets rules tell a plaintext secret
	// from one resolved at runtime from a keychain or the environment.
	PlaintextEnvKeys []string
	URL              string // for HTTP/SSE servers
	Description      string // from metadata.description, if present
	Disabled         bool
	// OAuth is true when the config declares an OAuth flow for a remote server
	// (Claude Code plugins do this). Such servers authenticate without a token
	// in env, so "no auth token" rules must not fire on them.
	OAuth bool
}

// clientConfigPaths returns candidate config file paths for the given client on the current OS.
func clientConfigPaths(client string) []string {
	home, _ := os.UserHomeDir()
	switch client {
	case ClientClaudeDesktop:
		if runtime.GOOS == "windows" {
			appdata := os.Getenv("APPDATA")
			return []string{filepath.Join(appdata, "Claude", "claude_desktop_config.json")}
		}
		if runtime.GOOS == "darwin" {
			return []string{filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")}
		}
		// Linux
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
		return []string{filepath.Join(configHome, "Claude", "claude_desktop_config.json")}

	case ClientClaudeCode:
		return claudeCodeConfigPaths(home)

	case ClientCursor:
		if runtime.GOOS == "windows" {
			appdata := os.Getenv("APPDATA")
			return []string{filepath.Join(appdata, "Cursor", "User", "mcp.json")}
		}
		return []string{filepath.Join(home, ".cursor", "mcp.json")}

	case ClientVSCode:
		if runtime.GOOS == "windows" {
			appdata := os.Getenv("APPDATA")
			return []string{filepath.Join(appdata, "Code", "User", "settings.json")}
		}
		if runtime.GOOS == "darwin" {
			return []string{filepath.Join(home, "Library", "Application Support", "Code", "User", "settings.json")}
		}
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
		return []string{filepath.Join(configHome, "Code", "User", "settings.json")}

	case ClientWindsurf:
		if runtime.GOOS == "windows" {
			appdata := os.Getenv("APPDATA")
			return []string{filepath.Join(appdata, "Windsurf", "User", "mcp_config.json")}
		}
		return []string{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")}

	case ClientCline:
		if runtime.GOOS == "windows" {
			appdata := os.Getenv("APPDATA")
			return []string{filepath.Join(appdata, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")}
		}
		if runtime.GOOS == "darwin" {
			return []string{filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")}
		}
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
		return []string{filepath.Join(configHome, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")}

	case ClientRooCline:
		// Roo Code (formerly Roo-Cline) uses the same JSON format as Cline.
		// Extension ID: RooVSCode.roo-cline
		if runtime.GOOS == "windows" {
			appdata := os.Getenv("APPDATA")
			return []string{filepath.Join(appdata, "Code", "User", "globalStorage", "RooVSCode.roo-cline", "settings", "cline_mcp_settings.json")}
		}
		if runtime.GOOS == "darwin" {
			return []string{filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "RooVSCode.roo-cline", "settings", "cline_mcp_settings.json")}
		}
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
		return []string{filepath.Join(configHome, "Code", "User", "globalStorage", "RooVSCode.roo-cline", "settings", "cline_mcp_settings.json")}

	case ClientContinue:
		// Continue.dev stores MCP servers in ~/.continue/config.json (mcpServers array).
		return []string{filepath.Join(home, ".continue", "config.json")}

	case ClientZed:
		// Zed editor stores context servers (MCP) in ~/.config/zed/settings.json.
		if runtime.GOOS == "windows" {
			appdata := os.Getenv("APPDATA")
			return []string{filepath.Join(appdata, "Zed", "settings.json")}
		}
		if runtime.GOOS == "darwin" {
			return []string{filepath.Join(home, "Library", "Application Support", "Zed", "settings.json")}
		}
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
		return []string{filepath.Join(configHome, "zed", "settings.json")}
	}
	return nil
}

// claudeCodeConfigPaths lists every file Claude Code reads MCP servers from:
//   - ~/.claude.json: "mcpServers" (user scope) and "projects.<dir>.mcpServers" (local scope)
//   - ./.mcp.json: project scope, committed to the repo
//   - <plugin installPath>/.mcp.json for each plugin in ~/.claude/plugins/installed_plugins.json
//
// Servers connected through claude.ai (remote connectors) are configured in the
// cloud and have no local file; they are only visible through aspex-trace.
func claudeCodeConfigPaths(home string) []string {
	paths := []string{filepath.Join(home, ".claude.json")}
	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, ".mcp.json"))
	}
	paths = append(paths, installedPluginMCPPaths(filepath.Join(home, ".claude", "plugins", "installed_plugins.json"))...)
	return paths
}

// installedPluginMCPPaths returns <installPath>/.mcp.json for every installed
// Claude Code plugin. Only the installed cache is consulted, never the
// marketplace catalog, so uninstalled plugins are not reported as servers.
func installedPluginMCPPaths(manifest string) []string {
	data, err := os.ReadFile(manifest)
	if err != nil {
		return nil
	}
	var m struct {
		Plugins map[string][]struct {
			InstallPath string `json:"installPath"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	var paths []string
	seen := map[string]bool{}
	for _, installs := range m.Plugins {
		for _, in := range installs {
			if in.InstallPath == "" || seen[in.InstallPath] {
				continue
			}
			seen[in.InstallPath] = true
			paths = append(paths, filepath.Join(in.InstallPath, ".mcp.json"))
		}
	}
	return paths
}

// AllClients is the default discovery order.
var AllClients = []string{
	ClientClaudeDesktop,
	ClientClaudeCode,
	ClientCursor,
	ClientVSCode,
	ClientWindsurf,
	ClientCline,
	ClientRooCline,
	ClientContinue,
	ClientZed,
}

// DiscoverAll reads all known client configs and returns every server entry found.
// Errors are collected per-path and returned alongside results so callers can report partial failures.
func DiscoverAll(clients []string) ([]ServerEntry, []DiscoveryError) {
	var entries []ServerEntry
	var errs []DiscoveryError
	for _, client := range clients {
		paths := clientConfigPaths(client)
		for _, p := range paths {
			found, err := ParseConfigFile(client, p)
			if err != nil {
				errs = append(errs, DiscoveryError{Client: client, Path: p, Err: err})
				continue
			}
			entries = append(entries, found...)
		}
	}
	return entries, errs
}

// DiscoveryError records a non-fatal config parse failure.
type DiscoveryError struct {
	Client string
	Path   string
	Err    error
}

func (e DiscoveryError) Error() string {
	return fmt.Sprintf("%s (%s): %v", e.Client, e.Path, e.Err)
}

// claudeDesktopConfig is the shape of claude_desktop_config.json.
type claudeDesktopConfig struct {
	MCPServers map[string]struct {
		Command  string            `json:"command"`
		Args     []string          `json:"args"`
		Env      map[string]string `json:"env"`
		URL      string            `json:"url"`
		Disabled bool              `json:"disabled"`
	} `json:"mcpServers"`
}

// cursorMCPConfig is the shape of ~/.cursor/mcp.json.
type cursorMCPConfig struct {
	MCPServers map[string]struct {
		Command  string            `json:"command"`
		Args     []string          `json:"args"`
		Env      map[string]string `json:"env"`
		URL      string            `json:"url"`
		Disabled bool              `json:"disabled"`
		Metadata struct {
			Description string `json:"description"`
		} `json:"metadata"`
	} `json:"mcpServers"`
}

// vscodeSettings is the shape of VS Code settings.json relevant to MCP servers.
// MCP servers are stored under the "mcp.servers" key.
type vscodeSettings struct {
	MCPServers map[string]struct {
		Command  string            `json:"command"`
		Args     []string          `json:"args"`
		Env      map[string]string `json:"env"`
		URL      string            `json:"url"`
		Disabled bool              `json:"disabled"`
	} `json:"mcp.servers"`
}

// windsurfMCPConfig is the shape of Windsurf mcp_config.json (same as cursor).
type windsurfMCPConfig struct {
	MCPServers map[string]struct {
		Command  string            `json:"command"`
		Args     []string          `json:"args"`
		Env      map[string]string `json:"env"`
		URL      string            `json:"url"`
		Disabled bool              `json:"disabled"`
	} `json:"mcpServers"`
}

// clineMCPSettings is the shape of cline_mcp_settings.json (used by Cline and Roo-Cline).
type clineMCPSettings struct {
	MCPServers map[string]struct {
		Command  string            `json:"command"`
		Args     []string          `json:"args"`
		Env      map[string]string `json:"env"`
		URL      string            `json:"url"`
		Disabled bool              `json:"disabled"`
	} `json:"mcpServers"`
}

// continueMCPServer is one entry in Continue.dev's mcpServers array.
type continueMCPServer struct {
	Name    string            `json:"name"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
}

// continueConfig is the shape of ~/.continue/config.json relevant to MCP.
type continueConfig struct {
	MCPServers []continueMCPServer `json:"mcpServers"`
}

// zedContextServerCommand is Zed's nested command spec for a context server.
type zedContextServerCommand struct {
	Path string            `json:"path"`
	Args []string          `json:"args"`
	Env  map[string]string `json:"env"`
}

// zedSettings is the shape of ~/.config/zed/settings.json relevant to MCP context servers.
type zedSettings struct {
	ContextServers map[string]struct {
		Command zedContextServerCommand `json:"command"`
	} `json:"context_servers"`
}

// ParseConfigFile parses a single config file and returns server entries.
// Returns nil, nil if the file does not exist (not an error -- client simply not installed).
// ParseConfigBytes parses config content for a client as if it lived at path.
// Used to analyze a config at a git revision without checking it out. path is
// only used for ConfigPath and for relative-root resolution.
func ParseConfigBytes(client, path string, data []byte) ([]ServerEntry, error) {
	switch client {
	case ClientClaudeDesktop:
		return parseClaudeDesktop(path, data)
	case ClientClaudeCode:
		return parseClaudeCode(path, data)
	case ClientCursor:
		return parseCursor(path, data)
	case ClientVSCode:
		return parseVSCode(path, data)
	case ClientWindsurf:
		return parseWindsurf(path, data)
	case ClientCline:
		return parseCline(path, data)
	case ClientRooCline:
		return parseRooCline(path, data)
	case ClientContinue:
		return parseContinue(path, data)
	case ClientZed:
		return parseZed(path, data)
	}
	return nil, fmt.Errorf("unknown client %q", client)
}

func ParseConfigFile(client, path string) ([]ServerEntry, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	switch client {
	case ClientClaudeDesktop:
		return parseClaudeDesktop(path, data)
	case ClientClaudeCode:
		return parseClaudeCode(path, data)
	case ClientCursor:
		return parseCursor(path, data)
	case ClientVSCode:
		return parseVSCode(path, data)
	case ClientWindsurf:
		return parseWindsurf(path, data)
	case ClientCline:
		return parseCline(path, data)
	case ClientRooCline:
		return parseRooCline(path, data)
	case ClientContinue:
		return parseContinue(path, data)
	case ClientZed:
		return parseZed(path, data)
	default:
		return nil, nil
	}
}

func parseClaudeDesktop(path string, data []byte) ([]ServerEntry, error) {
	var cfg claudeDesktopConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var entries []ServerEntry
	for name, s := range cfg.MCPServers {
		entries = append(entries, ServerEntry{
			Name:             name,
			Client:           ClientClaudeDesktop,
			ConfigPath:       path,
			Command:          s.Command,
			Args:             s.Args,
			EnvKeys:          envKeys(s.Env),
			PlaintextEnvKeys: plaintextEnvKeys(s.Env),
			URL:              s.URL,
			Disabled:         s.Disabled,
		})
	}
	return entries, nil
}

// claudeCodeServer is one server entry in any Claude Code config file.
// "type" is "stdio" (default), "http", or "sse"; http/sse servers carry a URL.
type claudeCodeServer struct {
	Type     string            `json:"type"`
	Command  string            `json:"command"`
	Args     []string          `json:"args"`
	Env      map[string]string `json:"env"`
	URL      string            `json:"url"`
	Disabled bool              `json:"disabled"`
	OAuth    json.RawMessage   `json:"oauth"`
}

// claudeCodeConfig covers both ~/.claude.json (top-level mcpServers plus
// per-project mcpServers under "projects") and plain .mcp.json files
// (top-level mcpServers only). One shape parses all of them.
type claudeCodeConfig struct {
	MCPServers map[string]claudeCodeServer `json:"mcpServers"`
	Projects   map[string]struct {
		MCPServers map[string]claudeCodeServer `json:"mcpServers"`
	} `json:"projects"`
}

func parseClaudeCode(path string, data []byte) ([]ServerEntry, error) {
	var cfg claudeCodeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var entries []ServerEntry
	add := func(name string, s claudeCodeServer, scope string) {
		entries = append(entries, ServerEntry{
			Name:             name,
			Client:           ClientClaudeCode,
			ConfigPath:       path,
			Command:          s.Command,
			Args:             s.Args,
			EnvKeys:          envKeys(s.Env),
			PlaintextEnvKeys: plaintextEnvKeys(s.Env),
			URL:              s.URL,
			Description:      scope,
			Disabled:         s.Disabled,
			OAuth:            len(s.OAuth) > 0 && string(s.OAuth) != "null",
		})
	}
	for name, s := range cfg.MCPServers {
		add(name, s, "")
	}
	for project, p := range cfg.Projects {
		for name, s := range p.MCPServers {
			add(name, s, "project: "+project)
		}
	}
	return entries, nil
}

func parseCursor(path string, data []byte) ([]ServerEntry, error) {
	var cfg cursorMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var entries []ServerEntry
	for name, s := range cfg.MCPServers {
		entries = append(entries, ServerEntry{
			Name:             name,
			Client:           ClientCursor,
			ConfigPath:       path,
			Command:          s.Command,
			Args:             s.Args,
			EnvKeys:          envKeys(s.Env),
			PlaintextEnvKeys: plaintextEnvKeys(s.Env),
			URL:              s.URL,
			Description:      s.Metadata.Description,
			Disabled:         s.Disabled,
		})
	}
	return entries, nil
}

func parseVSCode(path string, data []byte) ([]ServerEntry, error) {
	var cfg vscodeSettings
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var entries []ServerEntry
	for name, s := range cfg.MCPServers {
		entries = append(entries, ServerEntry{
			Name:             name,
			Client:           ClientVSCode,
			ConfigPath:       path,
			Command:          s.Command,
			Args:             s.Args,
			EnvKeys:          envKeys(s.Env),
			PlaintextEnvKeys: plaintextEnvKeys(s.Env),
			URL:              s.URL,
			Disabled:         s.Disabled,
		})
	}
	return entries, nil
}

func parseWindsurf(path string, data []byte) ([]ServerEntry, error) {
	var cfg windsurfMCPConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var entries []ServerEntry
	for name, s := range cfg.MCPServers {
		entries = append(entries, ServerEntry{
			Name:             name,
			Client:           ClientWindsurf,
			ConfigPath:       path,
			Command:          s.Command,
			Args:             s.Args,
			EnvKeys:          envKeys(s.Env),
			PlaintextEnvKeys: plaintextEnvKeys(s.Env),
			URL:              s.URL,
			Disabled:         s.Disabled,
		})
	}
	return entries, nil
}

func parseCline(path string, data []byte) ([]ServerEntry, error) {
	var cfg clineMCPSettings
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var entries []ServerEntry
	for name, s := range cfg.MCPServers {
		entries = append(entries, ServerEntry{
			Name:             name,
			Client:           ClientCline,
			ConfigPath:       path,
			Command:          s.Command,
			Args:             s.Args,
			EnvKeys:          envKeys(s.Env),
			PlaintextEnvKeys: plaintextEnvKeys(s.Env),
			URL:              s.URL,
			Disabled:         s.Disabled,
		})
	}
	return entries, nil
}

func parseRooCline(path string, data []byte) ([]ServerEntry, error) {
	// Roo-Cline uses the identical JSON format as Cline.
	var cfg clineMCPSettings
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var entries []ServerEntry
	for name, s := range cfg.MCPServers {
		entries = append(entries, ServerEntry{
			Name:             name,
			Client:           ClientRooCline,
			ConfigPath:       path,
			Command:          s.Command,
			Args:             s.Args,
			EnvKeys:          envKeys(s.Env),
			PlaintextEnvKeys: plaintextEnvKeys(s.Env),
			URL:              s.URL,
			Disabled:         s.Disabled,
		})
	}
	return entries, nil
}

func parseContinue(path string, data []byte) ([]ServerEntry, error) {
	// Continue.dev uses an array (not map) for mcpServers.
	var cfg continueConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var entries []ServerEntry
	for _, s := range cfg.MCPServers {
		name := s.Name
		if name == "" {
			name = s.Command
		}
		entries = append(entries, ServerEntry{
			Name:             name,
			Client:           ClientContinue,
			ConfigPath:       path,
			Command:          s.Command,
			Args:             s.Args,
			EnvKeys:          envKeys(s.Env),
			PlaintextEnvKeys: plaintextEnvKeys(s.Env),
			URL:              s.URL,
		})
	}
	return entries, nil
}

func parseZed(path string, data []byte) ([]ServerEntry, error) {
	// Zed uses "context_servers" (their MCP wrapper terminology).
	var cfg zedSettings
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var entries []ServerEntry
	for name, s := range cfg.ContextServers {
		entries = append(entries, ServerEntry{
			Name:             name,
			Client:           ClientZed,
			ConfigPath:       path,
			Command:          s.Command.Path,
			Args:             s.Command.Args,
			EnvKeys:          envKeys(s.Command.Env),
			PlaintextEnvKeys: plaintextEnvKeys(s.Command.Env),
		})
	}
	return entries, nil
}

func envKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// plaintextEnvKeys returns the keys whose value is a literal secret rather than
// a reference resolved at runtime. The value itself is never returned or stored.
func plaintextEnvKeys(m map[string]string) []string {
	var keys []string
	for k, v := range m {
		if isRuntimeRef(v) {
			continue
		}
		keys = append(keys, k)
	}
	return keys
}

// isRuntimeRef reports whether an env value is resolved at runtime (shell
// substitution, variable expansion, or empty) rather than a literal secret.
func isRuntimeRef(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	if strings.HasPrefix(v, "$(") || strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$") {
		return true
	}
	// op:// (1Password), vault:, keychain: style references.
	for _, pre := range []string{"op://", "vault:", "keychain:", "aws-vault:", "secret://"} {
		if strings.HasPrefix(v, pre) {
			return true
		}
	}
	return false
}
