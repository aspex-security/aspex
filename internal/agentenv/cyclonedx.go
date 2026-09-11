package agentenv

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CycloneDX export: the subset of the environment that maps cleanly onto
// CycloneDX 1.5. MCP servers are components (with a purl when the package
// and pin are known and the surface fingerprint as a hash), fixed
// destinations are external references, and attack paths are vulnerabilities
// with an Aspex rating. Capabilities, filesystem scope, hooks and blast
// radius are attached as properties because the standard has no first-class
// place for them; the native ASBOM stays the authoritative form.

type cdxBOM struct {
	BOMFormat    string    `json:"bomFormat"`
	SpecVersion  string    `json:"specVersion"`
	SerialNumber string    `json:"serialNumber"`
	Version      int       `json:"version"`
	Metadata     cdxMeta   `json:"metadata"`
	Components   []cdxComp `json:"components"`
	Vulns        []cdxVuln `json:"vulnerabilities,omitempty"`
}

type cdxMeta struct {
	Timestamp  string    `json:"timestamp"`
	Tools      []cdxTool `json:"tools"`
	Component  cdxComp   `json:"component"`
	Properties []cdxProp `json:"properties,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComp struct {
	Type       string    `json:"type"`
	BOMRef     string    `json:"bom-ref"`
	Name       string    `json:"name"`
	Version    string    `json:"version,omitempty"`
	PURL       string    `json:"purl,omitempty"`
	Hashes     []cdxHash `json:"hashes,omitempty"`
	ExtRefs    []cdxRef  `json:"externalReferences,omitempty"`
	Properties []cdxProp `json:"properties,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type cdxProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxVuln struct {
	ID             string       `json:"id"`
	Source         cdxSource    `json:"source"`
	Ratings        []cdxRating  `json:"ratings"`
	Description    string       `json:"description"`
	Detail         string       `json:"detail,omitempty"`
	Recommendation string       `json:"recommendation,omitempty"`
	Affects        []cdxAffects `json:"affects"`
	Properties     []cdxProp    `json:"properties,omitempty"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type cdxRating struct {
	Source   cdxSource `json:"source"`
	Severity string    `json:"severity"`
	Method   string    `json:"method"`
}

type cdxAffects struct {
	Ref string `json:"ref"`
}

// CycloneDX renders the environment as a CycloneDX 1.5 JSON BOM.
func CycloneDX(env Environment, version string) ([]byte, error) {
	src := cdxSource{Name: "Aspex", URL: "https://github.com/aspex-security/aspex"}
	bom := cdxBOM{
		BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1,
		SerialNumber: "urn:uuid:" + pseudoUUID(env),
		Metadata: cdxMeta{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools:     []cdxTool{{Vendor: "aspex-security", Name: "aspex", Version: version}},
			Component: cdxComp{Type: "application", BOMRef: "agent-environment", Name: "agent-environment"},
			Properties: []cdxProp{
				{"aspex:blast_radius", env.BlastRadius.Level},
				{"aspex:static", fmt.Sprintf("%t", env.Static)},
				{"aspex:schema", fmt.Sprintf("aspex-asbom/v%d", SchemaVersion)},
			},
		},
		Components: []cdxComp{},
	}
	for _, a := range env.Agents {
		bom.Components = append(bom.Components, cdxComp{Type: "application", BOMRef: "agent:" + a.Client, Name: a.Name, Properties: []cdxProp{{"aspex:kind", "agent"}, {"aspex:client", a.Client}}})
	}
	refOf := func(s Server) string { return "mcp:" + s.Client + "/" + s.Name }
	for _, s := range env.Servers {
		c := cdxComp{Type: "application", BOMRef: refOf(s), Name: s.Name, Hashes: []cdxHash{{Alg: "SHA-256", Content: s.Fingerprint}}}
		if s.Package != "" {
			c.PURL, c.Version = purlFor(s)
		}
		props := []cdxProp{{"aspex:kind", "mcp-server"}, {"aspex:client", s.Client}, {"aspex:capabilities", strings.Join(s.Capabilities, ",")}, {"aspex:identity", s.Identity}, {"aspex:tools", fmt.Sprintf("%d", len(s.Tools))}}
		if s.Scope != "" {
			props = append(props, cdxProp{"aspex:filesystem_scope", s.Scope})
		}
		if len(s.Roots) > 0 {
			props = append(props, cdxProp{"aspex:filesystem_roots", strings.Join(s.Roots, ",")})
		}
		if s.EgressOpen {
			props = append(props, cdxProp{"aspex:egress", "open"})
		}
		c.Properties = props
		for _, d := range s.Destinations {
			if d == "arbitrary https" || d == "allowlisted destinations" || d == "email recipients" {
				continue
			}
			c.ExtRefs = append(c.ExtRefs, cdxRef{Type: "distribution", URL: "https://" + d})
		}
		if s.URL != "" {
			c.ExtRefs = append(c.ExtRefs, cdxRef{Type: "website", URL: s.URL})
		}
		bom.Components = append(bom.Components, c)
	}
	for _, h := range env.Hooks {
		bom.Components = append(bom.Components, cdxComp{Type: "application", BOMRef: "hook:" + h.Hash, Name: h.Event + " hook", Hashes: []cdxHash{{Alg: "SHA-256", Content: h.Hash}},
			Properties: []cdxProp{{"aspex:kind", "hook"}, {"aspex:event", h.Event}, {"aspex:judgment", h.Judgment}, {"aspex:severity", h.Severity}}})
	}
	for _, sk := range env.Skills {
		bom.Components = append(bom.Components, cdxComp{Type: "data", BOMRef: "skill:" + sk.ContentHash, Name: sk.Name, Hashes: []cdxHash{{Alg: "SHA-256", Content: sk.ContentHash}},
			Properties: []cdxProp{{"aspex:kind", "skill"}, {"aspex:scope", sk.Scope}, {"aspex:executes", fmt.Sprintf("%t", sk.Executes)}}})
	}
	for _, p := range env.AttackPaths {
		v := cdxVuln{
			ID: p.ID + ":" + strings.Join(p.Servers, "+"), Source: src,
			Ratings:     []cdxRating{{Source: src, Severity: p.Severity, Method: "other"}},
			Description: p.Name, Detail: p.Impact + " Steps: " + strings.Join(p.Steps, " -> "), Recommendation: p.Remediation,
			Properties: []cdxProp{{"aspex:confidence", p.Confidence}, {"aspex:mitre", p.MITRETactic + " (" + p.MITRERef + ")"}, {"aspex:kind", "attack-path"}},
		}
		for _, name := range p.Servers {
			for _, s := range env.Servers {
				if s.Name == name {
					v.Affects = append(v.Affects, cdxAffects{Ref: refOf(s)})
				}
			}
		}
		bom.Vulns = append(bom.Vulns, v)
	}
	return json.MarshalIndent(bom, "", "  ")
}

// purlFor builds a package URL from the command line when it names an npm or
// PyPI package with a version. Unpinned packages get no version.
func purlFor(s Server) (purl, version string) {
	pkg := s.Package
	full := strings.ToLower(s.Command + " " + strings.Join(s.Args, " "))
	// The runtime may be wrapped (a gateway that execs "npx ..."), so look at
	// the whole command line, not just argv[0].
	cmd := ""
	for _, tok := range strings.Fields(full) {
		base := tok[strings.LastIndex(tok, "/")+1:]
		switch base {
		case "npx", "npm", "bunx", "uvx", "pipx", "python", "python3":
			cmd = base
		}
		if cmd != "" {
			break
		}
	}
	switch {
	case cmd == "npx" || cmd == "npm" || cmd == "bunx" || strings.HasPrefix(pkg, "@"):
		name := pkg
		if i := strings.LastIndex(name, "@"); i > 0 {
			version = name[i+1:]
			name = name[:i]
		} else if i := strings.Index(full, pkg+"@"); i >= 0 {
			rest := full[i+len(pkg)+1:]
			version = strings.Fields(rest + " ")[0]
		}
		name = strings.TrimPrefix(name, "@")
		purl = "pkg:npm/" + name
	case cmd == "uvx" || cmd == "pipx" || cmd == "python" || cmd == "python3":
		name := pkg
		if i := strings.Index(full, pkg+"=="); i >= 0 {
			rest := full[i+len(pkg)+2:]
			version = strings.Fields(rest + " ")[0]
		}
		purl = "pkg:pypi/" + name
	default:
		return "", ""
	}
	if version != "" {
		purl += "@" + version
	}
	return purl, version
}

// pseudoUUID derives a stable UUID-shaped identifier from the environment so
// two BOMs of the same setup share a serial number.
func pseudoUUID(env Environment) string {
	var b strings.Builder
	for _, s := range env.Servers {
		b.WriteString(s.Fingerprint)
	}
	h := shortHash([]byte(b.String())) + shortHash([]byte(b.String()+"x"))
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}
