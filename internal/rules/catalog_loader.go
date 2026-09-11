package rules

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Catalog rules are authored as data, not Go. Contributors add a detection by
// appending an entry to catalog_rules.yaml and a corpus fixture under
// testdata/corpus; no scanner code changes. The YAML is embedded at build time
// and parsed once into the same rule structs the evaluators already use, so a
// data rule and a (legacy) Go rule are indistinguishable at runtime.
//
//go:embed catalog_rules.yaml
var catalogYAML []byte

// yamlCatalog is the on-disk schema. Fields are exported with tags; the
// severity is a string ("critical".."low"|"info").
type yamlCatalog struct {
	Tools []struct {
		ID         string   `yaml:"id"`
		Name       string   `yaml:"name"`
		Severity   string   `yaml:"severity"`
		Fix        string   `yaml:"fix"`
		Mapping    string   `yaml:"mapping"`
		ToolNames  []string `yaml:"tool_names"`
		DescWords  []string `yaml:"desc_words"`
		SchemaKeys []string `yaml:"schema_keys"`
	} `yaml:"tools"`
	Resources []struct {
		ID        string   `yaml:"id"`
		Name      string   `yaml:"name"`
		Severity  string   `yaml:"severity"`
		Fix       string   `yaml:"fix"`
		Mapping   string   `yaml:"mapping"`
		URIWords  []string `yaml:"uri_words"`
		MimeTypes []string `yaml:"mime_types"`
	} `yaml:"resources"`
	Prompts []struct {
		ID        string   `yaml:"id"`
		Name      string   `yaml:"name"`
		Severity  string   `yaml:"severity"`
		Fix       string   `yaml:"fix"`
		Mapping   string   `yaml:"mapping"`
		DescWords []string `yaml:"desc_words"`
		NameWords []string `yaml:"name_words"`
		MinLen    int      `yaml:"min_len"`
	} `yaml:"prompts"`
}

// These slices are populated from the embedded YAML at init. The evaluators in
// catalog.go range over them exactly as before.
var (
	toolCatalogRules     []toolCatalogRule
	resourceCatalogRules []resourceCatalogRule
	promptCatalogRules   []promptCatalogRule
)

func init() {
	var cat yamlCatalog
	if err := yaml.Unmarshal(catalogYAML, &cat); err != nil {
		panic("rules: catalog_rules.yaml is malformed: " + err.Error())
	}
	seen := map[string]bool{}
	claim := func(id string) {
		if id == "" {
			panic("rules: catalog rule with empty id")
		}
		if seen[id] {
			panic("rules: duplicate catalog rule id " + id)
		}
		seen[id] = true
	}
	for _, r := range cat.Tools {
		claim(r.ID)
		toolCatalogRules = append(toolCatalogRules, toolCatalogRule{
			ruleID: r.ID, name: r.Name, sev: mustSeverity(r.ID, r.Severity), fix: r.Fix, mapping: r.Mapping,
			toolNames: r.ToolNames, descWords: r.DescWords, schemaKeys: r.SchemaKeys,
		})
	}
	for _, r := range cat.Resources {
		claim(r.ID)
		resourceCatalogRules = append(resourceCatalogRules, resourceCatalogRule{
			ruleID: r.ID, name: r.Name, sev: mustSeverity(r.ID, r.Severity), fix: r.Fix, mapping: r.Mapping,
			uriWords: r.URIWords, mimeTypes: r.MimeTypes,
		})
	}
	for _, r := range cat.Prompts {
		claim(r.ID)
		promptCatalogRules = append(promptCatalogRules, promptCatalogRule{
			ruleID: r.ID, name: r.Name, sev: mustSeverity(r.ID, r.Severity), fix: r.Fix, mapping: r.Mapping,
			descWords: r.DescWords, nameWords: r.NameWords, minLen: r.MinLen,
		})
	}
}

func mustSeverity(id, s string) Severity {
	switch s {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info":
		return SeverityInfo
	}
	panic(fmt.Sprintf("rules: %s has invalid severity %q (want critical|high|medium|low|info)", id, s))
}
