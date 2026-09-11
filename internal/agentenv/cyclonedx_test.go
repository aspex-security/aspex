package agentenv_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/agentenv"
	"github.com/aspex-security/aspex/internal/inspect"
)

func TestCycloneDXExport(t *testing.T) {
	env := agentenv.Build([]*inspect.Server{fsHome, fetch, github}, opts)
	data, err := agentenv.CycloneDX(env, "test")
	if err != nil {
		t.Fatal(err)
	}
	var bom map[string]interface{}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatal(err)
	}
	if bom["bomFormat"] != "CycloneDX" || bom["specVersion"] != "1.5" {
		t.Errorf("header: %v %v", bom["bomFormat"], bom["specVersion"])
	}
	comps := bom["components"].([]interface{})
	var purls []string
	for _, c := range comps {
		m := c.(map[string]interface{})
		if p, ok := m["purl"].(string); ok {
			purls = append(purls, p)
		}
	}
	joined := strings.Join(purls, " ")
	if !strings.Contains(joined, "pkg:npm/modelcontextprotocol/server-filesystem@0.6.2") {
		t.Errorf("pinned npm package should get a versioned purl: %v", purls)
	}
	vulns := bom["vulnerabilities"].([]interface{})
	if len(vulns) == 0 {
		t.Fatal("attack paths should be exported as vulnerabilities")
	}
	v := vulns[0].(map[string]interface{})
	if len(v["affects"].([]interface{})) == 0 || v["recommendation"] == "" {
		t.Errorf("vulnerability must reference affected components and carry a recommendation: %v", v)
	}
	if strings.Contains(string(data), "ghp_") {
		t.Error("no secrets in the BOM")
	}
	// Stable serial for the same environment.
	data2, _ := agentenv.CycloneDX(env, "test")
	var b2 map[string]interface{}
	json.Unmarshal(data2, &b2)
	if bom["serialNumber"] != b2["serialNumber"] {
		t.Error("serial number should be stable for an unchanged environment")
	}
}

func TestPackageDetectionThroughWrapper(t *testing.T) {
	wrapped := &inspect.Server{Entry: discoverEntry("filesystem", "/Users/x/.cursor/.onyx/onyx-mcp-gw", []string{"--", "npx", "-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/Users/x"})}
	env := agentenv.Build([]*inspect.Server{wrapped}, opts)
	if env.Servers[0].Package != "@modelcontextprotocol/server-filesystem" {
		t.Errorf("package should be the real npm package, not the wrapper: %q", env.Servers[0].Package)
	}
	data, _ := agentenv.CycloneDX(env, "t")
	if !strings.Contains(string(data), "pkg:npm/modelcontextprotocol/server-filesystem@0.6.2") {
		t.Errorf("purl should be derived through the wrapper:\n%s", data)
	}
}
