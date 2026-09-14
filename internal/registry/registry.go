// Package registry holds Aspex's list of MCP server packages with a known,
// published security advisory.
//
// This list must contain ONLY entries backed by a real, citable source: a CVE,
// a GitHub Security Advisory (GHSA), or a maintainer's published disclosure,
// recorded in Source. Aspex asserts, on real users' machines, that a named
// third-party package is vulnerable and names a fixed version; making that
// claim without a verifiable source is both wrong and unfair to the package's
// maintainers, and it breaks Aspex's promise that findings are computed from
// evidence, never generated. An entry with an empty Source must not ship.
//
// The list is intentionally empty until entries meet that bar. Aspex still
// detects dangerous capabilities and compositions from each server's actual
// tool surface (the MCPxxx and APxxx rules); those do not depend on this list.
// Contributions welcome: add an entry with its CVE/GHSA and the commit or
// release that fixed it.
package registry

// Entry is one MCP server package with a published security advisory.
type Entry struct {
	Package  string   // npm package name, e.g. "@some/mcp-server"
	Version  string   // affected version range, e.g. "<1.2.0" or "*"
	RuleIDs  []string // aspex-scan rules that characterise the issue
	Severity string   // "critical", "high", "medium", "low"
	Summary  string   // one sentence, from the cited advisory
	FixedIn  string   // version that fixed it, or "" if unfixed
	CVE      string   // CVE ID, if assigned
	Source   string   // REQUIRED: URL of the CVE/GHSA/disclosure this entry cites
	Reported string   // date reported, YYYY-MM-DD
}

// entries is the shipped advisory list. It is empty by design: see the package
// doc. Do not add an entry without a real, citable Source.
var entries = []Entry{}

// Lookup returns the Entry for a given npm package name, or nil if the package
// has no known published advisory in the list.
func Lookup(pkg string) *Entry {
	for i := range entries {
		if entries[i].Package == pkg {
			return &entries[i]
		}
	}
	return nil
}
