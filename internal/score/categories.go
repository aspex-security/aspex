package score

import "github.com/aspex-security/aspex/internal/rules"

// Category is a security dimension used in the breakdown score.
type Category string

const (
	CatPromptSecurity  Category = "Prompt Security"
	CatToolSecurity    Category = "Tool Security"
	CatDataProtection  Category = "Data Protection"
	CatSupplyChain     Category = "Supply Chain"
	CatNetworkSecurity Category = "Network Security"
	CatAccessControl   Category = "Access Control"
)

// CategoryScore is the score for a single security dimension.
type CategoryScore struct {
	Category    Category
	Score       int    // 0–100
	Grade       string // A+ A A- B+ B B- C+ C D F
	Driver      string // short explanation of the main contributor
	FindingCount int
}

// Breakdown holds category scores for a full scan.
type Breakdown struct {
	Categories []CategoryScore
}

// ruleCategory maps each rule ID to its primary security category.
var ruleCategory = map[string]Category{
	// Prompt Security
	"MCP001": CatPromptSecurity,
	"MCP002": CatPromptSecurity,
	"MCP016": CatPromptSecurity, // known-bad registry
	"MCP150": CatPromptSecurity,
	"MCP151": CatPromptSecurity,
	"MCP152": CatPromptSecurity,

	// Tool Security
	"MCP003": CatToolSecurity,
	"MCP004": CatToolSecurity,
	"MCP012": CatToolSecurity, // browser automation
	"MCP021": CatToolSecurity, // screenshot
	"MCP024": CatToolSecurity, // process listing
	"MCP025": CatToolSecurity, // clipboard
	"MCP027": CatToolSecurity, // container exec
	"MCP028": CatToolSecurity, // k8s exec
	"MCP034": CatToolSecurity, // REPL/eval
	"MCP035": CatToolSecurity,
	"MCP036": CatToolSecurity,
	"MCP037": CatToolSecurity,
	"MCP038": CatToolSecurity,

	// Data Protection
	"MCP005": CatDataProtection, // file read + net exfil
	"MCP006": CatDataProtection, // env var read
	"MCP009": CatDataProtection, // credential file access
	"MCP011": CatDataProtection, // SSH key
	"MCP014": CatDataProtection, // DB write
	"MCP019": CatDataProtection, // secrets manager
	"MCP040": CatDataProtection,
	"MCP041": CatDataProtection,
	"MCP042": CatDataProtection,
	"MCP043": CatDataProtection,
	"MCP044": CatDataProtection,
	"MCP045": CatDataProtection,

	// Supply Chain
	"MCP007": CatSupplyChain,
	"MCP010": CatSupplyChain, // git config write
	"MCP018": CatSupplyChain, // CI/CD modification
	"MCP022": CatSupplyChain, // npm/pip publish
	"MCP029": CatSupplyChain, // config management
	"MCP030": CatSupplyChain, // IaC apply/destroy
	"MCP031": CatSupplyChain, // container image push
	"MCP032": CatSupplyChain, // package manager exec
	"MCP033": CatSupplyChain, // build system
	"MCP046": CatSupplyChain,
	"MCP047": CatSupplyChain,
	"MCP048": CatSupplyChain,

	// Network Security
	"MCP008": CatNetworkSecurity, // outbound exfil
	"MCP013": CatNetworkSecurity, // email send
	"MCP015": CatNetworkSecurity, // cloud CLI
	"MCP017": CatNetworkSecurity, // GitHub token scope
	"MCP023": CatNetworkSecurity, // DNS manipulation
	"MCP049": CatNetworkSecurity,
	"MCP050": CatNetworkSecurity,

	// Access Control
	"MCP020": CatAccessControl, // memory/state write
	"MCP026": CatAccessControl, // calendar/contacts
	"MCP039": CatAccessControl,
}

// categoryOf returns the category for a rule ID, defaulting to ToolSecurity.
func categoryOf(ruleID string) Category {
	if c, ok := ruleCategory[ruleID]; ok {
		return c
	}
	return CatToolSecurity
}

// LetterGrade converts a 0-100 score to a letter grade.
func LetterGrade(score int) string {
	switch {
	case score >= 97:
		return "A+"
	case score >= 93:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 87:
		return "B+"
	case score >= 83:
		return "B"
	case score >= 80:
		return "B-"
	case score >= 77:
		return "C+"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// categoryDriver returns a short explanation for what drove a category score.
func categoryDriver(cat Category, findings []rules.Finding) string {
	if len(findings) == 0 {
		return "No issues detected"
	}
	// Find the most severe finding name.
	worst := findings[0]
	for _, f := range findings[1:] {
		if f.Severity > worst.Severity {
			worst = f
		}
	}
	return worst.Name
}

// ScoreBreakdown computes per-category scores from all findings across all servers.
func ScoreBreakdown(servers []ServerScore) Breakdown {
	// Bucket findings by category.
	byCategory := map[Category][]rules.Finding{}
	for _, s := range servers {
		for _, f := range s.Findings {
			cat := categoryOf(f.RuleID)
			byCategory[cat] = append(byCategory[cat], f)
		}
	}

	allCats := []Category{
		CatPromptSecurity,
		CatToolSecurity,
		CatDataProtection,
		CatSupplyChain,
		CatNetworkSecurity,
		CatAccessControl,
	}

	var categories []CategoryScore
	for _, cat := range allCats {
		findings := byCategory[cat]
		catScore := scoreFromFindings(findings)
		categories = append(categories, CategoryScore{
			Category:     cat,
			Score:        catScore,
			Grade:        LetterGrade(catScore),
			Driver:       categoryDriver(cat, findings),
			FindingCount: len(findings),
		})
	}

	return Breakdown{Categories: categories}
}

func scoreFromFindings(findings []rules.Finding) int {
	if len(findings) == 0 {
		return 100
	}
	deductions := 0
	hasCritical := false
	for _, f := range findings {
		switch f.Severity {
		case rules.SeverityCritical:
			hasCritical = true
			deductions += 40
		case rules.SeverityHigh:
			deductions += 25
		case rules.SeverityMedium:
			deductions += 12
		case rules.SeverityLow:
			deductions += 4
		case rules.SeverityInfo:
			deductions += 1
		}
	}
	s := 100 - deductions
	if s < 0 {
		s = 0
	}
	if hasCritical && s > 39 {
		s = 39
	}
	return s
}
