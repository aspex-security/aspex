// Package score implements the mcp-scan scoring model.
package score

import "github.com/aspex-security/aspex/internal/rules"

// Band names.
const (
	BandHealthy     = "HEALTHY"
	BandNeedsReview = "NEEDS REVIEW"
	BandAtRisk      = "AT RISK"
	BandHighRisk    = "HIGH RISK"
)

// ServerScore is the computed score for a single server.
type ServerScore struct {
	Score    int
	Band     string
	Findings []rules.Finding
}

// OverallScore summarizes the scan across all servers.
type OverallScore struct {
	Score   int
	Band    string
	Servers []ServerScore
	// Finding counts by severity.
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// ScoreServer computes a 0-100 score for a single server based on its findings.
// Any critical finding caps the score at 39.
func ScoreServer(findings []rules.Finding) ServerScore {
	if len(findings) == 0 {
		return ServerScore{Score: 95, Band: BandHealthy, Findings: findings}
	}

	deductions := 0
	hasCritical := false
	for _, f := range findings {
		switch f.Severity {
		case rules.SeverityCritical:
			hasCritical = true
			deductions += 35
		case rules.SeverityHigh:
			deductions += 20
		case rules.SeverityMedium:
			deductions += 10
		case rules.SeverityLow:
			deductions += 3
		case rules.SeverityInfo:
			deductions += 1
		}
	}

	score := 100 - deductions
	if score < 0 {
		score = 0
	}
	if hasCritical && score > 39 {
		score = 39
	}

	return ServerScore{
		Score:    score,
		Band:     Band(score),
		Findings: findings,
	}
}

// Band returns the risk band for a score.
func Band(score int) string {
	switch {
	case score >= 90:
		return BandHealthy
	case score >= 70:
		return BandNeedsReview
	case score >= 40:
		return BandAtRisk
	default:
		return BandHighRisk
	}
}

// ScoreOverall computes the aggregate score across all server scores.
// Uses the worst-weighted approach: the overall score is pulled toward the lowest server score.
func ScoreOverall(servers []ServerScore) OverallScore {
	if len(servers) == 0 {
		return OverallScore{Score: 100, Band: BandHealthy}
	}

	overall := OverallScore{Servers: servers}

	minScore := 100
	total := 0
	for _, s := range servers {
		total += s.Score
		if s.Score < minScore {
			minScore = s.Score
		}
		for _, f := range s.Findings {
			switch f.Severity {
			case rules.SeverityCritical:
				overall.Critical++
			case rules.SeverityHigh:
				overall.High++
			case rules.SeverityMedium:
				overall.Medium++
			case rules.SeverityLow:
				overall.Low++
			case rules.SeverityInfo:
				overall.Info++
			}
		}
	}

	avg := total / len(servers)
	// Weight: 60% worst server, 40% average.
	weighted := (minScore*60 + avg*40) / 100
	overall.Score = weighted
	overall.Band = Band(weighted)
	return overall
}
