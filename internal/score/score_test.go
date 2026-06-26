package score_test

import (
	"testing"

	"github.com/aspex-security/aspex/internal/rules"
	"github.com/aspex-security/aspex/internal/score"
)

func TestScoreServer_NoFindings(t *testing.T) {
	sc := score.ScoreServer(nil)
	if sc.Score < 90 {
		t.Errorf("expected healthy score >= 90 for no findings, got %d", sc.Score)
	}
	if sc.Band != score.BandHealthy {
		t.Errorf("expected %s band, got %s", score.BandHealthy, sc.Band)
	}
}

func TestScoreServer_CriticalCap(t *testing.T) {
	findings := []rules.Finding{
		{Severity: rules.SeverityCritical},
	}
	sc := score.ScoreServer(findings)
	if sc.Score > 39 {
		t.Errorf("critical finding should cap score at 39, got %d", sc.Score)
	}
	if sc.Band != score.BandHighRisk {
		t.Errorf("expected HIGH RISK band, got %s", sc.Band)
	}
}

func TestScoreServer_MultipleHighFindings(t *testing.T) {
	findings := []rules.Finding{
		{Severity: rules.SeverityHigh},
		{Severity: rules.SeverityHigh},
		{Severity: rules.SeverityMedium},
	}
	sc := score.ScoreServer(findings)
	if sc.Score >= 90 {
		t.Errorf("multiple findings should reduce score below 90, got %d", sc.Score)
	}
}

func TestBands(t *testing.T) {
	cases := []struct {
		score int
		band  string
	}{
		{100, score.BandHealthy},
		{90, score.BandHealthy},
		{89, score.BandNeedsReview},
		{70, score.BandNeedsReview},
		{69, score.BandAtRisk},
		{40, score.BandAtRisk},
		{39, score.BandHighRisk},
		{0, score.BandHighRisk},
	}
	for _, tc := range cases {
		got := score.Band(tc.score)
		if got != tc.band {
			t.Errorf("Band(%d) = %q, want %q", tc.score, got, tc.band)
		}
	}
}
