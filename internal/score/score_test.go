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

func TestApplyAttackPathsCapsButNeverRaises(t *testing.T) {
	healthy := score.OverallScore{Score: 95, Band: score.BandHealthy}
	capped := score.ApplyAttackPaths(healthy, []string{"critical"}, []string{"Potential credential exfiltration path"})
	if capped.Score != 39 || capped.Band != score.BandHighRisk || capped.CapReason == "" {
		t.Errorf("one critical path must cap a healthy score at 39: %+v", capped)
	}
	high := score.ApplyAttackPaths(healthy, []string{"high", "medium"}, []string{"x", "y"})
	if high.Score != 69 || high.Band != score.BandAtRisk {
		t.Errorf("one high path caps at 69: %+v", high)
	}
	low := score.OverallScore{Score: 20, Band: score.BandHighRisk}
	if got := score.ApplyAttackPaths(low, []string{"high"}, []string{"x"}); got.Score != 20 || got.CapReason != "" {
		t.Errorf("caps never raise a score: %+v", got)
	}
	if got := score.ApplyAttackPaths(healthy, nil, nil); got.Score != 95 || got.CapReason != "" {
		t.Errorf("no paths, no change: %+v", got)
	}
}
