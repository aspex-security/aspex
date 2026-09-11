package corpus_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aspex-security/aspex/internal/corpus"
)

// The scenario corpus is a detection contract: every scenario must pass, and
// a failure names the exact expectation that broke.
func TestScenarioCorpus(t *testing.T) {
	sum, err := corpus.RunAll(context.Background(), filepath.Join("..", "..", "testdata", "corpus", "scenarios"))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Scenarios < 5 {
		t.Fatalf("expected the shipped scenarios to load, got %d", sum.Scenarios)
	}
	for _, r := range sum.Results {
		if !r.Pass {
			t.Errorf("%s (%s): false negatives %v; false positives %v", r.Scenario, r.Category, r.FalseNegatives, r.FalsePositives)
		}
	}
	if sum.FalsePositives != 0 || sum.FalseNegatives != 0 {
		t.Errorf("corpus: %d TP, %d FN, %d FP", sum.TruePositives, sum.FalseNegatives, sum.FalsePositives)
	}
}

func TestScenarioLoaderRejectsBadYAML(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "bad.yaml"), "name: [unterminated"); err != nil {
		t.Fatal(err)
	}
	if _, err := corpus.Load(dir); err == nil || !strings.Contains(err.Error(), "bad.yaml") {
		t.Errorf("malformed scenario should fail loudly with its path, got %v", err)
	}
}
