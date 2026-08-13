package hereticjudge

import (
	"testing"

	"github.com/templar-framework/templar/internal/shared"
)

func makeStep(severity string, cvss float64) shared.ChainStep {
	return shared.ChainStep{
		Vulnerability: shared.Vulnerability{
			Severity:  severity,
			CVSSScore: cvss,
		},
	}
}

func TestScoreChain_EmptyChain(t *testing.T) {
	chain := shared.AttackChain{}
	if got := ScoreChain(chain); got != 0.0 {
		t.Errorf("expected 0.0 for empty chain, got %v", got)
	}
}

func TestScoreChain_SingleStep(t *testing.T) {
	chain := shared.AttackChain{
		Steps: []shared.ChainStep{makeStep("medium", 5.0)},
	}
	// Single step: no chain bonus, no critical → score = 5.0
	got := ScoreChain(chain)
	if got != 5.0 {
		t.Errorf("expected 5.0, got %v", got)
	}
}

func TestScoreChain_ChainLengthBonus(t *testing.T) {
	// 3 steps, max CVSS = 6.0, all medium
	// bonus = 2 * 0.3 = 0.6 → base = 6.6, no temporal adj → 6.6
	chain := shared.AttackChain{
		Steps: []shared.ChainStep{
			makeStep("medium", 6.0),
			makeStep("medium", 4.0),
			makeStep("medium", 5.0),
		},
	}
	got := ScoreChain(chain)
	if got != 6.6 {
		t.Errorf("expected 6.6, got %v", got)
	}
}

func TestScoreChain_CriticalTemporalBonus(t *testing.T) {
	// 2 steps, max CVSS = 8.0, one critical
	// base = 8.0 + 0.3 = 8.3, * 1.05 = 8.715 → rounded = 8.7
	chain := shared.AttackChain{
		Steps: []shared.ChainStep{
			makeStep("critical", 8.0),
			makeStep("medium", 5.0),
		},
	}
	got := ScoreChain(chain)
	if got != 8.7 {
		t.Errorf("expected 8.7, got %v", got)
	}
}

func TestScoreChain_AllLowReduction(t *testing.T) {
	// 2 steps, max CVSS = 3.0, all low
	// base = 3.0 + 0.3 = 3.3, * 0.95 = 3.135 → rounded = 3.1
	chain := shared.AttackChain{
		Steps: []shared.ChainStep{
			makeStep("low", 3.0),
			makeStep("info", 1.0),
		},
	}
	got := ScoreChain(chain)
	if got != 3.1 {
		t.Errorf("expected 3.1, got %v", got)
	}
}

func TestScoreChain_CappedAt10(t *testing.T) {
	// Many steps with high CVSS — must never exceed 10.0
	steps := make([]shared.ChainStep, 20)
	for i := range steps {
		steps[i] = makeStep("critical", 9.5)
	}
	chain := shared.AttackChain{Steps: steps}
	got := ScoreChain(chain)
	if got > 10.0 {
		t.Errorf("score exceeded 10.0: got %v", got)
	}
	if got != 10.0 {
		t.Errorf("expected 10.0 (cap), got %v", got)
	}
}

func TestScoreChain_NeverBelowMaxIndividual(t *testing.T) {
	// Single critical step at 9.8 — all-low reduction must not apply (has critical)
	chain := shared.AttackChain{
		Steps: []shared.ChainStep{makeStep("critical", 9.8)},
	}
	got := ScoreChain(chain)
	if got < 9.8 {
		t.Errorf("score fell below maxIndividualCVSS: got %v", got)
	}
}

func TestUpdateChainScore(t *testing.T) {
	chain := shared.AttackChain{
		Steps: []shared.ChainStep{makeStep("high", 7.0)},
	}
	UpdateChainScore(&chain)
	if chain.CombinedCVSS != 7.0 {
		t.Errorf("expected CombinedCVSS=7.0, got %v", chain.CombinedCVSS)
	}
}

func TestDeriveImpact(t *testing.T) {
	cases := []struct {
		name     string
		steps    []shared.ChainStep
		wantLvl  string
		wantDesc string
	}{
		{
			name:     "critical highest",
			steps:    []shared.ChainStep{makeStep("critical", 9.0), makeStep("low", 1.0)},
			wantLvl:  "critical",
			wantDesc: "Full system compromise possible",
		},
		{
			name:     "high highest",
			steps:    []shared.ChainStep{makeStep("high", 7.0), makeStep("medium", 5.0)},
			wantLvl:  "high",
			wantDesc: "Significant data exposure or privilege escalation",
		},
		{
			name:     "medium highest",
			steps:    []shared.ChainStep{makeStep("medium", 5.0), makeStep("low", 2.0)},
			wantLvl:  "medium",
			wantDesc: "Partial data access or service disruption",
		},
		{
			name:     "low only",
			steps:    []shared.ChainStep{makeStep("low", 2.0)},
			wantLvl:  "low",
			wantDesc: "Minimal direct impact",
		},
		{
			name:     "info only",
			steps:    []shared.ChainStep{makeStep("info", 0.0)},
			wantLvl:  "low",
			wantDesc: "Minimal direct impact",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := shared.AttackChain{Steps: tc.steps}
			got := DeriveImpact(chain)
			if got.Level != tc.wantLvl {
				t.Errorf("Level: want %q, got %q", tc.wantLvl, got.Level)
			}
			if got.Description != tc.wantDesc {
				t.Errorf("Description: want %q, got %q", tc.wantDesc, got.Description)
			}
		})
	}
}
