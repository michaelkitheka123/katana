package hereticjudge

import (
	"math"

	"github.com/templar-framework/templar/internal/shared"
)

// ScoreChain computes a combined CVSS score for the given attack chain.
// The score accounts for the individual step scores, chain length, and
// temporal severity adjustments, and is guaranteed to be in the range
// [maxIndividualCVSS, 10.0], rounded to 1 decimal place.
func ScoreChain(chain shared.AttackChain) float64 {
	if len(chain.Steps) == 0 {
		return 0.0
	}

	// Step 1: find the max individual CVSS across all steps.
	maxIndividualCVSS := 0.0
	for _, step := range chain.Steps {
		if step.Vulnerability.CVSSScore > maxIndividualCVSS {
			maxIndividualCVSS = step.Vulnerability.CVSSScore
		}
	}

	// Step 2: apply chain length multiplier.
	// Each additional step beyond the first adds 0.3 to the score.
	additionalSteps := float64(len(chain.Steps) - 1)
	score := maxIndividualCVSS + additionalSteps*0.3
	if score > 10.0 {
		score = 10.0
	}

	// Step 3: apply temporal severity adjustment.
	hasCritical := false
	allLowOrInfo := true
	for _, step := range chain.Steps {
		sev := step.Vulnerability.Severity
		switch sev {
		case "critical":
			hasCritical = true
			allLowOrInfo = false
		case "high", "medium":
			allLowOrInfo = false
		}
	}

	if hasCritical {
		score *= 1.05
		if score > 10.0 {
			score = 10.0
		}
	} else if allLowOrInfo {
		score *= 0.95
	}

	// Apply one_day boost
	for _, step := range chain.Steps {
		hasOneDay := false
		for _, t := range step.Vulnerability.Tags {
			if t == "one_day" {
				hasOneDay = true
				break
			}
		}
		if hasOneDay {
			score *= 1.1 // 10% boost for chains with a 1-day
			if score > 10.0 {
				score = 10.0
			}
			break
		}
	}

	// Step 4: enforce final bounds — must be ≥ maxIndividualCVSS and ≤ 10.0.
	if score < maxIndividualCVSS {
		score = maxIndividualCVSS
	}
	if score > 10.0 {
		score = 10.0
	}

	// Step 5: round to 1 decimal place.
	return math.Round(score*10) / 10
}

// UpdateChainScore computes the combined CVSS score for the chain and
// stores it in chain.CombinedCVSS.
func UpdateChainScore(chain *shared.AttackChain) {
	chain.CombinedCVSS = ScoreChain(*chain)
}

// DeriveImpact derives the chain impact level based on the highest severity
// step present in the chain, prioritizing exploits.
func DeriveImpact(chain shared.AttackChain) shared.ChainImpact {
	for _, step := range chain.Steps {
		if step.Vulnerability.ExploitAvailable {
			return shared.ChainImpact{
				Level:       "critical",
				Description: "Public exploit available for a vulnerability in this chain",
			}
		}
	}

	highest := highestSeverity(chain)

	switch highest {
	case "critical":
		return shared.ChainImpact{
			Level:       "critical",
			Description: "Full system compromise possible",
		}
	case "high":
		return shared.ChainImpact{
			Level:       "high",
			Description: "Significant data exposure or privilege escalation",
		}
	case "medium":
		return shared.ChainImpact{
			Level:       "medium",
			Description: "Partial data access or service disruption",
		}
	default:
		return shared.ChainImpact{
			Level:       "low",
			Description: "Minimal direct impact",
		}
	}
}

// highestSeverity returns the most severe severity string found across all
// chain steps, following the ordering: critical > high > medium > low/info.
func highestSeverity(chain shared.AttackChain) string {
	order := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}

	best := ""
	bestRank := -1

	for _, step := range chain.Steps {
		sev := step.Vulnerability.Severity
		rank, ok := order[sev]
		if !ok {
			rank = 0 // unknown severities treated as info
		}
		if rank > bestRank {
			bestRank = rank
			best = sev
		}
	}

	return best
}
