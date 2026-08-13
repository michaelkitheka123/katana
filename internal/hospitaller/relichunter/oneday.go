package relichunter

import (
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

// EvaluateFreshness checks if a vulnerability was disclosed within the freshness threshold.
// A vulnerability is considered a "one-day" if its disclosure date is within thresholdDays from now.
func EvaluateFreshness(vuln *shared.Vulnerability, thresholdDays int) bool {
	if vuln.DisclosureDate.IsZero() {
		return false
	}
	
	if thresholdDays <= 0 {
		thresholdDays = 30 // Default threshold
	}

	cutoff := time.Now().AddDate(0, 0, -thresholdDays)
	isOneDay := vuln.DisclosureDate.After(cutoff) || vuln.DisclosureDate.Equal(cutoff)

	if isOneDay {
		vuln.Tags = append(vuln.Tags, "one_day")
	}

	return isOneDay
}

// BoostSeverity increases the CVSS score of a vulnerability if it is a "one-day".
// The score is capped at 10.0.
func BoostSeverity(vuln *shared.Vulnerability, boost float64) {
	isOneDay := false
	for _, tag := range vuln.Tags {
		if tag == "one_day" {
			isOneDay = true
			break
		}
	}

	if !isOneDay {
		return
	}

	vuln.CVSSScore += boost
	if vuln.CVSSScore > 10.0 {
		vuln.CVSSScore = 10.0
	}
	
	// Update string severity based on new CVSS score if it was boosted to a new tier
	if vuln.CVSSScore >= 9.0 {
		vuln.Severity = "critical"
	} else if vuln.CVSSScore >= 7.0 {
		vuln.Severity = "high"
	}
}
