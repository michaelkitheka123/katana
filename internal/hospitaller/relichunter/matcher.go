package relichunter

import (
	"strings"

	"github.com/Masterminds/semver/v3"
)

// MatchTechnology computes a confidence score (0.0 - 1.0) for whether two technology names match.
// It handles common variations (e.g., "wordpress" vs "wp") and fuzzy matching.
func MatchTechnology(targetName, vulnPkgName string) float64 {
	target := strings.ToLower(strings.TrimSpace(targetName))
	vuln := strings.ToLower(strings.TrimSpace(vulnPkgName))

	if target == vuln {
		return 1.0
	}

	// Simple abbreviation checks
	if (target == "wp" && strings.Contains(vuln, "wordpress")) ||
		(vuln == "wp" && strings.Contains(target, "wordpress")) {
		return 0.9
	}

	// Containment check (e.g. "apache tomcat" vs "tomcat")
	if strings.Contains(target, vuln) || strings.Contains(vuln, target) {
		return 0.8
	}

	// Compute Levenshtein distance for fuzzy matching
	dist := levenshtein(target, vuln)
	maxLen := len(target)
	if len(vuln) > maxLen {
		maxLen = len(vuln)
	}

	if maxLen == 0 {
		return 0.0
	}

	similarity := 1.0 - (float64(dist) / float64(maxLen))
	
	// Penalize short strings to avoid false positives (e.g. "go" vs "io")
	if maxLen < 4 && similarity < 1.0 {
		similarity -= 0.3
	}

	if similarity < 0 {
		return 0.0
	}

	return similarity
}

// MatchVersion evaluates if a specific target version satisfies a given semantic version constraint.
func MatchVersion(targetVersion, vulnRange string) bool {
	targetVersion = strings.TrimSpace(targetVersion)
	vulnRange = strings.TrimSpace(vulnRange)

	if targetVersion == "" {
		return false
	}
	if vulnRange == "" || vulnRange == "*" {
		return true // No constraint means all versions are vulnerable
	}

	// Try strict semver constraint evaluation
	c, err := semver.NewConstraint(vulnRange)
	if err == nil {
		v, err := semver.NewVersion(targetVersion)
		if err == nil {
			return c.Check(v)
		}
	}

	// Fallback to basic string checking if semver parsing fails
	// Example fallback: basic exact match or containment for complex un-parseable strings
	if targetVersion == vulnRange {
		return true
	}
	if strings.Contains(vulnRange, targetVersion) && !strings.Contains(vulnRange, "<") && !strings.Contains(vulnRange, ">") {
		return true
	}

	return false
}

func levenshtein(a, b string) int {
	aRunes := []rune(a)
	bRunes := []rune(b)

	if len(aRunes) == 0 {
		return len(bRunes)
	}
	if len(bRunes) == 0 {
		return len(aRunes)
	}

	matrix := make([][]int, len(aRunes)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(bRunes)+1)
		matrix[i][0] = i
	}
	for j := 0; j <= len(bRunes); j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len(aRunes); i++ {
		for j := 1; j <= len(bRunes); j++ {
			cost := 1
			if aRunes[i-1] == bRunes[j-1] {
				cost = 0
			}
			min := matrix[i-1][j] + 1       // Deletion
			if matrix[i][j-1]+1 < min {
				min = matrix[i][j-1] + 1 // Insertion
			}
			if matrix[i-1][j-1]+cost < min {
				min = matrix[i-1][j-1] + cost // Substitution
			}
			matrix[i][j] = min
		}
	}
	return matrix[len(aRunes)][len(bRunes)]
}
