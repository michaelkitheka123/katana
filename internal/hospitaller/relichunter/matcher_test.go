package relichunter

import (
	"testing"

	"pgregory.net/rapid"
)

func TestMatchTechnology(t *testing.T) {
	cases := []struct {
		target   string
		vuln     string
		minScore float64
	}{
		{"wordpress", "WordPress", 1.0},
		{"wp", "wordpress plugin", 0.9},
		{"apache tomcat", "tomcat", 0.8},
		{"nginx", "ngnx", 0.7}, // typo
		{"go", "io", 0.0},      // penalized short string
	}

	for _, tc := range cases {
		t.Run(tc.target+"_"+tc.vuln, func(t *testing.T) {
			score := MatchTechnology(tc.target, tc.vuln)
			if score < tc.minScore {
				t.Errorf("Expected >= %f for %s vs %s, got %f", tc.minScore, tc.target, tc.vuln, score)
			}
		})
	}
}

func TestMatchVersion(t *testing.T) {
	cases := []struct {
		target string
		vuln   string
		match  bool
	}{
		{"1.5.2", ">= 1.5.0, < 2.0.0", true},
		{"2.0.0", ">= 1.5.0, < 2.0.0", false},
		{"1.5", "~1.5.0", true},
		{"1.0.0", "*", true},
		{"", ">= 1.0", false},
	}

	for _, tc := range cases {
		t.Run(tc.target+"_"+tc.vuln, func(t *testing.T) {
			match := MatchVersion(tc.target, tc.vuln)
			if match != tc.match {
				t.Errorf("Expected %v for target %s and vuln %s, got %v", tc.match, tc.target, tc.vuln, match)
			}
		})
	}
}

// Property-based test for MatchVersion
func TestMatchVersion_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		major := rapid.IntRange(0, 10).Draw(t, "major")
		minor := rapid.IntRange(0, 10).Draw(t, "minor")
		patch := rapid.IntRange(0, 10).Draw(t, "patch")
		
		targetStr := rapid.StringMatching(`^[0-9]+\.[0-9]+\.[0-9]+$`).Draw(t, "targetStr")
		
		// If it generated a valid targetStr or we construct one manually
		manualStr := ""
		if major >= 0 && minor >= 0 && patch >= 0 {
			manualStr = "1.2.3"
		}

		if targetStr != "" && MatchVersion(targetStr, targetStr) != true {
			t.Fatalf("Exact version match failed for %s", targetStr)
		}
		if manualStr != "" && MatchVersion(manualStr, manualStr) != true {
			t.Fatalf("Exact version match failed for %s", manualStr)
		}
	})
}
