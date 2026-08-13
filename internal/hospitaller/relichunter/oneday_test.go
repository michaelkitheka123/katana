package relichunter

import (
	"testing"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

func TestEvaluateFreshness(t *testing.T) {
	now := time.Now()
	
	cases := []struct {
		name       string
		vuln       shared.Vulnerability
		threshold  int
		expectTag  bool
	}{
		{
			name: "Recent vulnerability",
			vuln: shared.Vulnerability{
				DisclosureDate: now.Add(-10 * 24 * time.Hour), // 10 days ago
			},
			threshold: 30,
			expectTag: true,
		},
		{
			name: "Old vulnerability",
			vuln: shared.Vulnerability{
				DisclosureDate: now.Add(-40 * 24 * time.Hour), // 40 days ago
			},
			threshold: 30,
			expectTag: false,
		},
		{
			name: "No disclosure date",
			vuln: shared.Vulnerability{},
			threshold: 30,
			expectTag: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isOneDay := EvaluateFreshness(&tc.vuln, tc.threshold)
			if isOneDay != tc.expectTag {
				t.Errorf("Expected one-day status %v, got %v", tc.expectTag, isOneDay)
			}
			
			hasTag := false
			for _, tag := range tc.vuln.Tags {
				if tag == "one_day" {
					hasTag = true
					break
				}
			}
			
			if hasTag != tc.expectTag {
				t.Errorf("Expected tag presence %v, got %v", tc.expectTag, hasTag)
			}
		})
	}
}

func TestBoostSeverity(t *testing.T) {
	vuln := shared.Vulnerability{
		CVSSScore: 7.5, // High
		Severity:  "high",
		Tags:      []string{"one_day"},
	}
	
	BoostSeverity(&vuln, 2.0)
	
	if vuln.CVSSScore != 9.5 {
		t.Errorf("Expected boosted score 9.5, got %f", vuln.CVSSScore)
	}
	if vuln.Severity != "critical" {
		t.Errorf("Expected severity to be bumped to critical, got %s", vuln.Severity)
	}

	// Test hard cap at 10.0
	BoostSeverity(&vuln, 2.0)
	if vuln.CVSSScore != 10.0 {
		t.Errorf("Expected score to be capped at 10.0, got %f", vuln.CVSSScore)
	}
	
	// Test no boost for non-one-day
	normalVuln := shared.Vulnerability{
		CVSSScore: 5.0,
		Severity:  "medium",
	}
	BoostSeverity(&normalVuln, 2.0)
	if normalVuln.CVSSScore != 5.0 {
		t.Errorf("Expected normal vuln score to remain 5.0, got %f", normalVuln.CVSSScore)
	}
}
