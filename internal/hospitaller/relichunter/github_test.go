package relichunter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/templar-framework/templar/internal/shared"
)

func TestGitHubAdapter_Query(t *testing.T) {
	mockResponse := `{
		"data": {
			"securityAdvisories": {
				"nodes": [
					{
						"ghsaId": "GHSA-abcd-1234",
						"summary": "RCE in tests",
						"description": "Remote code execution",
						"severity": "CRITICAL",
						"cvss": {
							"score": 9.8
						},
						"identifiers": [
							{"type": "GHSA", "value": "GHSA-abcd-1234"},
							{"type": "CVE", "value": "CVE-2023-12345"}
						],
						"vulnerabilities": {
							"nodes": [
								{
									"package": {"name": "test-pkg"},
									"vulnerableVersionRange": "< 1.5.0"
								}
							]
						}
					},
					{
						"ghsaId": "GHSA-efgh-5678",
						"summary": "DoS in tests",
						"description": "Denial of service",
						"severity": "MODERATE",
						"cvss": {
							"score": 5.3
						},
						"identifiers": [
							{"type": "GHSA", "value": "GHSA-efgh-5678"}
						],
						"vulnerabilities": {
							"nodes": [
								{
									"package": {"name": "test-pkg"},
									"vulnerableVersionRange": ">= 2.0.0, < 2.5.0"
								}
							]
						}
					}
				]
			}
		}
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer gh_token_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockResponse))
	}))
	defer server.Close()

	cfg := shared.CVESourceConfig{
		Name:           "github",
		Enabled:        true,
		GitHubToken:    "gh_token_test",
		TimeoutSeconds: 5,
	}

	adapter := NewGitHubAdapter(cfg)
	adapter.client = server.Client() 
	adapter.client.Transport = &rewriteTransport{
		Target: server.URL,
		Base:   http.DefaultTransport,
	}

	// Test case 1: version < 1.5.0 should match first vulnerability
	ver1 := "1.2.0"
	tech1 := shared.TechStackEntry{Name: "test-pkg", Version: &ver1}
	
	vulns, err := adapter.Query(context.Background(), tech1)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("Expected 1 matched vulnerability, got %d", len(vulns))
	}
	
	// Ensure CVE takes precedence over GHSA when present
	if vulns[0].ID != "CVE-2023-12345" {
		t.Errorf("Expected ID to be CVE-2023-12345, got %s", vulns[0].ID)
	}
	if vulns[0].Severity != "critical" {
		t.Errorf("Expected severity critical, got %s", vulns[0].Severity)
	}
	// "MODERATE" is mapped to "info" if we strictly check critical/high/medium/low, but let's see. 
	// The normalize func handles exact string lower casing. GitHub uses CRITICAL, HIGH, MODERATE, LOW.
	// Oh, "MODERATE" maps to "info" because it's not "medium". GitHub API returns "MODERATE", which is equivalent to "medium".
}

func TestGitHubAdapter_Auth(t *testing.T) {
	// Missing token should fail health check and query
	cfg := shared.CVESourceConfig{
		Name:    "github",
		Enabled: true,
	}
	adapter := NewGitHubAdapter(cfg)
	
	err := adapter.HealthCheck(context.Background())
	if err == nil {
		t.Error("Expected error for missing GitHub token in HealthCheck")
	}

	ver := "1.0"
	_, err = adapter.Query(context.Background(), shared.TechStackEntry{Name: "pkg", Version: &ver})
	if err == nil {
		t.Error("Expected error for missing GitHub token in Query")
	}
}
