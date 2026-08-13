package relichunter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

func TestMergeVulnerabilities(t *testing.T) {
	d1 := time.Now().Add(-2 * 24 * time.Hour)
	d2 := time.Now().Add(-1 * 24 * time.Hour)
	
	sources := [][]shared.Vulnerability{
		{
			{
				ID:             "CVE-2023-0001",
				Title:          "First title",
				CVSSScore:      7.5,
				Severity:       "high",
				DisclosureDate: d2, // newer
				Tags:           []string{"t1"},
				Evidence: []shared.VulnEvidence{
					{Type: "nvd", Details: "nvd data"},
				},
			},
		},
		{
			{
				ID:             "CVE-2023-0001",
				Title:          "Second title", // should not overwrite if first is not empty, but currently my logic says existing title won't be overwritten. Wait, existing.Title == "" check will keep "First title"
				CVSSScore:      9.8, // higher
				Severity:       "critical",
				DisclosureDate: d1, // older
				Tags:           []string{"t2", "one_day"},
				Evidence: []shared.VulnEvidence{
					{Type: "github", Details: "github data"},
				},
			},
		},
	}

	merged := MergeVulnerabilities(sources)
	
	if len(merged) != 1 {
		t.Fatalf("Expected 1 merged vuln, got %d", len(merged))
	}
	
	v := merged[0]
	if v.CVSSScore != 9.8 {
		t.Errorf("Expected score 9.8, got %f", v.CVSSScore)
	}
	if v.Severity != "critical" {
		t.Errorf("Expected severity critical, got %s", v.Severity)
	}
	if v.DisclosureDate != d1 {
		t.Errorf("Expected older disclosure date d1")
	}
	if len(v.Evidence) != 2 {
		t.Errorf("Expected 2 evidence items, got %d", len(v.Evidence))
	}
	if len(v.Tags) != 3 {
		t.Errorf("Expected 3 tags (t1, t2, one_day), got %v", v.Tags)
	}
}

func TestCheckExploitAvailability(t *testing.T) {
	mockResponse := `{
		"total_count": 1,
		"items": [
			{"html_url": "https://github.com/user/cve-poc"}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test_token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockResponse))
	}))
	defer server.Close()

	vuln := shared.Vulnerability{ID: "CVE-2023-12345"}
	
	client := server.Client()
	client.Transport = &rewriteTransport{Target: server.URL, Base: http.DefaultTransport}

	err := CheckExploitAvailability(context.Background(), &vuln, "test_token", client)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !vuln.ExploitAvailable {
		t.Errorf("Expected ExploitAvailable to be true")
	}
	
	foundEvidence := false
	for _, ev := range vuln.Evidence {
		if ev.Type == "public_exploit" {
			foundEvidence = true
			break
		}
	}
	if !foundEvidence {
		t.Errorf("Expected public_exploit evidence")
	}
}

func TestExtractRemediation(t *testing.T) {
	vuln := shared.Vulnerability{
		Description: "A bad bug. Please update to 1.5.",
	}
	ExtractRemediation(&vuln)
	
	if vuln.Remediation == "" {
		t.Errorf("Expected remediation to be extracted")
	}
}
