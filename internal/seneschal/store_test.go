package seneschal

import (
	"strings"
	"testing"

	"github.com/templar-framework/templar/internal/shared"
	"pgregory.net/rapid"
)

// Property 11: Seneschal Artifact Round-Trip
func TestStore_RoundTrip(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		store, _ := NewStore(":memory:")
		defer store.db.Close()
		
		campaignID := rapid.StringMatching(`[a-zA-Z0-9-]{5,}`).Draw(rt, "campaignID")
		
		// Simplify the data generation due to deep nesting
		vulnTitle := rapid.String().Draw(rt, "title")
		vulns := []shared.Vulnerability{
			{ID: "V1", Title: vulnTitle, CVSSScore: 9.8},
		}

		err := store.StoreVulnerabilities(campaignID, vulns)
		if err != nil {
			rt.Fatalf("Failed to store: %v", err)
		}

		export, err := store.ExportCampaign(campaignID)
		if err != nil {
			rt.Fatalf("Failed to export: %v", err)
		}

		if len(export.Result.Vulnerabilities) != 1 {
			rt.Fatalf("Expected 1 vulnerability, got %d", len(export.Result.Vulnerabilities))
		}
		if export.Result.Vulnerabilities[0].Title != vulnTitle {
			rt.Fatalf("Round-trip failed. Expected %s, got %s", vulnTitle, export.Result.Vulnerabilities[0].Title)
		}
	})
}

// Property 9: API Key Isolation
func TestAPIKeyIsolation_Property(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		store, _ := NewStore(":memory:")
		defer store.db.Close()

		campaignID := "CAMP-API-KEY-TEST"
		
		apiKey := "sk-1234567890abcdefghij1234567890" // 32 chars OpenAI key
		bearerKey := "Bearer abcdefghijklmnopqrstuvwx" // 24 chars
		googleKey := "AIzaSy_1234567890abcdefghij12345678" // 33 chars

		vulns := []shared.Vulnerability{
			{
				ID: "V2", 
				Title: "Test Key Ingestion",
				Evidence: []shared.VulnEvidence{
					{Details: "Found key: " + apiKey},
					{Details: "Found auth: " + bearerKey},
					{Details: "Found GCP: " + googleKey},
				},
			},
		}
		
		// Attempt to store keys
		store.StoreVulnerabilities(campaignID, vulns)

		export, _ := store.ExportCampaign(campaignID)
		
		if len(export.Result.Vulnerabilities) > 0 {
			evidence := export.Result.Vulnerabilities[0].Evidence[0].Details
			
			if strings.Contains(evidence, apiKey) {
				rt.Fatalf("API key leaked in output: %s", evidence)
			}
			
			evidence2 := export.Result.Vulnerabilities[0].Evidence[1].Details
			if strings.Contains(evidence2, "abcdefghijklmnopqrstuvwx") {
				rt.Fatalf("Bearer key leaked in output: %s", evidence2)
			}
		}
	})
}
