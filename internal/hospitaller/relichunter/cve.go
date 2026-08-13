package relichunter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

var globalCoordinator *SourceCoordinator

func init() {
	// Initialize default adapters for the global coordinator
	adapters := []SourceAdapter{
		NewGitHubAdapter(shared.CVESourceConfig{Name: "github", Enabled: true, TimeoutSeconds: 10}),
		NewHackerOneAdapter(shared.CVESourceConfig{Name: "hackerone", Enabled: true, TimeoutSeconds: 10}),
		NewCustomFeedAdapter(shared.CVESourceConfig{Name: "custom-feed", Enabled: true, TimeoutSeconds: 10}),
	}
	globalCoordinator = NewSourceCoordinator(adapters, 15*time.Minute)
}

// SearchCVEs queries known vulnerabilities affecting a tech stack using the SourceCoordinator
func SearchCVEs(tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	if tech.Version == nil || *tech.Version == "" {
		return nil, nil // Only search if we have a version
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vulns, err := globalCoordinator.QueryAll(ctx, tech)
	
	// Report metrics after each top-level query for MVP
	ReportMetrics(globalCoordinator)
	
	if err != nil {
		shared.LogAudit(shared.AuditEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "TOOL_FAILURE",
			Message:   "Coordinator failed: " + err.Error(),
		})
	}
	
	return vulns, nil
}

func queryNVD(tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s+%s", tech.Name, *tech.Version)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Mock parsing, realistically this would parse NVD's complex schema
	return []shared.Vulnerability{}, nil
}

func queryOSV(tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Basic OSV post query mock
	url := "https://api.osv.dev/v1/query"
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, err
	}
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var osvResp struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	
	var vulns []shared.Vulnerability
	if json.NewDecoder(resp.Body).Decode(&osvResp) == nil {
		for _, v := range osvResp.Vulns {
			vulns = append(vulns, shared.Vulnerability{
				ID: v.ID,
				Title: "OSV Vulnerability " + v.ID,
				Severity: "high",
				Type: shared.VulnTypeMisc,
				Status: "confirmed",
			})
		}
	}
	
	return vulns, nil
}
