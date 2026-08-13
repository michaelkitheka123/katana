package inquisitor

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/tools"
)

// RunZAP executes OWASP ZAP headless against the endpoints
func RunZAP(endpoints []shared.DiscoveredEndpoint) ([]shared.Vulnerability, error) {
	if len(endpoints) == 0 {
		return nil, nil
	}

	var targets []string
	for _, ep := range endpoints {
		targets = append(targets, ep.URL)
	}
	targetList := strings.Join(targets, ",")

	// Use Python script since zap-cli has dependency issues
	// Increased timeout for comprehensive scanning
	out, _, exit, _ := tools.Execute("python", []string{"zap_scan.py", "quick-scan", "--self-contained", "--json", targetList}, 600)
	
	var vulns []shared.Vulnerability
	
	if exit == 0 && out != "" {
		// Mock parsing for JSON output from zap-cli
		var zapOut []struct {
			Alert       string `json:"alert"`
			Description string `json:"description"`
			Risk        string `json:"risk"`
			URL         string `json:"url"`
		}
		
		if err := json.Unmarshal([]byte(out), &zapOut); err == nil {
			for i, alert := range zapOut {
				vulns = append(vulns, shared.Vulnerability{
					ID:          "ZAP-ALERT-" + string(rune(i)),
					Title:       alert.Alert,
					Description: alert.Description,
					Severity:    strings.ToLower(alert.Risk),
					Endpoint: shared.DiscoveredEndpoint{
						URL: alert.URL,
					},
					Type:   shared.VulnTypeMisc,
					Status: "confirmed",
					Evidence: []shared.VulnEvidence{
						{
							Type:            "zap_alert",
							MatchedTemplate: alert.Alert,
							Details:         "ZAP identified risk: " + alert.Risk,
						},
					},
				})
			}
		}
	} else if exit != 0 {
		shared.LogAudit(shared.AuditEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "TOOL_FAILURE",
			Message:   "ZAP execution failed or timed out",
		})
	}
	
	return vulns, nil
}
