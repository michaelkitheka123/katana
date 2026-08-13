// Package inquisitor runs active vulnerability scans via Nuclei and OWASP ZAP.
// It prefers MCP server connections (nuclei-mcp, pd-tools-mcp) and falls back
// to local binary execution.
package inquisitor

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/mcp"
	"github.com/templar-framework/templar/internal/shared/tools"
)

// RunNuclei scans the given endpoints with Nuclei templates.
// Uses nuclei-mcp or pd-tools-mcp when available, falls back to local nuclei.
func RunNuclei(endpoints []shared.DiscoveredEndpoint, reg *mcp.Registry) ([]shared.Vulnerability, error) {
	if len(endpoints) == 0 {
		return nil, nil
	}

	var targets []string
	for _, ep := range endpoints {
		targets = append(targets, ep.URL)
	}

	// ── MCP: nuclei-mcp (addcontent/nuclei-mcp) ──────────────────────────────
	if reg != nil {
		if client, ok := reg.Get(mcp.ServerNuclei); ok {
			vulns, err := runNucleiViaMCP(client, targets)
			if err == nil && len(vulns) > 0 {
				return vulns, nil
			}
		}

		// ── MCP: pd-tools-mcp nuclei ─────────────────────────────────────────
		if client, ok := reg.Get(mcp.ServerPDTools); ok {
			raw, err := client.CallTool("nuclei", map[string]interface{}{
				"targets": targets,
				"silent":  true,
				"json":    true,
			})
			if err == nil {
				vulns := parseNucleiMCPResult(raw, endpoints)
				if len(vulns) > 0 {
					return vulns, nil
				}
			}
		}
	}

	// ── Local: nuclei binary ─────────────────────────────────────────────────
	tmpFile, err := os.CreateTemp("", "nuclei_targets_*.txt")
	if err == nil {
		tmpFile.WriteString(strings.Join(targets, "\n"))
		tmpFile.Close()
		defer os.Remove(tmpFile.Name())
		
		// Increased timeout to 600 seconds (10 minutes) for comprehensive scanning
		// Prioritize templates: start with quick security checks, then vulnerabilities
		// Strategy: 
		// 1. First pass: Quick templates (exposures, misconfigurations)
		// 2. Second pass: Vulnerability templates (cves, vulnerabilities)
		// Using -as for automatic smart selection
		// Using -etags to exclude slow/dos templates
		out, _, exit, _ := tools.Execute("nuclei", []string{
			"-l", tmpFile.Name(), 
			"-t", "C:\\Users\\victor\\nuclei-templates\\nuclei-templates-main", 
			"-as", 
			"-severity", "low,medium,high,critical", 
			"-etags", "dos,slow",  // Exclude denial-of-service and slow templates
			"-stats", 
			"-stats-interval", "10",  // Less frequent stats updates
			"-j", 
			"-silent",
			"-rate-limit", "150",  // Rate limit requests
			"-concurrency", "25",  // Manage concurrency
		}, 600)
		if exit != 0 {
			shared.LogAudit(shared.AuditEvent{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				EventType: "TOOL_FAILURE",
				Message:   "Nuclei execution failed or timed out",
			})
		}
		return parseNucleiJSONLines(out, endpoints), nil
	}
	
	return nil, nil
}

// runNucleiViaMCP calls the nuclei-mcp server's scan tool.
func runNucleiViaMCP(client *mcp.MCPClient, targets []string) ([]shared.Vulnerability, error) {
	raw, err := client.CallTool("scan", map[string]interface{}{
		"targets":   targets,
		"templates": []string{"cves", "exposures", "vulnerabilities", "misconfigurations"},
		"json":      true,
	})
	if err != nil {
		return nil, err
	}
	return parseNucleiMCPResult(raw, nil), nil
}

// parseNucleiMCPResult parses the JSON result from an MCP nuclei tool call.
func parseNucleiMCPResult(raw []byte, endpoints []shared.DiscoveredEndpoint) []shared.Vulnerability {
	// Try array of findings first.
	var findings []nucleiResult
	if json.Unmarshal(raw, &findings) == nil && len(findings) > 0 {
		return convertNucleiResults(findings, endpoints)
	}
	// Try wrapped result: {"results": [...], "output": "..."}
	var wrapped struct {
		Results []nucleiResult `json:"results"`
		Output  string         `json:"output"`
	}
	if json.Unmarshal(raw, &wrapped) == nil {
		vulns := convertNucleiResults(wrapped.Results, endpoints)
		// Also parse JSONL from Output field.
		vulns = append(vulns, parseNucleiJSONLines(wrapped.Output, endpoints)...)
		return vulns
	}
	// Fallback: treat raw as JSONL.
	return parseNucleiJSONLines(string(raw), endpoints)
}

type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Tags        string `json:"tags"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
	Type      string `json:"type"`
}

func convertNucleiResults(findings []nucleiResult, endpoints []shared.DiscoveredEndpoint) []shared.Vulnerability {
	vulns := make([]shared.Vulnerability, 0, len(findings))
	for _, f := range findings {
		ep := findEndpoint(f.MatchedAt, endpoints)
		vulns = append(vulns, shared.Vulnerability{
			ID:          "NUCLEI-" + f.TemplateID,
			Title:       f.Info.Name,
			Description: f.Info.Description,
			Severity:    normaliseSeverity(f.Info.Severity),
			Endpoint:    ep,
			Type:        inferVulnType(f.TemplateID, f.Info.Tags),
			Status:      "confirmed",
			Evidence: []shared.VulnEvidence{{
				Type:            "nuclei",
				MatchedTemplate: f.TemplateID,
				Details:         f.MatchedAt,
			}},
		})
	}
	return vulns
}

// parseNucleiJSONLines parses newline-delimited Nuclei JSON output.
func parseNucleiJSONLines(output string, endpoints []shared.DiscoveredEndpoint) []shared.Vulnerability {
	var vulns []shared.Vulnerability
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var f nucleiResult
		if json.Unmarshal([]byte(line), &f) == nil && f.TemplateID != "" {
			ep := findEndpoint(f.MatchedAt, endpoints)
			vulns = append(vulns, shared.Vulnerability{
				ID:          "NUCLEI-" + f.TemplateID,
				Title:       f.Info.Name,
				Description: f.Info.Description,
				Severity:    normaliseSeverity(f.Info.Severity),
				Endpoint:    ep,
				Type:        inferVulnType(f.TemplateID, f.Info.Tags),
				Status:      "confirmed",
				Evidence: []shared.VulnEvidence{{
					Type:            "nuclei",
					MatchedTemplate: f.TemplateID,
					Details:         line,
				}},
			})
		}
	}
	return vulns
}

// findEndpoint looks up an endpoint by URL; returns a synthetic one if not found.
func findEndpoint(url string, endpoints []shared.DiscoveredEndpoint) shared.DiscoveredEndpoint {
	for _, ep := range endpoints {
		if ep.URL == url {
			return ep
		}
	}
	return shared.DiscoveredEndpoint{URL: url, Method: "GET", Source: []string{"nuclei"}}
}

func normaliseSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(s)
	default:
		return "info"
	}
}

func inferVulnType(templateID, tags string) shared.VulnType {
	combined := strings.ToLower(templateID + " " + tags)
	switch {
	case strings.Contains(combined, "sqli") || strings.Contains(combined, "sql-injection"):
		return shared.VulnTypeSQLi
	case strings.Contains(combined, "xss"):
		return shared.VulnTypeXSS
	case strings.Contains(combined, "ssrf"):
		return shared.VulnTypeSSRF
	case strings.Contains(combined, "rce") || strings.Contains(combined, "code-execution"):
		return shared.VulnTypeRCE
	case strings.Contains(combined, "lfi") || strings.Contains(combined, "path-traversal"):
		return shared.VulnTypeLFI
	case strings.Contains(combined, "idor"):
		return shared.VulnTypeIDOR
	default:
		return shared.VulnTypeMisc
	}
}
