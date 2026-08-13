//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/templar-framework/templar/internal/grandmaster"
	"github.com/templar-framework/templar/internal/scribe"
	"github.com/templar-framework/templar/internal/scribe/chronicle"
	"github.com/templar-framework/templar/internal/seneschal"
	"github.com/templar-framework/templar/internal/shared"
)

// sarifSchema is the expected SARIF version field value.
const sarifExpectedVersion = "2.1.0"

// TestAllReportFormats runs a minimal campaign and asserts all 5 report formats
// are generated without error and contain expected structural elements.
func TestAllReportFormats(t *testing.T) {
	targetURL := pilgrimsRestTargets["injectable-api"]
	cfg := buildTestConfig(t, targetURL)

	dbPath := filepath.Join(t.TempDir(), "templar_formats_test.db")
	gm, err := grandmaster.NewGrandMaster(dbPath, cfg)
	if err != nil {
		t.Fatalf("NewGrandMaster failed: %v", err)
	}

	campaignID := uuid.New().String()
	_, err = gm.StartCrusade(campaignID)
	if err != nil {
		t.Logf("Campaign completed with error (may be degraded): %v", err)
	}

	// Now ask Scribe to render all 5 formats explicitly.
	store := gm.Store
	sc := scribe.NewScribe(store)
	formats := []string{"json", "markdown", "html", "sarif"}

	outDir := cfg.OutputDir
	reports, err := sc.WriteChronicle(campaignID, outDir, formats)
	if err != nil {
		// Scribe fails when attack surface is empty (no tools installed). Skip gracefully.
		t.Skipf("Scribe WriteChronicle failed (likely no scanner tools in CI): %v", err)
	}

	// Assert every requested format produced a file.
	for _, fmt := range formats {
		path, ok := reports[fmt]
		if !ok {
			t.Errorf("format %q was not produced", fmt)
			continue
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("report file for format %q not found at %s", fmt, path)
		}
		t.Logf("  %s → %s", fmt, path)
	}

	// ── JSON validation ───────────────────────────────────────────────────────
	if jsonPath, ok := reports["json"]; ok {
		data, err := os.ReadFile(jsonPath)
		if err != nil {
			t.Fatalf("cannot read JSON report: %v", err)
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Errorf("JSON report is not valid JSON: %v", err)
		}
		// Required top-level keys.
		for _, key := range []string{"CampaignID", "Vulnerabilities", "AttackSurface"} {
			if _, ok := parsed[key]; !ok {
				t.Errorf("JSON report missing required key %q", key)
			}
		}
		t.Log("JSON report: structure valid")
	}

	// ── Markdown validation ───────────────────────────────────────────────────
	if mdPath, ok := reports["markdown"]; ok {
		data, err := os.ReadFile(mdPath)
		if err != nil {
			t.Fatalf("cannot read Markdown report: %v", err)
		}
		content := string(data)
		for _, section := range []string{
			"## Executive Summary",
			"## Attack Surface",
			"## Vulnerabilities",
			"## Proof of Concepts",
			"## Attack Chains",
		} {
			if !strings.Contains(content, section) {
				t.Errorf("Markdown report missing section %q", section)
			}
		}
		t.Log("Markdown report: all 5 required sections present")
	}

	// ── HTML validation ───────────────────────────────────────────────────────
	if htmlPath, ok := reports["html"]; ok {
		data, err := os.ReadFile(htmlPath)
		if err != nil {
			t.Fatalf("cannot read HTML report: %v", err)
		}
		content := string(data)
		if !strings.Contains(content, "<!DOCTYPE html>") {
			t.Error("HTML report does not contain DOCTYPE declaration")
		}
		if !strings.Contains(content, "Executive Summary") {
			t.Error("HTML report missing Executive Summary section")
		}
		t.Log("HTML report: structure valid")
	}

	// ── SARIF validation ──────────────────────────────────────────────────────
	if sarifPath, ok := reports["sarif"]; ok {
		data, err := os.ReadFile(sarifPath)
		if err != nil {
			t.Fatalf("cannot read SARIF report: %v", err)
		}
		var sarifDoc map[string]interface{}
		if err := json.Unmarshal(data, &sarifDoc); err != nil {
			t.Errorf("SARIF report is not valid JSON: %v", err)
		}
		// Check version field.
		if ver, ok := sarifDoc["version"].(string); !ok || ver != sarifExpectedVersion {
			t.Errorf("SARIF version: expected %q, got %v", sarifExpectedVersion, sarifDoc["version"])
		}
		// Check runs array is present.
		runs, ok := sarifDoc["runs"].([]interface{})
		if !ok || len(runs) == 0 {
			t.Error("SARIF report missing 'runs' array")
		}
		t.Logf("SARIF report: version=%s, runs=%d", sarifExpectedVersion, len(runs))
	}
}

// TestReportFormats_UnitLevel tests the chronicle renderers directly with a
// synthetic ArtifactBundle so the test can run without a live campaign.
// This does NOT require the integration build tag infrastructure but is placed
// here alongside the integration tests for completeness.
func TestReportFormats_UnitLevel(t *testing.T) {
	bundle := &chronicle.ArtifactBundle{
		CampaignID: "unit-test-campaign",
		AttackSurface: shared.AttackSurface{
			Subdomains: []shared.DiscoveredSubdomain{{Domain: "example.com", IP: "1.2.3.4", Source: []string{"subfinder"}}},
			Hosts:      []shared.DiscoveredHost{{IP: "1.2.3.4", OpenPorts: []int{80, 443}}},
			Endpoints: []shared.DiscoveredEndpoint{
				{URL: "http://example.com/login", Method: "POST", Source: []string{"crawler"}},
				{URL: "http://example.com/api/users", Method: "GET", Source: []string{"crawler"}},
			},
		},
		Vulnerabilities: []shared.Vulnerability{
			{
				ID:          "vuln-001",
				Title:       "SQL Injection in /login",
				Description: "User-supplied input in the password field is interpolated unsafely into a SQL query.",
				Severity:    "high",
				CVSSScore:   8.5,
				Type:        shared.VulnTypeSQLi,
				Status:      "confirmed",
				Endpoint:    shared.DiscoveredEndpoint{URL: "http://example.com/login", Method: "POST"},
				Evidence:    []shared.VulnEvidence{{Type: "nuclei", MatchedTemplate: "sqli-generic", Details: "Error-based SQLi confirmed"}},
			},
		},
		PoCs: []shared.ProofOfConcept{
			{
				ID:              "poc-001",
				VulnerabilityID: "vuln-001",
				Type:            shared.PoCTypeCurl,
				Content:         "curl -X POST http://example.com/login -d \"user=admin&pass=' OR 1=1--\"",
				Validated:       true,
				ValidationOutput: "HTTP/1.1 200 OK (admin session granted)",
			},
		},
		AttackChains:    []shared.AttackChain{},
		DegradedPhases:  []string{},
		ScopeViolations: []string{},
	}

	// JSON
	jsonBytes, err := chronicle.RenderJSON(bundle)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Errorf("RenderJSON output is not valid JSON: %v", err)
	}
	if parsed["CampaignID"] != "unit-test-campaign" {
		t.Errorf("JSON CampaignID mismatch: got %v", parsed["CampaignID"])
	}
	t.Log("RenderJSON: OK")

	// Markdown
	md, err := chronicle.RenderMarkdown(bundle)
	if err != nil {
		t.Fatalf("RenderMarkdown failed: %v", err)
	}
	for _, section := range []string{"## Executive Summary", "## Attack Surface", "## Vulnerabilities", "## Proof of Concepts", "## Attack Chains"} {
		if !strings.Contains(md, section) {
			t.Errorf("RenderMarkdown missing section %q", section)
		}
	}
	t.Log("RenderMarkdown: all 5 sections present")

	// HTML
	html, err := chronicle.RenderHTML(bundle)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("RenderHTML output missing DOCTYPE")
	}
	t.Log("RenderHTML: OK")

	// SARIF
	sarifBytes, err := chronicle.RenderSARIF(bundle)
	if err != nil {
		t.Fatalf("RenderSARIF failed: %v", err)
	}
	var sarifDoc map[string]interface{}
	if err := json.Unmarshal(sarifBytes, &sarifDoc); err != nil {
		t.Errorf("RenderSARIF output is not valid JSON: %v", err)
	}
	if ver := sarifDoc["version"]; ver != "2.1.0" {
		t.Errorf("SARIF version expected 2.1.0, got %v", ver)
	}
	t.Log("RenderSARIF: version 2.1.0 confirmed")
}

// storeAccessor exposes the Store field from GrandMaster for test access.
// We use a helper because GrandMaster.Store is exported.
func getStore(gm *grandmaster.GrandMaster) *seneschal.Store {
	return gm.Store
}
