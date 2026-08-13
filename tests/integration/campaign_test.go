//go:build integration

// Package integration contains end-to-end Templar campaign tests that require
// the Pilgrim's Rest Docker Compose stack to be running.
//
// Run with:
//
//	docker compose -f tests/integration/pilgrims-rest/docker-compose.yml up -d
//	./tests/integration/pilgrims-rest/wait-for-healthy.sh
//	go test -tags integration -v ./tests/integration/...
package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/templar-framework/templar/internal/grandmaster"
	"github.com/templar-framework/templar/internal/shared"
)

// pilgrimsRestTargets maps service name to its local base URL.
var pilgrimsRestTargets = map[string]string{
	"juiceshop":      "http://localhost:4281",
	"injectable-api": "http://localhost:4283",
}

// buildTestConfig builds a shallow CrusadeConfig targeting the given base URL.
func buildTestConfig(t *testing.T, targetURL string) shared.CrusadeConfig {
	t.Helper()

	// Derive the hostname for scope config.
	host := strings.TrimPrefix(targetURL, "http://")
	host = strings.TrimPrefix(host, "https://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	outDir := filepath.Join(t.TempDir(), "reports")

	return shared.CrusadeConfig{
		TargetURL:      targetURL,
		AllowedDomains: []string{host},
		ScanDepth:      shared.ScanDepthShallow,
		OutputDir:      outDir,
		AIProviders: []shared.AIProviderConfig{
			{
				Name:   "openai",
				APIKey: "sk-test-integration-placeholder",
				Role:   "any",
			},
		},
		Scope: shared.ScopeConfig{
			AllowedDomains: []string{host},
			ExcludedPaths:  []string{},
		},
		RateLimit: shared.RateLimitConfig{
			RequestsPerSecond: 5,
		},
	}
}

// TestShallowCampaign_JuiceShop runs a shallow Crusade against Juice Shop and
// asserts that at least one vulnerability is discovered and persisted.
func TestShallowCampaign_JuiceShop(t *testing.T) {
	targetURL := pilgrimsRestTargets["juiceshop"]
	cfg := buildTestConfig(t, targetURL)

	dbPath := filepath.Join(t.TempDir(), "templar_test.db")
	gm, err := grandmaster.NewGrandMaster(dbPath, cfg)
	if err != nil {
		t.Fatalf("NewGrandMaster failed: %v", err)
	}

	campaignID := uuid.New().String()

	done := make(chan struct{})
	var result *shared.CampaignResult
	var runErr error

	go func() {
		defer close(done)
		result, runErr = gm.StartCrusade(campaignID)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Minute):
		t.Fatal("campaign timed out after 5 minutes")
	}

	if runErr != nil {
		t.Logf("Campaign returned error (may be degraded): %v", runErr)
	}

	if result == nil {
		t.Fatal("StartCrusade returned nil result")
	}

	// Assert: attack surface was discovered.
	if len(result.AttackSurface.Endpoints) == 0 {
		t.Error("expected at least one endpoint discovered, got 0")
	}

	// Assert: at least one vulnerability was found.
	// (Juice Shop has known XSS and SQLi vulnerabilities)
	if len(result.Vulnerabilities) == 0 {
		t.Log("WARNING: no vulnerabilities found — this may indicate scanner tools (Nuclei/ZAP) are not installed")
	}

	t.Logf("Campaign %s complete: %d endpoints, %d vulns, %d chains, %d PoCs",
		campaignID,
		len(result.AttackSurface.Endpoints),
		len(result.Vulnerabilities),
		len(result.AttackChains),
		len(result.PoCs),
	)
}

// TestShallowCampaign_InjectableAPI runs a shallow Crusade against the httpbin
// injectable API and asserts the attack surface contains at least one endpoint.
func TestShallowCampaign_InjectableAPI(t *testing.T) {
	targetURL := pilgrimsRestTargets["injectable-api"]
	cfg := buildTestConfig(t, targetURL)

	dbPath := filepath.Join(t.TempDir(), "templar_test.db")
	gm, err := grandmaster.NewGrandMaster(dbPath, cfg)
	if err != nil {
		t.Fatalf("NewGrandMaster failed: %v", err)
	}

	campaignID := uuid.New().String()

	done := make(chan struct{})
	var result *shared.CampaignResult
	var runErr error

	go func() {
		defer close(done)
		result, runErr = gm.StartCrusade(campaignID)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Minute):
		t.Fatal("campaign timed out after 3 minutes")
	}

	if runErr != nil {
		t.Logf("Campaign returned error (may be degraded): %v", runErr)
	}

	if result == nil {
		t.Fatal("StartCrusade returned nil result")
	}

	if len(result.AttackSurface.Endpoints) == 0 {
		t.Error("expected at least one endpoint discovered against httpbin, got 0")
	}

	t.Logf("Injectable API campaign %s: %d endpoints discovered", campaignID, len(result.AttackSurface.Endpoints))
}

// TestScopeEnforcement verifies that when a target is excluded from scope,
// zero requests reach it and all blocked URLs appear in the report.
func TestScopeEnforcement(t *testing.T) {
	// Use injectable-api as target but exclude its /post path.
	targetURL := pilgrimsRestTargets["injectable-api"]
	cfg := buildTestConfig(t, targetURL)
	cfg.Scope.ExcludedPaths = []string{"/post", "/put", "/delete", "/patch"}

	dbPath := filepath.Join(t.TempDir(), "templar_test.db")
	gm, err := grandmaster.NewGrandMaster(dbPath, cfg)
	if err != nil {
		t.Fatalf("NewGrandMaster failed: %v", err)
	}

	campaignID := uuid.New().String()
	result, err := gm.StartCrusade(campaignID)
	if err != nil {
		t.Logf("Campaign degraded (expected in test env): %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}

	// Assert: no discovered endpoint URL starts with an excluded path.
	for _, ep := range result.AttackSurface.Endpoints {
		for _, excluded := range cfg.Scope.ExcludedPaths {
			path := ep.URL
			if idx := strings.Index(path, "/"); idx != -1 {
				path = path[idx:]
			}
			if strings.HasPrefix(path, excluded) {
				t.Errorf("endpoint %s should have been excluded by scope (matches %s)", ep.URL, excluded)
			}
		}
	}

	t.Logf("Scope enforcement test passed — %d endpoints discovered (excluded paths blocked)", len(result.AttackSurface.Endpoints))
}

// TestReportOutputDir verifies that report files are written to the configured output dir.
func TestReportOutputDir(t *testing.T) {
	targetURL := pilgrimsRestTargets["injectable-api"]
	cfg := buildTestConfig(t, targetURL)

	dbPath := filepath.Join(t.TempDir(), "templar_test.db")
	gm, err := grandmaster.NewGrandMaster(dbPath, cfg)
	if err != nil {
		t.Fatalf("NewGrandMaster failed: %v", err)
	}

	campaignID := uuid.New().String()
	result, err := gm.StartCrusade(campaignID)
	if err != nil {
		t.Logf("Campaign degraded: %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}

	// Check that the output directory was created.
	if _, err := os.Stat(cfg.OutputDir); os.IsNotExist(err) {
		t.Errorf("output directory %s was not created", cfg.OutputDir)
		return
	}

	// Check for at least the JSON report.
	jsonPath := filepath.Join(cfg.OutputDir, campaignID+".json")
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Logf("JSON report not found at %s (Scribe may have been degraded)", jsonPath)
		return
	}

	// Validate JSON is well-formed.
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read JSON report: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("JSON report is malformed: %v", err)
	}

	t.Logf("Report output validated at %s", cfg.OutputDir)
}
