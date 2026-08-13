package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_CVESources(t *testing.T) {
	tmpDir := t.TempDir()

	validConfig := `
target_url: "https://example.com"
allowed_domains: ["example.com"]
output_dir: "./output"
scan_depth: "standard"
ai_providers:
  - name: "test"
    api_key: "dummy"
cveSources:
  - name: "hackerone"
    enabled: true
    hackeroneApiKey: "h1_key"
    hackeroneProgramHandle: "h1_handle"
  - name: "custom_feed"
    enabled: true
    feedUrl: "https://example.com/feed.xml"
    feedFormat: "rss"
`
	validPath := filepath.Join(tmpDir, "valid.yaml")
	if err := os.WriteFile(validPath, []byte(validConfig), 0644); err != nil {
		t.Fatalf("Failed to write valid config: %v", err)
	}

	cfg, err := loadConfig(validPath)
	if err != nil {
		t.Errorf("Expected valid config to load, got error: %v", err)
	}
	if len(cfg.CVESources) != 2 {
		t.Errorf("Expected 2 CVE sources, got %d", len(cfg.CVESources))
	}

	invalidConfig := `
target_url: "https://example.com"
allowed_domains: ["example.com"]
output_dir: "./output"
scan_depth: "standard"
ai_providers:
  - name: "test"
    api_key: "dummy"
cveSources:
  - name: "hackerone"
    enabled: true
    # Missing required fields
`
	invalidPath := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("Failed to write invalid config: %v", err)
	}

	_, err = loadConfig(invalidPath)
	if err == nil {
		t.Errorf("Expected invalid config to fail loading, but it succeeded")
	}
}
