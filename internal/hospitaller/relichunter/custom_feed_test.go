package relichunter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/templar-framework/templar/internal/shared"
)

func TestCustomFeedJSON(t *testing.T) {
	mockJSON := `[
		{
			"id": "CUSTOM-001",
			"title": "WordPress plugin vulnerability",
			"description": "SQLi in wordpress plugin",
			"severity": "high",
			"cvss_score": 8.0,
			"published": "2023-10-10T12:00:00Z"
		}
	]`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(mockJSON))
	}))
	defer server.Close()

	cfg := shared.CVESourceConfig{
		Name:       "test-json",
		Enabled:    true,
		FeedURL:    server.URL,
		FeedFormat: "json",
	}

	adapter := NewCustomFeedAdapter(cfg)
	tech := shared.TechStackEntry{Name: "wordpress"}

	vulns, err := adapter.Query(context.Background(), tech)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("Expected 1 vuln, got %d", len(vulns))
	}

	if vulns[0].ID != "CUSTOM-001" {
		t.Errorf("Expected CUSTOM-001, got %s", vulns[0].ID)
	}
}

func TestCustomFeedRSS(t *testing.T) {
	mockRSS := `<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
<channel>
  <title>Sec Feed</title>
  <item>
    <title>Django RCE</title>
    <description>Remote code execution in Django framework</description>
    <link>http://example.com/vuln/1</link>
    <guid>VULN-1234</guid>
    <pubDate>Tue, 10 Oct 2023 12:00:00 GMT</pubDate>
  </item>
</channel>
</rss>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		w.Write([]byte(mockRSS))
	}))
	defer server.Close()

	cfg := shared.CVESourceConfig{
		Name:       "test-rss",
		Enabled:    true,
		FeedURL:    server.URL,
		FeedFormat: "rss",
	}

	adapter := NewCustomFeedAdapter(cfg)
	tech := shared.TechStackEntry{Name: "django"}

	vulns, err := adapter.Query(context.Background(), tech)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("Expected 1 vuln, got %d", len(vulns))
	}

	if vulns[0].ID != "VULN-1234" {
		t.Errorf("Expected VULN-1234, got %s", vulns[0].ID)
	}
}
