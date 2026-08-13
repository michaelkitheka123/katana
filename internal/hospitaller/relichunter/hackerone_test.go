package relichunter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

func TestHackerOneAdapter_Query(t *testing.T) {
	mockResponse := `{
		"data": [
			{
				"id": "12345",
				"attributes": {
					"title": "SQL Injection in Login",
					"severity": {
						"rating": "critical",
						"score": 9.8
					},
					"created_at": "2023-01-01T00:00:00Z"
				}
			},
			{
				"id": "12345",
				"attributes": {
					"title": "SQL Injection in Login Duplicate",
					"severity": {
						"rating": "critical",
						"score": 9.8
					},
					"created_at": "2023-01-01T00:00:00Z"
				}
			},
			{
				"id": "67890",
				"attributes": {
					"title": "XSS in Profile",
					"severity": {
						"rating": "medium",
						"score": 5.4
					},
					"created_at": "2023-01-02T00:00:00Z"
				}
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "h1_handle" || pass != "h1_key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockResponse))
	}))
	defer server.Close()

	cfg := shared.CVESourceConfig{
		Name:                   "hackerone",
		Enabled:                true,
		HackerOneAPIKey:        "h1_key",
		HackerOneProgramHandle: "h1_handle",
		TimeoutSeconds:         5,
	}

	adapter := NewHackerOneAdapter(cfg)
	adapter.client = server.Client() 
	
	adapter.client.Transport = &rewriteTransport{
		Target: server.URL,
		Base:   adapter.client.Transport,
	}
	if adapter.client.Transport.(*rewriteTransport).Base == nil {
		adapter.client.Transport.(*rewriteTransport).Base = http.DefaultTransport
	}

	ver := "1.0"
	tech := shared.TechStackEntry{Name: "test-app", Version: &ver}
	
	vulns, err := adapter.Query(context.Background(), tech)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(vulns) != 2 {
		t.Fatalf("Expected 2 deduplicated vulnerabilities, got %d", len(vulns))
	}

	if vulns[0].ID != "H1-12345" || vulns[0].Severity != "critical" {
		t.Errorf("Unexpected first vulnerability: %+v", vulns[0])
	}
	if vulns[1].ID != "H1-67890" || vulns[1].Severity != "medium" {
		t.Errorf("Unexpected second vulnerability: %+v", vulns[1])
	}
}

func TestHackerOneAdapter_RateLimitBackoff(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	cfg := shared.CVESourceConfig{
		Name:                   "hackerone",
		Enabled:                true,
		HackerOneAPIKey:        "h1_key",
		HackerOneProgramHandle: "h1_handle",
		TimeoutSeconds:         5,
	}

	adapter := NewHackerOneAdapter(cfg)
	adapter.client = server.Client()
	adapter.client.Transport = &rewriteTransport{
		Target: server.URL,
		Base:   http.DefaultTransport,
	}

	ver := "1.0"
	tech := shared.TechStackEntry{Name: "test-app", Version: &ver}
	
	start := time.Now()
	_, err := adapter.Query(context.Background(), tech)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Expected successful retry, got error: %v", err)
	}
	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
	// Initial backoff is 50ms, then 100ms. Total expected wait ~150ms.
	if duration < 100*time.Millisecond {
		t.Errorf("Backoff was too short: %v", duration)
	}
}

type rewriteTransport struct {
	Target string
	Base   http.RoundTripper
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newReq, _ := http.NewRequestWithContext(req.Context(), req.Method, t.Target, req.Body)
	newReq.Header = req.Header
	return t.Base.RoundTrip(newReq)
}
