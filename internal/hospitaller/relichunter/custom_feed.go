package relichunter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mmcdole/gofeed"
	"github.com/templar-framework/templar/internal/shared"
)

type CustomFeedAdapter struct {
	config  shared.CVESourceConfig
	metrics SourceMetrics
	client  *http.Client
	mu      sync.RWMutex
}

func NewCustomFeedAdapter(cfg shared.CVESourceConfig) *CustomFeedAdapter {
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 30
	}
	return &CustomFeedAdapter{
		config: cfg,
		client: &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second},
	}
}

func (a *CustomFeedAdapter) Name() string {
	return string(a.config.Name)
}

func (a *CustomFeedAdapter) Type() SourceType {
	return SourceTypeVulnerabilityFeed
}

func (a *CustomFeedAdapter) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config.Enabled
}

func (a *CustomFeedAdapter) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config.Enabled = enabled
}

func (a *CustomFeedAdapter) GetMetrics() SourceMetrics {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.metrics
}

func (a *CustomFeedAdapter) HealthCheck(ctx context.Context) error {
	if a.config.FeedURL == "" {
		return fmt.Errorf("custom feed requires a FeedURL")
	}
	return nil
}

func (a *CustomFeedAdapter) Query(ctx context.Context, tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	a.mu.Lock()
	a.metrics.QueryCount++
	a.metrics.LastQueryTime = time.Now()
	a.mu.Unlock()

	start := time.Now()
	vulns, err := a.doQuery(ctx, tech)

	a.mu.Lock()
	defer a.mu.Unlock()
	queryTime := time.Since(start)

	if a.metrics.QueryCount == 1 {
		a.metrics.AverageQueryTime = queryTime
	} else {
		a.metrics.AverageQueryTime = (a.metrics.AverageQueryTime*time.Duration(a.metrics.QueryCount-1) + queryTime) / time.Duration(a.metrics.QueryCount)
	}

	if err != nil {
		a.metrics.FailureCount++
		a.metrics.LastFailureTime = time.Now()
		a.metrics.ConsecutiveFailures++
		if a.metrics.ConsecutiveFailures >= 3 {
			a.config.Enabled = false
			shared.LogAudit(shared.AuditEvent{Timestamp: time.Now().UTC().Format(time.RFC3339), EventType: "SOURCE_DISABLED", Message: "Custom Feed disabled due to consecutive failures"})
		}
		return nil, err
	}

	a.metrics.SuccessCount++
	a.metrics.LastSuccessTime = time.Now()
	a.metrics.ConsecutiveFailures = 0

	return vulns, nil
}

func (a *CustomFeedAdapter) doQuery(ctx context.Context, tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", a.config.FeedURL, nil)
	if err != nil {
		return nil, err
	}

	// Apply Authentication
	if a.config.FeedAuth != nil {
		switch strings.ToLower(a.config.FeedAuth.Type) {
		case "basic":
			req.SetBasicAuth(a.config.FeedAuth.Username, a.config.FeedAuth.Password)
		case "bearer":
			req.Header.Set("Authorization", "Bearer "+a.config.FeedAuth.Token)
		case "api_key":
			headerName := a.config.FeedAuth.APIKeyHeader
			if headerName == "" {
				headerName = "X-API-Key"
			}
			req.Header.Set(headerName, a.config.FeedAuth.APIKey)
		}
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("feed HTTP error: %d", resp.StatusCode)
	}

	format := strings.ToLower(a.config.FeedFormat)
	if format == "json" {
		return a.parseJSONFeed(resp.Body, tech)
	}

	// Default to RSS/Atom using gofeed
	return a.parseXMLFeed(resp.Body, tech)
}

// Minimal JSON structure expectation
type jsonFeedItem struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score"`
	Published   string  `json:"published"`
}

func (a *CustomFeedAdapter) parseJSONFeed(body io.Reader, tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	var items []jsonFeedItem
	if err := json.NewDecoder(body).Decode(&items); err != nil {
		return nil, err
	}

	var vulns []shared.Vulnerability
	for _, item := range items {
		// Keyword match title or description for technology
		lowerTitle := strings.ToLower(item.Title)
		lowerDesc := strings.ToLower(item.Description)
		lowerTech := strings.ToLower(tech.Name)

		if !strings.Contains(lowerTitle, lowerTech) && !strings.Contains(lowerDesc, lowerTech) {
			continue
		}

		vuln := shared.Vulnerability{
			ID:          item.ID,
			Title:       item.Title,
			Description: item.Description,
			Severity:    normalizeSeverity(item.Severity),
			CVSSScore:   item.CVSSScore,
			Type:        shared.VulnTypeMisc,
			Status:      "confirmed",
			Evidence: []shared.VulnEvidence{
				{Type: "custom_feed", Details: "Found in JSON feed"},
			},
		}

		if t, err := time.Parse(time.RFC3339, item.Published); err == nil {
			vuln.DisclosureDate = t
		}

		if EvaluateFreshness(&vuln, a.config.FreshnessThresholdDays) {
			BoostSeverity(&vuln, 1.0) // Modest boost for custom feed one-days
		}

		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func (a *CustomFeedAdapter) parseXMLFeed(body io.Reader, tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	fp := gofeed.NewParser()
	feed, err := fp.Parse(body)
	if err != nil {
		return nil, err
	}

	var vulns []shared.Vulnerability
	for _, item := range feed.Items {
		lowerTitle := strings.ToLower(item.Title)
		lowerDesc := strings.ToLower(item.Description)
		lowerTech := strings.ToLower(tech.Name)

		if !strings.Contains(lowerTitle, lowerTech) && !strings.Contains(lowerDesc, lowerTech) {
			continue
		}

		vulnID := item.GUID
		if vulnID == "" {
			// fallback to link or title hash
			vulnID = "FEED-ITEM-" + item.Title
		}

		vuln := shared.Vulnerability{
			ID:          vulnID,
			Title:       item.Title,
			Description: item.Description,
			Severity:    "medium", // Default for unstructured feeds
			CVSSScore:   5.0,
			Type:        shared.VulnTypeMisc,
			Status:      "confirmed",
			Evidence: []shared.VulnEvidence{
				{Type: "custom_feed", Details: "Found in RSS/Atom feed: " + item.Link},
			},
		}

		if item.PublishedParsed != nil {
			vuln.DisclosureDate = *item.PublishedParsed
		}

		if EvaluateFreshness(&vuln, a.config.FreshnessThresholdDays) {
			BoostSeverity(&vuln, 1.0)
		}

		vulns = append(vulns, vuln)
	}
	return vulns, nil
}
