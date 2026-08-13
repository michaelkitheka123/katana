package relichunter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

type HackerOneAdapter struct {
	config  shared.CVESourceConfig
	metrics SourceMetrics
	client  *http.Client
	mu      sync.RWMutex
}

func NewHackerOneAdapter(cfg shared.CVESourceConfig) *HackerOneAdapter {
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 30
	}
	return &HackerOneAdapter{
		config: cfg,
		client: &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second},
	}
}

func (a *HackerOneAdapter) Name() string {
	return string(a.config.Name)
}

func (a *HackerOneAdapter) Type() SourceType {
	return SourceTypeBugBounty
}

func (a *HackerOneAdapter) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config.Enabled
}

func (a *HackerOneAdapter) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config.Enabled = enabled
}

func (a *HackerOneAdapter) GetMetrics() SourceMetrics {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.metrics
}

func (a *HackerOneAdapter) HealthCheck(ctx context.Context) error {
	if a.config.HackerOneAPIKey == "" || a.config.HackerOneProgramHandle == "" {
		return fmt.Errorf("missing credentials")
	}
	return nil
}

func (a *HackerOneAdapter) Query(ctx context.Context, tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
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
			shared.LogAudit(shared.AuditEvent{Timestamp: time.Now().UTC().Format(time.RFC3339), EventType: "SOURCE_DISABLED", Message: "HackerOne disabled due to consecutive failures"})
		}
		return nil, err
	}

	a.metrics.SuccessCount++
	a.metrics.LastSuccessTime = time.Now()
	a.metrics.ConsecutiveFailures = 0
	
	vulns = a.deduplicate(vulns)

	return vulns, nil
}

func (a *HackerOneAdapter) doQuery(ctx context.Context, tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	if tech.Version == nil {
		return nil, nil
	}

	var resp *http.Response
	var err error
	
	url := fmt.Sprintf("https://api.hackerone.com/v1/hackers/programs/%s/reports?filter[keyword]=%s", 
		a.config.HackerOneProgramHandle, tech.Name)

	backoff := 50 * time.Millisecond // Use small backoff for testing/simulation
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.SetBasicAuth(a.config.HackerOneProgramHandle, a.config.HackerOneAPIKey)
		
		resp, err = a.client.Do(req)
		if err == nil {
			if resp.StatusCode == 200 {
				break
			}
			if resp.StatusCode == 429 || resp.StatusCode >= 500 {
				resp.Body.Close()
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		time.Sleep(backoff)
		backoff *= 2
	}
	
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed after retries")
	}
	defer resp.Body.Close()

	var h1Resp struct {
		Data []struct {
			Id         string `json:"id"`
			Attributes struct {
				Title       string `json:"title"`
				Severity    struct {
					Rating string `json:"rating"`
					Score  float64 `json:"score"`
				} `json:"severity"`
				CreatedAt   string `json:"created_at"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&h1Resp); err != nil {
		return nil, err
	}

	var vulns []shared.Vulnerability
	for _, report := range h1Resp.Data {
		vuln := shared.Vulnerability{
			ID:          "H1-" + report.Id,
			Title:       report.Attributes.Title,
			Severity:    normalizeSeverity(report.Attributes.Severity.Rating),
			CVSSScore:   report.Attributes.Severity.Score,
			Type:        shared.VulnTypeMisc,
			Status:      "confirmed",
			Evidence: []shared.VulnEvidence{
				{
					Type: "bug_bounty_report",
					Details: "HackerOne Report " + report.Id,
				},
			},
		}

		if t, err := time.Parse(time.RFC3339, report.Attributes.CreatedAt); err == nil {
			vuln.DisclosureDate = t
		}

		if EvaluateFreshness(&vuln, a.config.FreshnessThresholdDays) {
			BoostSeverity(&vuln, 1.5) // Example boost factor
		}

		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func normalizeSeverity(rating string) string {
	switch rating {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func (a *HackerOneAdapter) deduplicate(vulns []shared.Vulnerability) []shared.Vulnerability {
	seen := make(map[string]bool)
	var deduped []shared.Vulnerability
	for _, v := range vulns {
		if !seen[v.ID] {
			seen[v.ID] = true
			deduped = append(deduped, v)
		}
	}
	return deduped
}
