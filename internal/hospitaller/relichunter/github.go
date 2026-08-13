package relichunter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

type GitHubAdapter struct {
	config  shared.CVESourceConfig
	metrics SourceMetrics
	client  *http.Client
	mu      sync.RWMutex
}

func NewGitHubAdapter(cfg shared.CVESourceConfig) *GitHubAdapter {
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 30
	}
	return &GitHubAdapter{
		config: cfg,
		client: &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second},
	}
}

func (a *GitHubAdapter) Name() string {
	return string(a.config.Name)
}

func (a *GitHubAdapter) Type() SourceType {
	return SourceTypeSecurityAdvisory
}

func (a *GitHubAdapter) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config.Enabled
}

func (a *GitHubAdapter) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config.Enabled = enabled
}

func (a *GitHubAdapter) GetMetrics() SourceMetrics {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.metrics
}

func (a *GitHubAdapter) HealthCheck(ctx context.Context) error {
	// GitHub token is optional for basic REST but required for GraphQL
	if a.config.GitHubToken == "" {
		// Just a warning in logs typically, but we require it for GraphQL
		return fmt.Errorf("GitHub adapter requires a GitHubToken for GraphQL queries")
	}
	return nil
}

func (a *GitHubAdapter) Query(ctx context.Context, tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
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
			shared.LogAudit(shared.AuditEvent{Timestamp: time.Now().UTC().Format(time.RFC3339), EventType: "SOURCE_DISABLED", Message: "GitHub disabled due to consecutive failures"})
		}
		return nil, err
	}

	a.metrics.SuccessCount++
	a.metrics.LastSuccessTime = time.Now()
	a.metrics.ConsecutiveFailures = 0

	return vulns, nil
}

const githubGraphQLEndpoint = "https://api.github.com/graphql"

const advisoryQuery = `
query($searchQuery: String!) {
  securityAdvisories(first: 20, query: $searchQuery) {
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      cvss {
        score
      }
      identifiers {
        type
        value
      }
      vulnerabilities(first: 5) {
        nodes {
          package {
            name
          }
          vulnerableVersionRange
        }
      }
    }
  }
}
`

type ghAdvisoryResponse struct {
	Data struct {
		SecurityAdvisories struct {
			Nodes []struct {
				GhsaId      string `json:"ghsaId"`
				Summary     string `json:"summary"`
				Description string `json:"description"`
				Severity    string `json:"severity"`
				PublishedAt string `json:"publishedAt"`
				Cvss        struct {
					Score float64 `json:"score"`
				} `json:"cvss"`
				Identifiers []struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"identifiers"`
				Vulnerabilities struct {
					Nodes []struct {
						Package struct {
							Name string `json:"name"`
						} `json:"package"`
						VulnerableVersionRange string `json:"vulnerableVersionRange"`
					} `json:"nodes"`
				} `json:"vulnerabilities"`
			} `json:"nodes"`
		} `json:"securityAdvisories"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (a *GitHubAdapter) doQuery(ctx context.Context, tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	if tech.Version == nil {
		return nil, nil
	}
	
	if a.config.GitHubToken == "" {
		return nil, fmt.Errorf("github token missing")
	}

	queryVars := map[string]interface{}{
		"searchQuery": tech.Name,
	}
	
	reqBody, _ := json.Marshal(map[string]interface{}{
		"query":     advisoryQuery,
		"variables": queryVars,
	})

	var resp *http.Response
	var err error

	backoff := 50 * time.Millisecond
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequestWithContext(ctx, "POST", githubGraphQLEndpoint, bytes.NewReader(reqBody))
		req.Header.Set("Authorization", "Bearer "+a.config.GitHubToken)
		req.Header.Set("Content-Type", "application/json")

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

	var ghResp ghAdvisoryResponse
	if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil {
		return nil, err
	}
	
	if len(ghResp.Errors) > 0 {
		return nil, fmt.Errorf("graphql error: %s", ghResp.Errors[0].Message)
	}

	var vulns []shared.Vulnerability
	for _, node := range ghResp.Data.SecurityAdvisories.Nodes {
		var cveID string
		for _, id := range node.Identifiers {
			if id.Type == "CVE" {
				cveID = id.Value
				break
			}
		}

		vulnID := node.GhsaId
		if cveID != "" {
			vulnID = cveID
		}

		matchesVersion := false
		for _, v := range node.Vulnerabilities.Nodes {
			if MatchTechnology(tech.Name, v.Package.Name) >= 0.8 {
				if *tech.Version == "" || MatchVersion(*tech.Version, v.VulnerableVersionRange) {
					matchesVersion = true
					break
				}
			}
		}
		
		if !matchesVersion && len(node.Vulnerabilities.Nodes) > 0 {
			continue
		}

		vuln := shared.Vulnerability{
			ID:          vulnID,
			Title:       node.Summary,
			Severity:    normalizeGHSASeverity(node.Severity),
			CVSSScore:   node.Cvss.Score,
			Type:        shared.VulnTypeMisc,
			Status:      "confirmed",
			Evidence: []shared.VulnEvidence{
				{
					Type:    "security_advisory",
					Details: "GHSA: " + node.GhsaId,
				},
			},
		}

		if t, err := time.Parse(time.RFC3339, node.PublishedAt); err == nil {
			vuln.DisclosureDate = t
		}

		if EvaluateFreshness(&vuln, a.config.FreshnessThresholdDays) {
			BoostSeverity(&vuln, 1.5) // Example boost factor
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

func normalizeGHSASeverity(severity string) string {
	s := strings.ToLower(severity)
	switch s {
	case "critical", "high", "low":
		return s
	case "moderate":
		return "medium"
	default:
		return "info"
	}
}
