package shared

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AuditEvent represents an event to be logged
type AuditEvent struct {
	Timestamp string
	EventType string
	URL       string
	RuleType  string
	Pattern   string
	Message   string
}

// importantEvents are always logged regardless of dedup.
var importantEvents = map[string]bool{
	"TOOL_FAILURE":          true,
	"SCOPE_VIOLATION":       true,
	"RECON_PARTIAL":         true,
	"DATA_INTEGRITY_WARNING": true,
	"CHAIN_VALIDATION_FAILURE": true,
	"CHAIN_ANALYSIS_SKIPPED": true,
	"LLM_FAILURE":           true,
}

// dedupCache suppresses repeated identical messages within a campaign run.
var (
	dedupMu    sync.Mutex
	dedupCache = make(map[string]bool)
)

// LogAudit logs important audit events, suppressing repetitive TOOL_EXECUTION spam.
func LogAudit(event AuditEvent) {
	// Always suppress noisy TOOL_EXECUTION lines (they appear hundreds of times).
	if event.EventType == "TOOL_EXECUTION" {
		return
	}

	// For important events, deduplicate by (eventType + message) so the same
	// failure isn't printed 50 times for 50 subdomains.
	if importantEvents[event.EventType] {
		key := event.EventType + "|" + event.Message
		dedupMu.Lock()
		already := dedupCache[key]
		if !already {
			dedupCache[key] = true
		}
		dedupMu.Unlock()
		if already {
			return
		}
	}

	fmt.Printf("[%s] %s | %s\n", event.Timestamp, event.EventType, event.Message)
}

// isInScope checks if a given URL is within the defined scope
func isInScope(rawURL string, scope ScopeConfig) bool {
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Host == "" {
		LogAudit(AuditEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "URL_MALFORMED",
			URL:       rawURL,
			Message:   "Failed to parse URL",
		})
		return false
	}

	host := strings.ToLower(parsedURL.Hostname())
	path := parsedURL.Path

	// Check exclusions first
	for _, excludedPath := range scope.ExcludedPaths {
		if strings.HasPrefix(path, excludedPath) {
			LogAudit(AuditEvent{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				EventType: "SCOPE_VIOLATION",
				URL:       rawURL,
				RuleType:  "exclusion",
				Pattern:   excludedPath,
				Message:   "Blocked by excluded path",
			})
			return false
		}
	}

	// Check allowed domains
	for _, allowedDomain := range scope.AllowedDomains {
		allowedDomain = strings.ToLower(allowedDomain)
		if strings.HasPrefix(allowedDomain, "*.") {
			baseDomain := strings.TrimPrefix(allowedDomain, "*.")
			if strings.HasSuffix(host, "."+baseDomain) {
				return true
			}
		} else {
			if host == allowedDomain {
				return true
			}
		}
	}

	LogAudit(AuditEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: "SCOPE_VIOLATION",
		URL:       rawURL,
		RuleType:  "domain_mismatch",
		Pattern:   "Not in allowed domains",
		Message:   "Domain not allowed in scope",
	})
	return false
}

// ScopeEnforcingTransport is an HTTP transport middleware that enforces scope rules
type ScopeEnforcingTransport struct {
	Transport http.RoundTripper
	Scope     ScopeConfig
}

// RoundTrip executes a single HTTP transaction, enforcing scope before dialing
func (t *ScopeEnforcingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !isInScope(req.URL.String(), t.Scope) {
		return nil, fmt.Errorf("SCOPE_VIOLATION: url %s is out of scope", req.URL.String())
	}

	if t.Transport == nil {
		t.Transport = http.DefaultTransport
	}

	return t.Transport.RoundTrip(req)
}
