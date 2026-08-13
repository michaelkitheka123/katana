package relichunter

import (
	"context"
	"time"

	"github.com/templar-framework/templar/internal/shared"
)

// SourceType represents the category of vulnerability source
type SourceType string

const (
	SourceTypeTraditionalCVE   SourceType = "traditional_cve"
	SourceTypeBugBounty        SourceType = "bug_bounty"
	SourceTypeSecurityAdvisory SourceType = "security_advisory"
	SourceTypeVulnerabilityFeed SourceType = "vulnerability_feed"
)

// CVESource represents a configured CVE source with its parameters
type CVESource struct {
	Name         string                 // Unique identifier for the source (nvd, osv, hackerone, github, exploitdb, custom_feed)
	Type         SourceType             // Source type category
	Enabled      bool                   // Whether this source is enabled
	Config       map[string]interface{} // Source-specific configuration
	Timeout      time.Duration          // Query timeout for this source
	Priority     int                    // Priority for query ordering (higher = earlier)
}

// SourceAdapter defines the interface that all CVE source adapters must implement
type SourceAdapter interface {
	// Name returns the unique identifier for this source adapter
	Name() string
	
	// Type returns the source type category
	Type() SourceType
	
	// Query searches for vulnerabilities affecting the given tech stack entry
	Query(ctx context.Context, tech shared.TechStackEntry) ([]shared.Vulnerability, error)
	
	// HealthCheck verifies the source is accessible and properly configured
	HealthCheck(ctx context.Context) error
	
	// GetMetrics returns performance metrics for this source
	GetMetrics() SourceMetrics
	
	// IsEnabled returns whether this source is currently enabled
	IsEnabled() bool
	
	// SetEnabled enables or disables this source
	SetEnabled(enabled bool)
}

// SourceMetrics tracks performance metrics for a CVE source
type SourceMetrics struct {
	QueryCount       int64         // Total number of queries executed
	SuccessCount     int64         // Number of successful queries
	FailureCount     int64         // Number of failed queries
	AverageQueryTime time.Duration // Average query execution time
	LastQueryTime    time.Time     // Timestamp of last query
	LastSuccessTime  time.Time     // Timestamp of last successful query
	LastFailureTime  time.Time     // Timestamp of last failed query
	ConsecutiveFailures int        // Number of consecutive failures
}

// QueryOptions provides optional parameters for source queries
type QueryOptions struct {
	FreshnessThreshold time.Duration // Maximum age for "one-day" vulnerabilities
	BatchSize          int           // Maximum number of vulnerabilities to return
	IncludeExploits    bool          // Whether to include exploit information
	IncludeRemediation bool          // Whether to include remediation guidance
}

// SourceFactory creates source adapters based on configuration
type SourceFactory interface {
	// CreateAdapter creates a source adapter from configuration
	CreateAdapter(source CVESource) (SourceAdapter, error)
	
	// SupportedSources returns a list of source names supported by this factory
	SupportedSources() []string
}