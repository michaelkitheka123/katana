package relichunter

import (
	"context"
	"sync"
	"time"

	"github.com/templar-framework/templar/internal/shared"
	"golang.org/x/sync/errgroup"
)

// SourceCoordinator manages concurrent querying of multiple CVE sources,
// applies timeouts, and aggregates metrics.
type SourceCoordinator struct {
	Adapters []SourceAdapter
	cache    map[string]cacheEntry
	mu       sync.RWMutex
	cacheTTL time.Duration
}

type cacheEntry struct {
	vulns     []shared.Vulnerability
	expiresAt time.Time
}

// NewSourceCoordinator initializes a new coordinator with given adapters.
func NewSourceCoordinator(adapters []SourceAdapter, cacheTTL time.Duration) *SourceCoordinator {
	if cacheTTL == 0 {
		cacheTTL = 15 * time.Minute
	}
	return &SourceCoordinator{
		Adapters: adapters,
		cache:    make(map[string]cacheEntry),
		cacheTTL: cacheTTL,
	}
}

// QueryAll executes queries across all enabled adapters concurrently.
func (c *SourceCoordinator) QueryAll(ctx context.Context, tech shared.TechStackEntry) ([]shared.Vulnerability, error) {
	cacheKey := tech.Name
	if tech.Version != nil {
		cacheKey += "@" + *tech.Version
	}

	// Check cache
	c.mu.RLock()
	if entry, found := c.cache[cacheKey]; found && time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.vulns, nil
	}
	c.mu.RUnlock()

	var allVulns [][]shared.Vulnerability
	var vulnsMu sync.Mutex
	
	g, gCtx := errgroup.WithContext(ctx)
	
	for _, a := range c.Adapters {
		if !a.IsEnabled() {
			continue
		}
		
		adapter := a // capture loop variable
		
		g.Go(func() error {
			// Adapter applies its own timeouts via its HTTP client, but we could also wrap it here
			vulns, err := adapter.Query(gCtx, tech)
			if err != nil {
				// We don't fail the whole group on a single source failure
				// Graceful degradation: log error and continue
				shared.LogAudit(shared.AuditEvent{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					EventType: "SOURCE_QUERY_FAILURE",
					Message:   "Adapter " + adapter.Name() + " failed: " + err.Error(),
				})
				return nil
			}

			vulnsMu.Lock()
			if len(vulns) > 0 {
				allVulns = append(allVulns, vulns)
			}
			vulnsMu.Unlock()
			return nil
		})
	}

	// Wait for all queries to finish
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Cross-reference and merge
	mergedVulns := MergeVulnerabilities(allVulns)

	// Update cache
	c.mu.Lock()
	c.cache[cacheKey] = cacheEntry{
		vulns:     mergedVulns,
		expiresAt: time.Now().Add(c.cacheTTL),
	}
	c.mu.Unlock()

	return mergedVulns, nil
}
