package preceptor

import (
	"testing"

	"github.com/templar-framework/templar/internal/shared"
	"pgregory.net/rapid"
)

// Property 8: Deduplication Idempotency
func TestDeduplicateIdempotency_Property(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate random endpoints
		numEndpoints := rapid.IntRange(1, 20).Draw(rt, "numEndpoints")
		var endpoints []shared.DiscoveredEndpoint
		
		for i := 0; i < numEndpoints; i++ {
			url := rapid.StringMatching(`https://[a-z]{3,10}\.com/[a-z]{0,5}`).Draw(rt, "url")
			method := rapid.SampledFrom([]string{"GET", "POST", "PUT", "DELETE"}).Draw(rt, "method")
			source := rapid.StringMatching(`[a-z]{3,8}`).Draw(rt, "source")
			
			endpoints = append(endpoints, shared.DiscoveredEndpoint{
				URL:    url,
				Method: method,
				Source: []string{source},
				Parameters: []shared.DiscoveredParameter{
					{Name: "id", Source: []string{source}},
				},
			})
		}
		
		// First pass
		pass1 := DeduplicateEndpoints(endpoints)
		
		// Second pass (idempotency check)
		pass2 := DeduplicateEndpoints(pass1)
		
		if len(pass1) != len(pass2) {
			rt.Fatalf("Deduplication is not idempotent: pass1 len %d, pass2 len %d", len(pass1), len(pass2))
		}
	})
}
