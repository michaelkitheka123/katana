package hospitaller

import (
	"testing"

	"github.com/templar-framework/templar/internal/shared"
	"pgregory.net/rapid"
)

// Property 3: Vulnerability Endpoint Referential Integrity
func TestVulnEndpointReferentialIntegrity_Property(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// 1. Generate AttackSurface
		numEndpoints := rapid.IntRange(1, 10).Draw(rt, "numEndpoints")
		var endpoints []shared.DiscoveredEndpoint
		
		for i := 0; i < numEndpoints; i++ {
			url := rapid.StringMatching(`https://example\.com/[a-z]{3,8}`).Draw(rt, "url")
			endpoints = append(endpoints, shared.DiscoveredEndpoint{URL: url})
		}
		
		surface := shared.AttackSurface{
			Endpoints: endpoints,
		}

		// 2. Setup mock Hospitaller
		hospitaller := NewHospitaller(nil, nil)
		
		// 3. Run Hospitaller (We mock the network calls in Oracle and others by letting them fail fast)
		vulns, _ := hospitaller.Run("TEST-CAMP", surface)
		
		// 4. Verify Referential Integrity
		for _, v := range vulns {
			found := false
			for _, e := range surface.Endpoints {
				if v.Endpoint.URL == e.URL {
					found = true
					break
				}
			}
			// Note: if the tool genuinely found a new endpoint, this property is strictly saying it MUST be in the attack surface.
			// The current Oracle implementation explicitly filters out hallucinated URLs to enforce this.
			// RelicHunter and Inquisitor also build off the surface endpoints.
			if !found {
				// We expect some vulns might not have endpoints (e.g. RelicHunter CVEs are host-based, not endpoint based).
				// We need to refine the check: IF a vulnerability has an Endpoint.URL set, it must exist in the surface.
				if v.Endpoint.URL != "" {
					rt.Fatalf("Referential Integrity Violated: Vuln %s references unknown endpoint %s", v.ID, v.Endpoint.URL)
				}
			}
		}
	})
}
