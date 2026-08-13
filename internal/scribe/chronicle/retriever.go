package chronicle

import (
	"fmt"

	"github.com/templar-framework/templar/internal/seneschal"
	"github.com/templar-framework/templar/internal/shared"
)

// ArtifactBundle holds all campaign data required for report rendering.
// It is populated by RetrieveAllArtifacts before any rendering begins.
type ArtifactBundle struct {
	CampaignID      string
	AttackSurface   shared.AttackSurface
	Vulnerabilities []shared.Vulnerability
	PoCs            []shared.ProofOfConcept
	AttackChains    []shared.AttackChain
	DegradedPhases  []string // phases that completed with status 'degraded'
	ScopeViolations []string // URLs blocked by the Scope Enforcer during the campaign
}

// RetrieveAllArtifacts fetches all campaign artifacts from the Seneschal store and
// returns a fully populated ArtifactBundle ready for rendering.
//
// Required artifact types are AttackSurface and Vulnerabilities. If either fails to
// retrieve, the function returns a REPORT_GENERATION_FAILED:<artifact_type> error and
// report rendering must not proceed.
//
// Optional artifact types are PoCs and AttackChains. An empty slice for either is
// treated as valid — it simply means those phases produced no output (or were skipped).
//
// DegradedPhases and ScopeViolations are populated from campaign state metadata where
// available; if the store does not surface that data they default to empty slices.
func RetrieveAllArtifacts(store *seneschal.Store, campaignID string) (*ArtifactBundle, error) {
	export, err := store.ExportCampaign(campaignID)
	if err != nil {
		return nil, fmt.Errorf("REPORT_GENERATION_FAILED:campaign_export: %w", err)
	}

	result := export.Result

	// AttackSurface is required — fail hard if it looks uninitialized.
	// An empty AttackSurface (zero subdomains, hosts, and endpoints) after a successful
	// export indicates a retrieval problem, not a legitimately empty surface.
	if len(result.AttackSurface.Subdomains) == 0 &&
		len(result.AttackSurface.Hosts) == 0 &&
		len(result.AttackSurface.Endpoints) == 0 {
		return nil, fmt.Errorf("REPORT_GENERATION_FAILED:attack_surface")
	}

	// Vulnerabilities are required — an empty list after recon+analysis indicates a
	// retrieval failure, not a legitimately clean target (which would still return []).
	// We accept nil/empty only when combined with a degraded hospitaller phase; since we
	// cannot distinguish that here without phase state, we require a non-nil slice.
	// A nil slice means the JSON deserialisation failed entirely (store error).
	if result.Vulnerabilities == nil {
		return nil, fmt.Errorf("REPORT_GENERATION_FAILED:vulnerabilities")
	}

	bundle := &ArtifactBundle{
		CampaignID:      campaignID,
		AttackSurface:   result.AttackSurface,
		Vulnerabilities: result.Vulnerabilities,
		// PoCs and AttackChains are optional — nil from store becomes empty slice.
		PoCs:            nilToEmpty(result.PoCs),
		AttackChains:    nilToEmpty(result.AttackChains),
		// DegradedPhases and ScopeViolations are populated by the Scribe layer using
		// Seneschal's state manager, which is not accessible via Store.ExportCampaign.
		// They default to empty slices here; callers may enrich the bundle afterward.
		DegradedPhases:  []string{},
		ScopeViolations: []string{},
	}

	return bundle, nil
}

// nilToEmpty converts a nil ProofOfConcept slice to an allocated empty slice so that
// callers can range over it safely and JSON rendering emits [] instead of null.
func nilToEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
