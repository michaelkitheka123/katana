// Package marshal implements the Marshal coordinator — the exploit forge orchestrator.
// It filters eligible vulnerabilities, drives PoC generation via Holy Lance,
// optionally validates PoCs through the Siege Engine, and persists results
// to the Seneschal store.
package marshal

import (
	"fmt"
	"strings"
	"time"

	"github.com/templar-framework/templar/internal/marshal/holylance"
	"github.com/templar-framework/templar/internal/marshal/siegeengine"
	"github.com/templar-framework/templar/internal/seneschal"
	"github.com/templar-framework/templar/internal/shared"
)

// eligibleSeverities are the only severity levels for which PoCs are generated.
var eligibleSeverities = map[string]bool{
	"medium":   true,
	"high":     true,
	"critical": true,
}

// validatablePoCTypes are the PoC types that can be automatically validated
// by the Siege Engine.
var validatablePoCTypes = map[shared.PoCType]bool{
	shared.PoCTypeCurl:   true,
	shared.PoCTypePython: true,
}

// Marshal is the exploit forge coordinator. It orchestrates Holy Lance PoC
// generation, optional Siege Engine validation, and Seneschal persistence.
type Marshal struct {
	Generator        *holylance.Generator
	Store            *seneschal.Store
	AllowDestructive bool
}

// NewMarshal constructs a Marshal with the given generator, store, and
// destructive-action permission flag.
func NewMarshal(generator *holylance.Generator, store *seneschal.Store, allowDestructive bool) *Marshal {
	return &Marshal{
		Generator:        generator,
		Store:            store,
		AllowDestructive: allowDestructive,
	}
}

// ForgeExploits generates, optionally validates, and persists PoCs for a set of
// vulnerabilities associated with the given campaign.
//
// Only vulnerabilities with severity medium, high, or critical are processed.
// For each eligible vuln the Holy Lance generator is called; the resulting PoC
// is integrity-checked, optionally validated by the Siege Engine if its type
// supports execution, then collected. After all PoCs are assembled they are
// persisted via the Seneschal store before being returned.
func (m *Marshal) ForgeExploits(campaignID string, vulns []shared.Vulnerability) ([]shared.ProofOfConcept, error) {
	var pocs []shared.ProofOfConcept

	for _, vuln := range vulns {
		// 1. Filter: skip severities below medium.
		if !eligibleSeverities[strings.ToLower(vuln.Severity)] {
			continue
		}

		// 2. Generate a PoC via Holy Lance.
		poc, err := m.Generator.Generate(vuln)
		if err != nil {
			shared.LogAudit(shared.AuditEvent{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				EventType: "TOOL_FAILURE",
				URL:       vuln.Endpoint.URL,
				Message:   fmt.Sprintf("Holy Lance generation failed for vuln %s: %v", vuln.ID, err),
			})
			continue
		}

		// 3. Integrity check: VulnerabilityID on the PoC must match the source vuln.
		if poc.VulnerabilityID != vuln.ID {
			shared.LogAudit(shared.AuditEvent{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				EventType: "DATA_INTEGRITY_WARNING",
				URL:       vuln.Endpoint.URL,
				Message: fmt.Sprintf(
					"PoC VulnerabilityID mismatch: expected %s, got %s — skipping",
					vuln.ID, poc.VulnerabilityID,
				),
			})
			continue
		}

		// 4. Optionally validate via Siege Engine for executable PoC types.
		if validatablePoCTypes[poc.Type] {
			if err := siegeengine.ValidatePoC(&poc, vuln.Endpoint, m.AllowDestructive); err != nil {
				shared.LogAudit(shared.AuditEvent{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					EventType: "TOOL_FAILURE",
					URL:       vuln.Endpoint.URL,
					Message:   fmt.Sprintf("Siege Engine validation error for PoC %s: %v", poc.ID, err),
				})
				// Validation errors are non-fatal; collect the PoC with Validated=false.
			}
		}

		// 5. Collect the PoC.
		pocs = append(pocs, poc)
	}

	// 6. Persist all collected PoCs.
	if err := m.Store.StorePOCs(campaignID, pocs); err != nil {
		return pocs, fmt.Errorf("marshal: failed to store PoCs for campaign %s: %w", campaignID, err)
	}

	// 7. Return the collected PoCs.
	return pocs, nil
}
