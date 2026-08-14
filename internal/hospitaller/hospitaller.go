package hospitaller

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/templar-framework/templar/internal/hospitaller/inquisitor"
	"github.com/templar-framework/templar/internal/hospitaller/oracle"
	"github.com/templar-framework/templar/internal/hospitaller/relichunter"
	"github.com/templar-framework/templar/internal/seneschal"
	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/llm"
	"github.com/templar-framework/templar/internal/shared/mcp"
)

type Hospitaller struct {
	Store     *seneschal.Store
	LLMClient *llm.LLMClient
	MCP       *mcp.Registry
}

func NewHospitaller(
	store *seneschal.Store,
	llmClient *llm.LLMClient,
) *Hospitaller {
	return &Hospitaller{
		Store:     store,
		LLMClient: llmClient,
	}
}

// NewHospitallerWithMCP creates a Hospitaller with an MCP registry.
func NewHospitallerWithMCP(
	store *seneschal.Store,
	llmClient *llm.LLMClient,
	reg *mcp.Registry,
) *Hospitaller {
	return &Hospitaller{
		Store:     store,
		LLMClient: llmClient,
		MCP:       reg,
	}
}

// Run performs the Hospitaller vulnerability-analysis phase.
//
// The individual scanners run concurrently where the original implementation
// did so, but errors are no longer discarded. A scanner failure is recorded
// and returned to the caller instead of silently becoming "zero findings".
func (h *Hospitaller) Run(
	campaignID string,
	surface shared.AttackSurface,
) ([]shared.Vulnerability, error) {

	var allVulns []shared.Vulnerability

	var (
		mu     sync.Mutex
		errMu  sync.Mutex
		errors []error
	)

	// -------------------------------------------------------------------------
	// Helper for safely collecting errors from concurrent workers.
	// -------------------------------------------------------------------------

	recordError := func(component string, err error) {
		if err == nil {
			return
		}

		wrapped := fmt.Errorf("%s: %w", component, err)

		errMu.Lock()
		errors = append(errors, wrapped)
		errMu.Unlock()

		// Audit the failure as well, so it remains visible even if the caller
		// does not print the returned error.
		shared.LogAudit(shared.AuditEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "HOSPITALLER_COMPONENT_FAILURE",
			URL:       "",
			RuleType:  component,
			Pattern:   "",
			Message:   wrapped.Error(),
		})
	}

	// -------------------------------------------------------------------------
	// 1. Inquisitor Layer
	//
	// Nuclei and ZAP run concurrently.
	// -------------------------------------------------------------------------

	var wg1 sync.WaitGroup
	wg1.Add(2)

	// Nuclei
	go func() {
		defer wg1.Done()

		vulns, err := inquisitor.RunNuclei(
			surface.Endpoints,
			h.MCP,
		)

		if err != nil {
			recordError("Nuclei", err)
		}

		if len(vulns) > 0 {
			mu.Lock()
			allVulns = append(allVulns, vulns...)
			mu.Unlock()
		}
	}()

	// ZAP
	go func() {
		defer wg1.Done()

		vulns, err := inquisitor.RunZAP(
			surface.Endpoints,
		)

		if err != nil {
			recordError("ZAP", err)
		}

		if len(vulns) > 0 {
			mu.Lock()
			allVulns = append(allVulns, vulns...)
			mu.Unlock()
		}
	}()

	wg1.Wait()

	// -------------------------------------------------------------------------
	// 2. Relic Hunter Layer - Using Real Tech Stack from Cartographer
	//
	// Query CVE sources for detected technologies (from Wappalyzer fingerprinting)
	// instead of mocking service versions.
	// -------------------------------------------------------------------------

	var wg2 sync.WaitGroup

	// 2a. Search CVEs for technologies detected by Cartographer
	if len(surface.TechStack) > 0 {
		fmt.Printf("[Hospitaller] Processing %d detected technologies for CVE search\n", len(surface.TechStack))
		
		for _, tech := range surface.TechStack {
			// Only search if we have a version
			if tech.Version == nil || *tech.Version == "" {
				fmt.Printf("[Hospitaller] Skipping %s: no version detected\n", tech.Name)
				continue
			}

			fmt.Printf("[Hospitaller] CVE search for: %s (v%s)\n", tech.Name, *tech.Version)

			// CVE search
			wg2.Add(1)

			go func(t shared.TechStackEntry) {
				defer wg2.Done()

				vulns, err := relichunter.SearchCVEs(t)

				if err != nil {
					recordError(
						fmt.Sprintf("RelicHunter CVE search (%s)", t.Name),
						err,
					)
				}

				if len(vulns) > 0 {
					fmt.Printf("[Hospitaller] CVE search found %d vulnerabilities for %s\n", len(vulns), t.Name)
					mu.Lock()
					allVulns = append(allVulns, vulns...)
					mu.Unlock()
				}
			}(tech)

			// ExploitDB search
			wg2.Add(1)

			go func(t shared.TechStackEntry) {
				defer wg2.Done()

				vulns, err := relichunter.SearchExploitDB(t)

				if err != nil {
					recordError(
						fmt.Sprintf("RelicHunter ExploitDB search (%s)", t.Name),
						err,
					)
				}

				if len(vulns) > 0 {
					fmt.Printf("[Hospitaller] ExploitDB found %d vulnerabilities for %s\n", len(vulns), t.Name)
					mu.Lock()
					allVulns = append(allVulns, vulns...)
					mu.Unlock()
				}
			}(tech)
		}
	} else {
		fmt.Println("[Hospitaller] No technologies detected by Cartographer, skipping CVE searches")
		shared.LogAudit(shared.AuditEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "HOSPITALLER_WARNING",
			Message:   "No technologies in TechStack; CVE sources will not be queried",
		})
	}

	// 2b. Also search for services detected by port scanning (fallback for incomplete fingerprinting)
	if len(surface.Hosts) > 0 {
		fmt.Printf("[Hospitaller] Processing %d hosts with port scan results\n", len(surface.Hosts))
		
		for _, host := range surface.Hosts {
			for _, svc := range host.Services {

				if svc == "" || svc == "unknown" {
					continue
				}

				// Use host fingerprinting if available, otherwise fallback to port scan service
				tech := shared.TechStackEntry{
					Name:    svc,
					Version: ptr("1.0.0"), // Fallback: assumed version from port scan
				}

				fmt.Printf("[Hospitaller] Fallback CVE search for port-scanned service: %s\n", svc)

				// CVE search
				wg2.Add(1)

				go func(t shared.TechStackEntry) {
					defer wg2.Done()

					vulns, err := relichunter.SearchCVEs(t)

					if err != nil {
						recordError(
							fmt.Sprintf("RelicHunter CVE search (fallback) (%s)", t.Name),
							err,
						)
					}

					if len(vulns) > 0 {
						fmt.Printf("[Hospitaller] Fallback CVE found %d vulnerabilities for %s\n", len(vulns), t.Name)
						mu.Lock()
						allVulns = append(allVulns, vulns...)
						mu.Unlock()
					}
				}(tech)
			}
		}
	}

	wg2.Wait()

	// -------------------------------------------------------------------------
	// 3. Oracle Layer
	// -------------------------------------------------------------------------

	if h.LLMClient != nil {
		vulns, err := oracle.Analyze(
			surface,
			h.LLMClient,
		)

		if err != nil {
			recordError("Oracle analysis", err)
		}

		if len(vulns) > 0 {
			mu.Lock()
			allVulns = append(allVulns, vulns...)
			mu.Unlock()
		}
	}

	// -------------------------------------------------------------------------
	// 4. Deduplicate
	// -------------------------------------------------------------------------

	deduped := deduplicateVulnerabilities(allVulns)

	// -------------------------------------------------------------------------
	// 5. Sort
	// -------------------------------------------------------------------------

	sortVulnerabilities(deduped)

	// -------------------------------------------------------------------------
	// 6. Store
	// -------------------------------------------------------------------------

	if h.Store != nil {
		h.Store.StoreVulnerabilities(
			campaignID,
			deduped,
		)
	}

	// -------------------------------------------------------------------------
	// 7. Return scanner errors instead of silently hiding them.
	//
	// Important:
	// We still return the vulnerabilities collected from successful components.
	// Therefore one broken scanner doesn't discard findings from another.
	// -------------------------------------------------------------------------

	if len(errors) > 0 {
		return deduped, combineErrors(errors)
	}

	return deduped, nil
}

// combineErrors combines multiple component failures into a single error.
//
// Go's standard errors.Join would also work on sufficiently recent Go
// versions, but keeping this explicit avoids introducing a dependency on the
// project's configured Go version.
func combineErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}

	var parts []string

	for _, err := range errs {
		if err == nil {
			continue
		}

		parts = append(parts, err.Error())
	}

	if len(parts) == 0 {
		return nil
	}

	return fmt.Errorf(
		"Hospitaller encountered %d component failure(s): %s",
		len(parts),
		strings.Join(parts, "; "),
	)
}

func deduplicateVulnerabilities(
	vulns []shared.Vulnerability,
) []shared.Vulnerability {

	vMap := make(map[string]*shared.Vulnerability)

	for _, v := range vulns {

		// Use the first evidence's matched template as the payload-like
		// discriminator, preserving the behavior of the original MVP.
		payload := ""

		if len(v.Evidence) > 0 {
			payload = v.Evidence[0].MatchedTemplate
		}

		key := v.Endpoint.URL + "|" + string(v.Type)

		if payload != "" {
			key += "|" + payload
		}

		if existing, ok := vMap[key]; ok {

			// Max CVSS
			if v.CVSSScore > existing.CVSSScore {
				existing.CVSSScore = v.CVSSScore
			}

			// Higher severity wins
			existing.Severity = maxSeverity(
				existing.Severity,
				v.Severity,
			)

			// Union of evidence
			existing.Evidence = append(
				existing.Evidence,
				v.Evidence...,
			)

		} else {
			copyV := v
			vMap[key] = &copyV
		}
	}

	final := make([]shared.Vulnerability, 0, len(vMap))

	for _, v := range vMap {
		final = append(final, *v)
	}

	return final
}

var sevRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
}

func maxSeverity(a, b string) string {
	a = strings.ToLower(a)
	b = strings.ToLower(b)

	if sevRank[a] >= sevRank[b] {
		return a
	}

	return b
}

func sortVulnerabilities(
	vulns []shared.Vulnerability,
) {
	sort.Slice(vulns, func(i, j int) bool {

		rI := sevRank[strings.ToLower(
			vulns[i].Severity,
		)]

		rJ := sevRank[strings.ToLower(
			vulns[j].Severity,
		)]

		if rI != rJ {
			return rI > rJ
		}

		return vulns[i].CVSSScore > vulns[j].CVSSScore
	})
}

func ptr(s string) *string {
	return &s
}
