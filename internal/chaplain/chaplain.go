package chaplain

import (
	"log"
	"sort"

	"github.com/templar-framework/templar/internal/chaplain/crusadeplanner"
	"github.com/templar-framework/templar/internal/chaplain/hereticjudge"
	"github.com/templar-framework/templar/internal/seneschal"
	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/llm"
)

// Chaplain orchestrates the full attack chain analysis pipeline.
type Chaplain struct {
	Store     *seneschal.Store
	LLMClient *llm.LLMClient
}

// NewChaplain creates a new Chaplain with the given store and LLM client.
func NewChaplain(store *seneschal.Store, llmClient *llm.LLMClient) *Chaplain {
	return &Chaplain{
		Store:     store,
		LLMClient: llmClient,
	}
}

// PlanChains runs the full attack chain analysis pipeline for the given
// campaign and vulnerability list. It builds the attack graph, enumerates
// and validates chains, scores them, and persists the results.
//
// If no eligible vulnerabilities exist (none with Status "confirmed" or
// "poc_available"), it logs a skip message and returns an empty slice.
func (c *Chaplain) PlanChains(campaignID string, vulns []shared.Vulnerability) ([]shared.AttackChain, error) {
	// Step 1: check for eligible vulnerabilities.
	eligible := false
	for _, v := range vulns {
		if v.Status == "confirmed" || v.Status == "poc_available" {
			eligible = true
			break
		}
	}

	if len(vulns) == 0 || !eligible {
		log.Println("CHAIN_ANALYSIS_SKIPPED: no_eligible_vulnerabilities")
		return []shared.AttackChain{}, nil
	}

	// Step 2: build the attack graph.
	graph := crusadeplanner.BuildGraph(vulns)

	// Step 3: enumerate and validate chains.
	chains, err := crusadeplanner.FindChains(graph, c.LLMClient)
	if err != nil {
		return nil, err
	}

	// Step 4: score each chain and derive its impact.
	for i := range chains {
		hereticjudge.UpdateChainScore(&chains[i])
		chains[i].Impact = hereticjudge.DeriveImpact(chains[i])
	}

	// Step 5: sort — descending CombinedCVSS, then descending step count,
	// then ascending CreatedAt.
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].CombinedCVSS != chains[j].CombinedCVSS {
			return chains[i].CombinedCVSS > chains[j].CombinedCVSS
		}
		if len(chains[i].Steps) != len(chains[j].Steps) {
			return len(chains[i].Steps) > len(chains[j].Steps)
		}
		return chains[i].CreatedAt.Before(chains[j].CreatedAt)
	})

	// Step 6: persist all chains.
	if err := c.Store.StoreChains(campaignID, chains); err != nil {
		return nil, err
	}

	// Step 7: return the sorted chains.
	return chains, nil
}
