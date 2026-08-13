package crusadeplanner

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/llm"
)

const (
	minPathLength = 2
	maxPathLength = 10
)

// FindChains enumerates all valid attack chains from the given AttackGraph,
// validates each candidate chain with the LLM, and returns the surviving
// chains sorted by descending CombinedCVSS, then descending step count,
// then ascending CreatedAt.
func FindChains(g *AttackGraph, llmClient *llm.LLMClient) ([]shared.AttackChain, error) {
	// Collect all paths of length 2–10 nodes using DFS.
	var candidates [][]*AttackGraphNode
	visited := make(map[*AttackGraphNode]bool)

	var dfs func(node *AttackGraphNode, path []*AttackGraphNode)
	dfs = func(node *AttackGraphNode, path []*AttackGraphNode) {
		path = append(path, node)

		if len(path) >= minPathLength {
			// Make a copy of the current path and record it as a candidate.
			cp := make([]*AttackGraphNode, len(path))
			copy(cp, path)
			candidates = append(candidates, cp)
		}

		if len(path) < maxPathLength {
			visited[node] = true
			for _, next := range g.Edges[node] {
				if !visited[next] {
					dfs(next, path)
				}
			}
			visited[node] = false
		}
	}

	for _, start := range g.Nodes {
		dfs(start, nil)
	}

	// Validate each candidate path with the LLM.
	var chains []shared.AttackChain
	for _, path := range candidates {
		feasible, rationale, err := validateChainWithLLM(llmClient, path)
		if err != nil {
			// Retry once.
			feasible, rationale, err = validateChainWithLLM(llmClient, path)
			if err != nil {
				log.Printf("CHAIN_VALIDATION_FAILURE: path of %d nodes excluded after retry: %v", len(path), err)
				continue
			}
		}

		if !feasible {
			log.Printf("Chain excluded as infeasible. Rationale: %s", rationale)
			continue
		}

		chain := buildAttackChain(path)
		chains = append(chains, chain)
	}

	// Sort: descending CombinedCVSS → descending step count → ascending CreatedAt.
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].CombinedCVSS != chains[j].CombinedCVSS {
			return chains[i].CombinedCVSS > chains[j].CombinedCVSS
		}
		if len(chains[i].Steps) != len(chains[j].Steps) {
			return len(chains[i].Steps) > len(chains[j].Steps)
		}
		return chains[i].CreatedAt.Before(chains[j].CreatedAt)
	})

	return chains, nil
}

// buildAttackChain constructs a shared.AttackChain from a validated node path.
func buildAttackChain(path []*AttackGraphNode) shared.AttackChain {
	steps := make([]shared.ChainStep, len(path))
	var combinedCVSS float64
	var highestNode *AttackGraphNode

	for i, node := range path {
		steps[i] = shared.ChainStep{
			Vulnerability:  node.Vulnerability,
			Preconditions:  node.Preconditions,
			Postconditions: node.Postconditions,
		}
		combinedCVSS += node.Vulnerability.CVSSScore
		if highestNode == nil || node.Vulnerability.CVSSScore > highestNode.Vulnerability.CVSSScore {
			highestNode = node
		}
	}

	return shared.AttackChain{
		ID:           uuid.New().String(),
		Steps:        steps,
		CombinedCVSS: combinedCVSS,
		Impact:       deriveImpact(highestNode),
		CreatedAt:    time.Now(),
	}
}

// deriveImpact derives ChainImpact from the highest-severity vulnerability node.
func deriveImpact(node *AttackGraphNode) shared.ChainImpact {
	if node == nil {
		return shared.ChainImpact{Level: "low", Description: "No significant impact identified."}
	}

	v := node.Vulnerability
	level := severityLevel(v.Severity, v.CVSSScore)
	description := fmt.Sprintf(
		"Highest severity vulnerability: %s (CVSS %.1f). Type: %s. %s",
		v.Title, v.CVSSScore, v.Type, v.Description,
	)

	return shared.ChainImpact{
		Level:       level,
		Description: description,
	}
}

// severityLevel normalises a severity string; falls back to CVSS score bands.
func severityLevel(severity string, cvss float64) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	}
	// Fall back to CVSS score.
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	case cvss >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

// validateChainWithLLM asks the LLM whether the given path is a feasible
// attack chain. Returns (feasible, rationale, error).
func validateChainWithLLM(client *llm.LLMClient, path []*AttackGraphNode) (bool, string, error) {
	prompt := buildChainPrompt(path)
	response, err := client.Call("analysis", prompt)
	if err != nil {
		return false, "", fmt.Errorf("LLM call failed: %w", err)
	}

	rationale := generateLLMRationale(response, path)

	lower := strings.ToLower(response)
	if strings.Contains(lower, "not feasible") ||
		strings.Contains(lower, "infeasible") ||
		strings.Contains(lower, "invalid") {
		return false, rationale, nil
	}

	return true, rationale, nil
}

// buildChainPrompt constructs the prompt describing the attack chain steps.
func buildChainPrompt(path []*AttackGraphNode) string {
	var sb strings.Builder
	sb.WriteString("Evaluate whether the following attack chain is technically feasible. ")
	sb.WriteString("Respond with a clear assessment.\n\n")
	sb.WriteString("Attack Chain Steps:\n")

	for i, node := range path {
		v := node.Vulnerability
		sb.WriteString(fmt.Sprintf(
			"Step %d: [%s] %s (Severity: %s, CVSS: %.1f)\n",
			i+1, v.Type, v.Title, v.Severity, v.CVSSScore,
		))
		sb.WriteString(fmt.Sprintf("  Preconditions:  %s\n", strings.Join(node.Preconditions, ", ")))
		sb.WriteString(fmt.Sprintf("  Postconditions: %s\n", strings.Join(node.Postconditions, ", ")))
	}

	sb.WriteString("\nIs this chain feasible as a multi-step attack sequence? Explain your reasoning.")
	return sb.String()
}

// generateLLMRationale ensures the rationale is at least 50 characters,
// padding with contextual information about the chain if it is shorter.
func generateLLMRationale(response string, path []*AttackGraphNode) string {
	const minRationaleLen = 50

	rationale := strings.TrimSpace(response)
	if len(rationale) >= minRationaleLen {
		return rationale
	}

	// Build padding context from the chain.
	types := make([]string, len(path))
	for i, node := range path {
		types[i] = string(node.Vulnerability.Type)
	}
	padding := fmt.Sprintf(
		" [Chain context: %d-step sequence involving %s]",
		len(path), strings.Join(types, " → "),
	)

	padded := rationale + padding
	// If still too short, append a generic note.
	for len(padded) < minRationaleLen {
		padded += " (no further detail provided)"
	}

	return padded
}
