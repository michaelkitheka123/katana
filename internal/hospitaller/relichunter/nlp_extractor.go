package relichunter

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/llm"
)

// NLPBehavioralMatch represents the result of the LLM evaluating an unstructured report against an attack surface.
type NLPBehavioralMatch struct {
	MatchesTarget bool    `json:"matches_target"`
	Confidence    float64 `json:"confidence"`
	Reasoning     string  `json:"reasoning"`
}

// EvaluateBehavioralMatch uses an LLM to evaluate if a vulnerability described in unstructured text
// practically affects the given attack surface (e.g., specific endpoints or parameters).
func EvaluateBehavioralMatch(ctx context.Context, llmClient *llm.LLMClient, reportText string, surface shared.AttackSurface) (*NLPBehavioralMatch, error) {
	if llmClient == nil {
		return nil, fmt.Errorf("no LLM client provided")
	}

	// Prepare surface context
	var surfaceCtx strings.Builder
	surfaceCtx.WriteString("Target Attack Surface:\n")
	for _, ep := range surface.Endpoints {
		surfaceCtx.WriteString(fmt.Sprintf("- %s %s\n", ep.Method, ep.URL))
		if len(ep.Parameters) > 0 {
			surfaceCtx.WriteString("  Parameters: ")
			for i, p := range ep.Parameters {
				surfaceCtx.WriteString(p.Name)
				if i < len(ep.Parameters)-1 {
					surfaceCtx.WriteString(", ")
				}
			}
			surfaceCtx.WriteString("\n")
		}
	}

	prompt := fmt.Sprintf(`You are an expert security analyst. Evaluate if the following vulnerability report applies to the target attack surface based on behavioral preconditions (e.g. specific endpoints, API structures, or parameters mentioned in the report).

Vulnerability Report:
%s

%s

Determine if the vulnerability likely applies to the target's attack surface.
Return a JSON object matching this schema exactly (no markdown formatting, just pure JSON):
{
  "matches_target": true/false,
  "confidence": 0.0 to 1.0 (float),
  "reasoning": "brief explanation"
}
`, reportText, surfaceCtx.String())

	// Use the "analysis" role
	resp, err := llmClient.Call("analysis", prompt)
	if err != nil {
		return nil, fmt.Errorf("LLM analysis failed: %w", err)
	}

	// Clean up LLM output if it added markdown
	resp = strings.TrimSpace(resp)
	resp = strings.TrimPrefix(resp, "```json")
	resp = strings.TrimPrefix(resp, "```")
	resp = strings.TrimSuffix(resp, "```")
	resp = strings.TrimSpace(resp)

	var match NLPBehavioralMatch
	if err := json.Unmarshal([]byte(resp), &match); err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return &match, nil
}
