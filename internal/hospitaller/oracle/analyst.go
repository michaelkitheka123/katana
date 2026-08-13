package oracle

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/llm"
)

// Analyze endpoints via AI
func Analyze(surface shared.AttackSurface, llmClient *llm.LLMClient) ([]shared.Vulnerability, error) {
	if llmClient == nil || len(surface.Endpoints) == 0 {
		return nil, nil
	}

	var allVulns []shared.Vulnerability
	batchSize := 10

	for i := 0; i < len(surface.Endpoints); i += batchSize {
		end := i + batchSize
		if end > len(surface.Endpoints) {
			end = len(surface.Endpoints)
		}

		batch := surface.Endpoints[i:end]
		prompt := BuildPrompt(batch, surface.Hosts)

		// 3. Call configured LLM with role analysis
		resp, err := llmClient.Call("analysis", prompt)
		if err != nil {
			shared.LogAudit(shared.AuditEvent{Timestamp: time.Now().UTC().Format(time.RFC3339), EventType: "LLM_FAILURE", Message: err.Error()})
			continue
		}

		// Strip markdown formatting if the LLM wrapped the JSON
		cleanResp := resp
		if strings.HasPrefix(strings.TrimSpace(cleanResp), "```json") {
			cleanResp = strings.TrimSpace(cleanResp)
			cleanResp = strings.TrimPrefix(cleanResp, "```json")
			cleanResp = strings.TrimSuffix(cleanResp, "```")
		} else if strings.HasPrefix(strings.TrimSpace(cleanResp), "```") {
			cleanResp = strings.TrimSpace(cleanResp)
			cleanResp = strings.TrimPrefix(cleanResp, "```")
			cleanResp = strings.TrimSuffix(cleanResp, "```")
		}

		var aiVulns []shared.Vulnerability
		if err := json.Unmarshal([]byte(cleanResp), &aiVulns); err == nil {
			for _, v := range aiVulns {
				// Discard any AI finding whose endpoint URL is absent from the AttackSurface
				if !isValidEndpoint(v.Endpoint.URL, surface.Endpoints) {
					shared.LogAudit(shared.AuditEvent{
						Timestamp: time.Now().UTC().Format(time.RFC3339),
						EventType: "DATA_INTEGRITY_WARNING",
						Message:   "LLM hallucinated URL: " + v.Endpoint.URL,
					})
					continue
				}
				allVulns = append(allVulns, v)
			}
		}
	}

	return allVulns, nil
}

func isValidEndpoint(url string, endpoints []shared.DiscoveredEndpoint) bool {
	for _, ep := range endpoints {
		if ep.URL == url {
			return true
		}
	}
	return false
}
