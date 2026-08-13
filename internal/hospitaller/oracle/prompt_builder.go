package oracle

import (
	"encoding/json"

	"github.com/templar-framework/templar/internal/shared"
)

// BuildPrompt creates the AnalysisContext for the LLM fitting within 128,000 tokens
func BuildPrompt(endpoints []shared.DiscoveredEndpoint, hosts []shared.DiscoveredHost) string {
	// For MVP, we serialize the endpoints and host contexts to JSON to serve as prompt body
	
	contextData := struct {
		Endpoints []shared.DiscoveredEndpoint `json:"endpoints"`
		Hosts     []shared.DiscoveredHost     `json:"hosts"`
	}{
		Endpoints: endpoints,
		Hosts:     hosts,
	}

	b, _ := json.Marshal(contextData)

	prompt := "You are an expert security analyst evaluating the following endpoints for logical vulnerabilities (IDOR, Broken Access Control, Business Logic flaws).\n\n" +
		"Return your findings as a strict JSON array of Vulnerability objects.\n\n" +
		"Context:\n" + string(b)

	// In reality we would truncate to max tokens. We rely on standard Go tools in this MVP.
	if len(prompt) > 400000 {
		prompt = prompt[:400000] // Roughly 100k tokens safety bound
	}

	return prompt
}
