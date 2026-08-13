// Package holylance implements the Holy Lance PoC generator sub-agent.
// It generates Proof-of-Concept exploits for confirmed vulnerabilities by first
// checking ExploitDB for existing exploits and falling back to LLM-driven generation.
package holylance

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"strings"
	"text/template"

	"github.com/google/uuid"
	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/llm"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// skippedSeverities lists the severity levels that must not receive a PoC.
var skippedSeverities = map[string]bool{
	"low":  true,
	"info": true,
}

// pocTypeByVulnType maps vuln types to their preferred PoC type (primary choice).
var pocTypeByVulnType = map[shared.VulnType]shared.PoCType{
	shared.VulnTypeSQLi:      shared.PoCTypeCurl,
	shared.VulnTypeXSS:       shared.PoCTypeCurl,
	shared.VulnTypeSSRF:      shared.PoCTypeCurl,
	shared.VulnTypeLFI:       shared.PoCTypeCurl,
	shared.VulnTypeRCE:       shared.PoCTypePython,
	shared.VulnTypeInjection: shared.PoCTypePython,
	shared.VulnTypeCSRF:      shared.PoCTypePython,
	shared.VulnTypeIDOR:      shared.PoCTypePython,
	shared.VulnTypeMisc:      shared.PoCTypePython,
}

// templateByVulnType maps vuln types to the template filename to use.
var templateByVulnType = map[shared.VulnType]string{
	shared.VulnTypeSQLi: "sqli.tmpl",
	shared.VulnTypeXSS:  "xss.tmpl",
	shared.VulnTypeSSRF: "ssrf.tmpl",
	shared.VulnTypeRCE:  "rce.tmpl",
}

// ExploitDBSearcher describes the interface used to search ExploitDB for existing
// exploits matching CVE identifiers. The relichunter package fulfils this.
type ExploitDBSearcher interface {
	SearchByCVE(cveIDs []string) ([]shared.Vulnerability, error)
}

// Generator holds the dependencies needed to generate PoCs.
type Generator struct {
	LLMClient  *llm.LLMClient
	ExploitDB  ExploitDBSearcher
	templates  *template.Template
}

// promptData is the data passed into a PoC prompt template.
type promptData struct {
	VulnType    string
	EndpointURL string
	Method      string
	Evidence    []shared.VulnEvidence
	CVEIDs      []string
	OutputFormat string
}

// NewGenerator creates a new Holy Lance generator, pre-parsing all embedded templates.
func NewGenerator(llmClient *llm.LLMClient, exploitDB ExploitDBSearcher) (*Generator, error) {
	if llmClient == nil {
		return nil, errors.New("llmClient is required")
	}

	tmpl, err := template.New("").ParseFS(templateFS, "templates/*.tmpl")
	if err != nil {
		return nil, fmt.Errorf("failed to parse PoC prompt templates: %w", err)
	}

	return &Generator{
		LLMClient: llmClient,
		ExploitDB: exploitDB,
		templates: tmpl,
	}, nil
}

// Generate produces a ProofOfConcept for the given vulnerability.
// It skips low/info severity vulns and tries ExploitDB before calling the LLM.
func (g *Generator) Generate(vuln shared.Vulnerability) (shared.ProofOfConcept, error) {
	if skippedSeverities[strings.ToLower(vuln.Severity)] {
		return shared.ProofOfConcept{}, fmt.Errorf(
			"skipping vulnerability %s: severity %q is below medium threshold",
			vuln.ID, vuln.Severity,
		)
	}

	// Determine the target PoC type based on vuln type.
	pocType := selectPoCType(vuln.Type)

	// 1. Search ExploitDB for existing exploits matching CVE IDs.
	if g.ExploitDB != nil && len(vuln.Evidence) > 0 {
		cveIDs := extractCVEIDs(vuln)
		if len(cveIDs) > 0 {
			existing, err := g.ExploitDB.SearchByCVE(cveIDs)
			if err == nil && len(existing) > 0 {
				best := selectBestExploit(existing)
				return adaptExploit(best, vuln, pocType), nil
			}
		}
	}

	// 2. Fall back to LLM-driven PoC generation.
	return g.generateViaLLM(vuln, pocType)
}

// generateViaLLM builds a structured prompt and calls the LLM with temperature 0.2.
func (g *Generator) generateViaLLM(vuln shared.Vulnerability, pocType shared.PoCType) (shared.ProofOfConcept, error) {
	prompt, err := g.buildPrompt(vuln, pocType)
	if err != nil {
		return shared.ProofOfConcept{}, fmt.Errorf("failed to build PoC prompt: %w", err)
	}

	rawResponse, err := g.LLMClient.Call("exploit_gen", prompt)
	if err != nil {
		return shared.ProofOfConcept{}, fmt.Errorf("LLM call failed: %w", err)
	}

	if err := validateLLMResponse(rawResponse); err != nil {
		return shared.ProofOfConcept{}, fmt.Errorf("LLM response rejected: %w", err)
	}

	return shared.ProofOfConcept{
		ID:              uuid.New().String(),
		VulnerabilityID: vuln.ID,
		Type:            pocType,
		Content:         rawResponse,
		Validated:       false,
	}, nil
}

// buildPrompt selects the appropriate template and renders it with vuln data.
func (g *Generator) buildPrompt(vuln shared.Vulnerability, pocType shared.PoCType) (string, error) {
	tmplName := selectTemplateName(vuln.Type)

	data := promptData{
		VulnType:     string(vuln.Type),
		EndpointURL:  vuln.Endpoint.URL,
		Method:       vuln.Endpoint.Method,
		Evidence:     vuln.Evidence,
		CVEIDs:       extractCVEIDs(vuln),
		OutputFormat: string(pocType),
	}

	var buf bytes.Buffer
	if err := g.templates.ExecuteTemplate(&buf, tmplName, data); err != nil {
		return "", fmt.Errorf("template %q execution failed: %w", tmplName, err)
	}

	return buf.String(), nil
}

// validateLLMResponse rejects empty responses or those containing no code block.
func validateLLMResponse(response string) error {
	trimmed := strings.TrimSpace(response)
	if trimmed == "" {
		return errors.New("LLM returned an empty response")
	}
	if !strings.Contains(trimmed, "```") {
		return errors.New("LLM response contains no code block (expected a fenced ``` block)")
	}
	return nil
}

// selectPoCType returns the preferred PoCType for a given vulnerability type.
// Defaults to python_script for unknown types.
func selectPoCType(vulnType shared.VulnType) shared.PoCType {
	if t, ok := pocTypeByVulnType[vulnType]; ok {
		return t
	}
	return shared.PoCTypePython
}

// selectTemplateName returns the template filename for the given vuln type,
// falling back to generic.tmpl for unrecognised types.
func selectTemplateName(vulnType shared.VulnType) string {
	if name, ok := templateByVulnType[vulnType]; ok {
		return name
	}
	return "generic.tmpl"
}

// extractCVEIDs collects CVE identifiers from the vulnerability's evidence.
// Assumes evidence of type "cve" carries the CVE ID in the Details field.
func extractCVEIDs(vuln shared.Vulnerability) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, ev := range vuln.Evidence {
		if strings.EqualFold(ev.Type, "cve") && ev.Details != "" {
			if !seen[ev.Details] {
				seen[ev.Details] = true
				ids = append(ids, ev.Details)
			}
		}
	}
	return ids
}

// selectBestExploit picks the highest-severity existing exploit from a list.
// Prefers critical > high > medium > anything else.
func selectBestExploit(exploits []shared.Vulnerability) shared.Vulnerability {
	order := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
	best := exploits[0]
	for _, e := range exploits[1:] {
		if order[strings.ToLower(e.Severity)] > order[strings.ToLower(best.Severity)] {
			best = e
		}
	}
	return best
}

// adaptExploit converts an existing ExploitDB finding into a ProofOfConcept
// targeted at the confirmed vulnerability's endpoint.
func adaptExploit(exploit shared.Vulnerability, vuln shared.Vulnerability, pocType shared.PoCType) shared.ProofOfConcept {
	// Build adapted content noting the original exploit and the target endpoint.
	content := fmt.Sprintf(
		"# Adapted from ExploitDB match: %s\n# Target endpoint: %s [%s]\n\n%s",
		exploit.ID,
		vuln.Endpoint.URL,
		vuln.Endpoint.Method,
		buildAdaptedContent(exploit, vuln),
	)

	// If the exploit's format can't be determined, normalise to the preferred type.
	resolvedType := resolveAdaptedPoCType(exploit, pocType)

	return shared.ProofOfConcept{
		ID:              uuid.New().String(),
		VulnerabilityID: vuln.ID,
		Type:            resolvedType,
		Content:         content,
		Validated:       false,
	}
}

// buildAdaptedContent generates a minimal adapted exploit body from an ExploitDB entry.
func buildAdaptedContent(exploit shared.Vulnerability, vuln shared.Vulnerability) string {
	var sb strings.Builder
	sb.WriteString("```python\n")
	sb.WriteString("# Auto-adapted PoC — review and test before use\n")
	sb.WriteString(fmt.Sprintf("import requests\n\n"))
	sb.WriteString(fmt.Sprintf("TARGET = %q\n", vuln.Endpoint.URL))
	sb.WriteString(fmt.Sprintf("METHOD = %q\n\n", vuln.Endpoint.Method))
	sb.WriteString("# Original exploit description:\n")
	for _, ev := range exploit.Evidence {
		sb.WriteString(fmt.Sprintf("# [%s] %s\n", ev.Type, ev.Details))
	}
	sb.WriteString("\nresp = requests.request(METHOD, TARGET)\n")
	sb.WriteString("print(f'Status: {resp.status_code}')\n")
	sb.WriteString("print(resp.text[:2048])\n")
	sb.WriteString("```\n")
	return sb.String()
}

// resolveAdaptedPoCType ensures the adapted PoC has a valid PoCType.
// Falls back to python_script if the original format doesn't map to a known type.
func resolveAdaptedPoCType(exploit shared.Vulnerability, preferred shared.PoCType) shared.PoCType {
	// Attempt to infer type from evidence details (best-effort heuristic).
	for _, ev := range exploit.Evidence {
		lower := strings.ToLower(ev.Details)
		switch {
		case strings.Contains(lower, "metasploit") || strings.Contains(lower, "msf"):
			return shared.PoCTypeMetasploit
		case strings.Contains(lower, "curl"):
			return shared.PoCTypeCurl
		case strings.Contains(lower, "burp"):
			return shared.PoCTypeBurp
		case strings.Contains(lower, "browser") || strings.Contains(lower, "steps"):
			return shared.PoCTypeBrowser
		case strings.Contains(lower, "python") || strings.Contains(lower, "script"):
			return shared.PoCTypePython
		}
	}
	// Prefer the caller's preferred type; default python_script if not a valid PoCType.
	if isValidPoCType(preferred) {
		return preferred
	}
	return shared.PoCTypePython
}

// isValidPoCType confirms the value is one of the five accepted PoCType constants.
func isValidPoCType(t shared.PoCType) bool {
	switch t {
	case shared.PoCTypeCurl, shared.PoCTypePython,
		shared.PoCTypeMetasploit, shared.PoCTypeBurp, shared.PoCTypeBrowser:
		return true
	}
	return false
}
