package chronicle

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/templar-framework/templar/internal/shared"
)

// SARIF 2.1.0 struct definitions — all types are defined locally and use only stdlib.

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	HelpURI          string          `json:"helpUri"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// vulnTypeMetadata holds the human-readable name and OWASP help URI for each VulnType.
var vulnTypeMetadata = map[shared.VulnType]struct {
	name    string
	helpURI string
}{
	shared.VulnTypeSQLi:      {"SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"},
	shared.VulnTypeXSS:       {"Cross-Site Scripting", "https://owasp.org/www-community/attacks/xss/"},
	shared.VulnTypeCSRF:      {"Cross-Site Request Forgery", "https://owasp.org/www-community/attacks/csrf"},
	shared.VulnTypeIDOR:      {"Insecure Direct Object Reference", "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"},
	shared.VulnTypeSSRF:      {"Server-Side Request Forgery", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"},
	shared.VulnTypeRCE:       {"Remote Code Execution", "https://owasp.org/www-community/attacks/Code_Injection"},
	shared.VulnTypeLFI:       {"Local File Inclusion", "https://owasp.org/www-community/attacks/Path_Traversal"},
	shared.VulnTypeInjection: {"Injection", "https://owasp.org/www-community/attacks/Injection_Flaws"},
	shared.VulnTypeMisc:      {"Miscellaneous Vulnerability", "https://owasp.org/www-community/vulnerabilities/"},
}

// sarifLevel maps a vulnerability severity string to the SARIF result level.
// critical/high → error, medium → warning, low/info/anything else → note.
func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// ruleMetadata returns the human-readable name and help URI for a VulnType.
// Falls back to a generic entry for unknown types.
func ruleMetadata(vt shared.VulnType) (name, helpURI string) {
	if meta, ok := vulnTypeMetadata[vt]; ok {
		return meta.name, meta.helpURI
	}
	return string(vt), "https://owasp.org/www-community/vulnerabilities/"
}

// RenderSARIF converts an ArtifactBundle into a valid SARIF 2.1.0 JSON document.
//
// The output contains a single run with:
//   - one rule entry per unique VulnType found across all vulnerabilities
//   - one result entry per vulnerability
//
// Severity is mapped to SARIF levels: critical/high → error, medium → warning,
// low/info/unknown → note.
func RenderSARIF(bundle *ArtifactBundle) ([]byte, error) {
	// Collect unique VulnTypes in stable insertion order.
	seen := map[shared.VulnType]bool{}
	var orderedTypes []shared.VulnType
	for _, v := range bundle.Vulnerabilities {
		if !seen[v.Type] {
			seen[v.Type] = true
			orderedTypes = append(orderedTypes, v.Type)
		}
	}

	// Build one SARIF rule per unique VulnType.
	rules := make([]sarifRule, 0, len(orderedTypes))
	for _, vt := range orderedTypes {
		name, helpURI := ruleMetadata(vt)
		rules = append(rules, sarifRule{
			ID:               string(vt),
			Name:             name,
			ShortDescription: sarifMessage{Text: fmt.Sprintf("%s vulnerability", name)},
			HelpURI:          helpURI,
		})
	}

	// Build one SARIF result per vulnerability.
	results := make([]sarifResult, 0, len(bundle.Vulnerabilities))
	for _, v := range bundle.Vulnerabilities {
		results = append(results, sarifResult{
			RuleID: string(v.Type),
			Level:  sarifLevel(v.Severity),
			Message: sarifMessage{
				Text: fmt.Sprintf("%s: %s", v.Title, v.Description),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: v.Endpoint.URL,
						},
					},
				},
			},
		})
	}

	doc := sarifDocument{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Templar",
						Version:        "1.0.0",
						InformationURI: "https://github.com/templar-framework/templar",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(doc, "", "  ")
}
