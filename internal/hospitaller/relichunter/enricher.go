package relichunter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/templar-framework/templar/internal/shared"
)

// MergeVulnerabilities takes slices of vulnerabilities from different sources
// and intelligently merges them by ID (e.g. CVE ID).
func MergeVulnerabilities(sources [][]shared.Vulnerability) []shared.Vulnerability {
	vulnMap := make(map[string]*shared.Vulnerability)

	for _, sourceVulns := range sources {
		for _, v := range sourceVulns {
			// Make a copy to avoid pointer issues
			vulnCopy := v
			
			existing, found := vulnMap[vulnCopy.ID]
			if !found {
				vulnMap[vulnCopy.ID] = &vulnCopy
				continue
			}

			// Merge Evidence
			existing.Evidence = append(existing.Evidence, vulnCopy.Evidence...)

			// Merge Tags and deduplicate
			tagMap := make(map[string]bool)
			for _, tag := range existing.Tags {
				tagMap[tag] = true
			}
			for _, tag := range vulnCopy.Tags {
				if !tagMap[tag] {
					existing.Tags = append(existing.Tags, tag)
					tagMap[tag] = true
				}
			}

			// Resolve severity conflict (take the highest CVSS)
			if vulnCopy.CVSSScore > existing.CVSSScore {
				existing.CVSSScore = vulnCopy.CVSSScore
				existing.Severity = vulnCopy.Severity
			}

			// Use the earliest disclosure date
			if existing.DisclosureDate.IsZero() || (!vulnCopy.DisclosureDate.IsZero() && vulnCopy.DisclosureDate.Before(existing.DisclosureDate)) {
				existing.DisclosureDate = vulnCopy.DisclosureDate
			}
			
			// Prefer non-empty title/description
			if existing.Title == "" && vulnCopy.Title != "" {
				existing.Title = vulnCopy.Title
			}
			if existing.Description == "" && vulnCopy.Description != "" {
				existing.Description = vulnCopy.Description
			}
		}
	}

	result := make([]shared.Vulnerability, 0, len(vulnMap))
	for _, v := range vulnMap {
		result = append(result, *v)
	}
	return result
}

type ghSearchResponse struct {
	TotalCount int `json:"total_count"`
	Items []struct {
		HTMLURL string `json:"html_url"`
	} `json:"items"`
}

// CheckExploitAvailability checks GitHub for proof-of-concept exploits for a given vulnerability.
func CheckExploitAvailability(ctx context.Context, vuln *shared.Vulnerability, githubToken string, client *http.Client) error {
	if vuln.ID == "" {
		return nil
	}

	if client == nil {
		client = http.DefaultClient
	}

	// We only want to search if it looks like a CVE, as GHSAs and H1 reports might not match public PoCs well
	if !strings.HasPrefix(strings.ToUpper(vuln.ID), "CVE-") {
		return nil
	}

	query := fmt.Sprintf("%s poc", vuln.ID)
	url := fmt.Sprintf("https://api.github.com/search/repositories?q=%s", query)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	
	if githubToken != "" {
		req.Header.Set("Authorization", "Bearer "+githubToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		// Rate limited, just skip enrichment silently
		return nil
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("github search returned %d", resp.StatusCode)
	}

	var searchResp ghSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return err
	}

	if searchResp.TotalCount > 0 && len(searchResp.Items) > 0 {
		vuln.ExploitAvailable = true
		vuln.Evidence = append(vuln.Evidence, shared.VulnEvidence{
			Type:    "public_exploit",
			Details: "Found public PoC: " + searchResp.Items[0].HTMLURL,
		})
	}

	return nil
}

// ExtractRemediation uses simple heuristics to find remediation guidance within evidence or descriptions.
func ExtractRemediation(vuln *shared.Vulnerability) {
	if vuln.Remediation != "" {
		return
	}

	searchTexts := []string{strings.ToLower(vuln.Description)}
	for _, ev := range vuln.Evidence {
		searchTexts = append(searchTexts, strings.ToLower(ev.Details))
	}

	remediationKeywords := []string{
		"upgrade to", "update to", "apply patch", "workaround", "mitigation", "fixed in",
	}

	for _, text := range searchTexts {
		for _, kw := range remediationKeywords {
			if strings.Contains(text, kw) {
				// Very basic heuristic: extract the snippet containing the keyword.
				// For a production implementation, an LLM call or more sophisticated regex is better.
				vuln.Remediation = "Guidance found indicating: " + kw
				return
			}
		}
	}
}
