package chronicle

import (
	"fmt"
	"strings"

	"github.com/templar-framework/templar/internal/shared"
)

// RenderMarkdown transforms an ArtifactBundle into a structured Markdown report
// string. The report always contains the five core sections (Executive Summary,
// Attack Surface, Vulnerabilities, Proof of Concepts, Attack Chains) and
// conditionally includes Operational Issues and Excluded Targets when the
// corresponding bundle fields are non-empty.
func RenderMarkdown(bundle *ArtifactBundle) (string, error) {
	var b strings.Builder

	writeExecutiveSummary(&b, bundle)
	writeAttackSurface(&b, bundle)
	writeVulnerabilities(&b, bundle)
	writeProofOfConcepts(&b, bundle)
	writeAttackChains(&b, bundle)

	if len(bundle.DegradedPhases) > 0 {
		writeOperationalIssues(&b, bundle)
	}
	if len(bundle.ScopeViolations) > 0 {
		writeExcludedTargets(&b, bundle)
	}

	return b.String(), nil
}

// writeExecutiveSummary renders the ## Executive Summary section.
func writeExecutiveSummary(b *strings.Builder, bundle *ArtifactBundle) {
	b.WriteString("## Executive Summary\n\n")
	fmt.Fprintf(b, "**Campaign ID:** %s\n\n", bundle.CampaignID)

	// Count vulnerabilities by severity.
	severityCounts := map[string]int{}
	for _, v := range bundle.Vulnerabilities {
		severityCounts[strings.ToLower(v.Severity)]++
	}

	b.WriteString("**Vulnerability Counts by Severity:**\n\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "informational"} {
		if n, ok := severityCounts[sev]; ok {
			fmt.Fprintf(b, "- %s: %d\n", strings.Title(sev), n)
		}
	}
	b.WriteString("\n")

	fmt.Fprintf(b, "**Attack Chain Count:** %d\n\n", len(bundle.AttackChains))
	fmt.Fprintf(b, "**Proof of Concept Count:** %d\n\n", len(bundle.PoCs))

	riskRating := overallRiskRating(bundle.Vulnerabilities)
	fmt.Fprintf(b, "**Overall Risk Rating:** %s\n\n", riskRating)
}

// overallRiskRating returns "Critical" if any vulnerability has critical severity,
// otherwise returns the highest severity present, or "None" if there are no vulns.
func overallRiskRating(vulns []shared.Vulnerability) string {
	order := []string{"critical", "high", "medium", "low", "informational"}
	found := map[string]bool{}
	for _, v := range vulns {
		found[strings.ToLower(v.Severity)] = true
	}
	if found["critical"] {
		return "Critical"
	}
	for _, sev := range order {
		if found[sev] {
			return strings.Title(sev)
		}
	}
	return "None"
}

// writeAttackSurface renders the ## Attack Surface section.
func writeAttackSurface(b *strings.Builder, bundle *ArtifactBundle) {
	as := bundle.AttackSurface
	b.WriteString("## Attack Surface\n\n")
	fmt.Fprintf(b, "**Subdomain Count:** %d\n\n", len(as.Subdomains))
	fmt.Fprintf(b, "**Host Count:** %d\n\n", len(as.Hosts))
	fmt.Fprintf(b, "**Endpoint Count:** %d\n\n", len(as.Endpoints))

	if len(as.Endpoints) > 0 {
		b.WriteString("| URL | Method | Source |\n")
		b.WriteString("| --- | ------ | ------ |\n")
		for _, ep := range as.Endpoints {
			source := strings.Join(ep.Source, ", ")
			fmt.Fprintf(b, "| %s | %s | %s |\n", ep.URL, ep.Method, source)
		}
		b.WriteString("\n")
	}
}

// writeVulnerabilities renders the ## Vulnerabilities section.
func writeVulnerabilities(b *strings.Builder, bundle *ArtifactBundle) {
	b.WriteString("## Vulnerabilities\n\n")

	if len(bundle.Vulnerabilities) == 0 {
		b.WriteString("No vulnerabilities found.\n\n")
		return
	}

	for _, v := range bundle.Vulnerabilities {
		fmt.Fprintf(b, "### %s\n\n", v.Title)
		if v.ExploitAvailable {
			b.WriteString("> [!WARNING]\n> **Public Exploit Available**\n\n")
		}
		fmt.Fprintf(b, "- **ID:** %s\n", v.ID)
		fmt.Fprintf(b, "- **Severity:** %s\n", v.Severity)
		fmt.Fprintf(b, "- **CVSS Score:** %.1f\n", v.CVSSScore)
		fmt.Fprintf(b, "- **Endpoint:** %s\n", v.Endpoint.URL)
		if !v.DisclosureDate.IsZero() {
			fmt.Fprintf(b, "- **Disclosure Date:** %s\n", v.DisclosureDate.Format("2006-01-02"))
		}
		if len(v.Tags) > 0 {
			fmt.Fprintf(b, "- **Tags:** %s\n", strings.Join(v.Tags, ", "))
		}
		b.WriteString("\n")
		fmt.Fprintf(b, "**Description:** %s\n\n", v.Description)
		if v.Remediation != "" {
			b.WriteString("**Remediation:**\n\n")
			fmt.Fprintf(b, "%s\n\n", v.Remediation)
		}

		if len(v.Evidence) > 0 {
			b.WriteString("**Evidence:**\n\n")
			for _, ev := range v.Evidence {
				fmt.Fprintf(b, "- **Type:** %s\n", ev.Type)
				if ev.MatchedTemplate != "" {
					fmt.Fprintf(b, "  - **Matched Template:** %s\n", ev.MatchedTemplate)
				}
				if ev.Details != "" {
					fmt.Fprintf(b, "  - **Details:** %s\n", ev.Details)
				}
			}
			b.WriteString("\n")
		}
	}
}

// writeProofOfConcepts renders the ## Proof of Concepts section.
func writeProofOfConcepts(b *strings.Builder, bundle *ArtifactBundle) {
	b.WriteString("## Proof of Concepts\n\n")

	if len(bundle.PoCs) == 0 {
		b.WriteString("No proof of concepts available.\n\n")
		return
	}

	for _, poc := range bundle.PoCs {
		fmt.Fprintf(b, "### PoC — Vulnerability %s\n\n", poc.VulnerabilityID)
		fmt.Fprintf(b, "- **ID:** %s\n", poc.ID)
		fmt.Fprintf(b, "- **Type:** %s\n", poc.Type)

		validated := "No"
		if poc.Validated {
			validated = "Yes"
		}
		fmt.Fprintf(b, "- **Validated:** %s\n\n", validated)

		if poc.ValidationOutput != "" {
			fmt.Fprintf(b, "**Validation Output:** %s\n\n", poc.ValidationOutput)
		}

		b.WriteString("```\n")
		b.WriteString(poc.Content)
		b.WriteString("\n```\n\n")
	}
}

// writeAttackChains renders the ## Attack Chains section.
func writeAttackChains(b *strings.Builder, bundle *ArtifactBundle) {
	b.WriteString("## Attack Chains\n\n")

	if len(bundle.AttackChains) == 0 {
		b.WriteString("No attack chains identified.\n\n")
		return
	}

	for _, chain := range bundle.AttackChains {
		fmt.Fprintf(b, "### Chain %s\n\n", chain.ID)
		fmt.Fprintf(b, "- **Combined CVSS:** %.1f\n", chain.CombinedCVSS)
		fmt.Fprintf(b, "- **Impact Level:** %s\n\n", chain.Impact.Level)

		if chain.Impact.Description != "" {
			fmt.Fprintf(b, "**Rationale:** %s\n\n", chain.Impact.Description)
		}

		if len(chain.Steps) > 0 {
			b.WriteString("**Steps:**\n\n")
			for i, step := range chain.Steps {
				fmt.Fprintf(b, "%d. **%s** (Severity: %s, CVSS: %.1f)\n",
					i+1,
					step.Vulnerability.Title,
					step.Vulnerability.Severity,
					step.Vulnerability.CVSSScore,
				)
				if len(step.Preconditions) > 0 {
					fmt.Fprintf(b, "   - Preconditions: %s\n", strings.Join(step.Preconditions, "; "))
				}
				if len(step.Postconditions) > 0 {
					fmt.Fprintf(b, "   - Postconditions: %s\n", strings.Join(step.Postconditions, "; "))
				}
			}
			b.WriteString("\n")
		}
	}
}

// writeOperationalIssues renders the ## Operational Issues section.
// Only called when bundle.DegradedPhases is non-empty.
func writeOperationalIssues(b *strings.Builder, bundle *ArtifactBundle) {
	b.WriteString("## Operational Issues\n\n")
	b.WriteString("The following phases completed in a degraded state:\n\n")
	for _, phase := range bundle.DegradedPhases {
		fmt.Fprintf(b, "- %s\n", phase)
	}
	b.WriteString("\n")
}

// writeExcludedTargets renders the ## Excluded Targets section.
// Only called when bundle.ScopeViolations is non-empty.
func writeExcludedTargets(b *strings.Builder, bundle *ArtifactBundle) {
	b.WriteString("## Excluded Targets\n\n")
	b.WriteString("The following URLs were blocked by the Scope Enforcer:\n\n")
	for _, url := range bundle.ScopeViolations {
		fmt.Fprintf(b, "- %s\n", url)
	}
	b.WriteString("\n")
}
