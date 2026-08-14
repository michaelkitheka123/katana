package cartographer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/tools"
)

// wappalyzerOutput represents the actual JSON output format of the wappalyzer CLI.
// The CLI returns: {"urls": {"http://example.com": {"applications": [...], "status": 200}}}
type wappalyzerOutput struct {
	URLs map[string]struct {
		Status       int `json:"status"`
		Applications []struct {
			Name       string `json:"name"`
			Version    string `json:"version"`
			Categories []struct {
				Name string `json:"name"`
			} `json:"categories"`
		} `json:"applications"`
	} `json:"urls"`
}

// Fingerprint orchestrates Wappalyzer and httpx to identify tech stack
func Fingerprint(hosts []shared.DiscoveredHost) ([]shared.TechStackEntry, error) {
	var techStack []shared.TechStackEntry
	var targets []string
	
	// Validate that we have hosts
	if len(hosts) == 0 {
		fmt.Println("Fingerprinting: no hosts provided, skipping")
		return techStack, nil
	}

	// Prepare targets for fingerprinting
	for _, host := range hosts {
		// Skip hosts with no open ports
		if len(host.OpenPorts) == 0 {
			continue
		}

		for _, port := range host.OpenPorts {
			if port == 80 {
				targets = append(targets, "http://"+host.IP)
			} else if port == 443 {
				targets = append(targets, "https://"+host.IP)
			} else {
				// For other ports, try http first (more common)
				targets = append(targets, "http://"+host.IP+":"+strconv.Itoa(port))
			}
		}
	}
	
	if len(targets) == 0 {
		fmt.Println("Fingerprinting: no valid targets from hosts, skipping")
		return techStack, nil
	}

	fmt.Printf("Fingerprinting %d targets: %v\n", len(targets), targets)

	// 1. httpx (Probing) - validates which targets are actually alive
	// We use wappalyzer directly on the targets we have

	// 2. Wappalyzer - Attempt to run, but handle gracefully if not installed
	out, stderr, exit, execErr := tools.Execute("wappalyzer", append([]string{"--quiet", "--batch"}, targets...), 300)
	
	if execErr != nil {
		// wappalyzer not found or failed to execute
		fmt.Printf("Warning: Wappalyzer execution failed (%v). Fingerprinting will be skipped.\n", execErr)
		fmt.Println("Install wappalyzer with: npm install -g wappalyzer")
		shared.LogAudit(shared.AuditEvent{
			Timestamp: shared.GetTimestamp(),
			EventType: "TOOL_WARNING",
			Message:   fmt.Sprintf("Wappalyzer not available: %v", execErr),
		})
		return techStack, nil
	}

	if exit != 0 {
		fmt.Printf("Warning: Wappalyzer returned exit code %d\n", exit)
		if stderr != "" {
			fmt.Printf("Stderr: %s\n", stderr)
		}
		// Continue anyway - might be partial results
	}

	if out != "" {
		fmt.Printf("DEBUG: Wappalyzer raw output:\n%s\n\n", out)
		
		// Parse the actual Wappalyzer JSON format: {"urls": {"http://target": {...}}}
		var wOut wappalyzerOutput
		
		if err := json.Unmarshal([]byte(out), &wOut); err != nil {
			fmt.Printf("Warning: Failed to parse Wappalyzer output: %v\n", err)
			shared.LogAudit(shared.AuditEvent{
				Timestamp: shared.GetTimestamp(),
				EventType: "TOOL_FAILURE",
				Message:   fmt.Sprintf("Wappalyzer JSON parsing failed: %v, output was: %s", err, out),
			})
		} else {
			// Extract applications from the URLs map
			for url, urlData := range wOut.URLs {
				fmt.Printf("DEBUG: Processing URL: %s (status: %d, apps: %d)\n", url, urlData.Status, len(urlData.Applications))
				
				for _, app := range urlData.Applications {
					var version *string
					if app.Version != "" {
						version = &app.Version
					}
					
					confidence := 0.5
					if version != nil {
						confidence = 0.9 // Higher confidence if version is detected
					}
					
					entry := shared.TechStackEntry{
						Name:       strings.TrimSpace(app.Name),
						Category:   mapCategory(app.Categories),
						Version:    version,
						Confidence: confidence,
					}
					
					fmt.Printf("DEBUG: Detected tech: %s (v%s, confidence: %.2f)\n", entry.Name, 
						func(v *string) string { if v == nil { return "unknown" }; return *v }(version), 
						confidence)
					
					techStack = append(techStack, entry)
				}
			}
		}
	}
	
	// Deduplicate
	dedupMap := make(map[string]shared.TechStackEntry)
	for _, t := range techStack {
		dedupMap[t.Name] = t
	}
	
	var finalStack []shared.TechStackEntry
	for _, t := range dedupMap {
		finalStack = append(finalStack, t)
	}

	fmt.Printf("Fingerprinting complete: detected %d technologies\n", len(finalStack))
	
	shared.LogAudit(shared.AuditEvent{
		Timestamp: shared.GetTimestamp(),
		EventType: "FINGERPRINTING_COMPLETE",
		Message:   fmt.Sprintf("Detected %d technologies: %v", len(finalStack), func() []string {
			var names []string
			for _, t := range finalStack {
				names = append(names, t.Name)
			}
			return names
		}()),
	})
	
	return finalStack, nil
}

func mapCategory(cats []struct{Name string `json:"name"`}) shared.TechCategory {
	if len(cats) == 0 {
		return shared.TechCategoryMisc
	}
	
	cat := strings.ToLower(cats[0].Name)
	if strings.Contains(cat, "web") || strings.Contains(cat, "server") {
		return shared.TechCategoryWeb
	}
	if strings.Contains(cat, "database") || strings.Contains(cat, "data") {
		return shared.TechCategoryDB
	}
	if strings.Contains(cat, "language") || strings.Contains(cat, "php") {
		return shared.TechCategoryLang
	}
	if strings.Contains(cat, "framework") || strings.Contains(cat, "library") {
		return shared.TechCategoryFramework
	}
	if strings.Contains(cat, "operating system") || strings.Contains(cat, "os") {
		return shared.TechCategoryOS
	}
	
	return shared.TechCategoryMisc
}
