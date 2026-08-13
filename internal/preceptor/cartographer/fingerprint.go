package cartographer

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/tools"
)

// wappalyzerOutput represents the JSON output format of the wappalyzer CLI
type wappalyzerOutput struct {
	URLs map[string]struct {
		Status int `json:"status"`
		Applications []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Category string `json:"category"`
		} `json:"applications"`
	} `json:"urls"`
}

// Fingerprint orchestrates Wappalyzer and httpx to identify tech stack
func Fingerprint(hosts []shared.DiscoveredHost) ([]shared.TechStackEntry, error) {
	var techStack []shared.TechStackEntry
	var targets []string
	
	// Prepare targets for fingerprinting
	for _, host := range hosts {
		for _, port := range host.OpenPorts {
			if port == 80 {
				targets = append(targets, "http://"+host.IP)
			} else if port == 443 {
				targets = append(targets, "https://"+host.IP)
			} else {
				targets = append(targets, "http://"+host.IP+":"+strconv.Itoa(port)) // naive approach
			}
		}
	}
	
	if len(targets) == 0 {
		return techStack, nil
	}

	// 1. httpx (Probing)
	// Output can be piped to wappalyzer or used directly. We'll use wappalyzer for tech stack.
	
	// 2. Wappalyzer
	// We'll mock the Wappalyzer CLI call because the real one takes target list via stdin or args.
	// We use comma separated args for this mock.
	out, _, exit, _ := tools.Execute("wappalyzer", append([]string{"--quiet", "--batch"}, targets...), 300)
	
	if exit == 0 && out != "" {
		var wOut []struct{
			Applications []struct {
				Name     string `json:"name"`
				Version  string `json:"version"`
				Categories []struct{
					Name string `json:"name"`
				} `json:"categories"`
			} `json:"applications"`
		}
		
		_ = json.Unmarshal([]byte(out), &wOut)
		
		// In MVP, we map Wappalyzer output to TechStackEntry
		for _, res := range wOut {
			for _, app := range res.Applications {
				var version *string
				if app.Version != "" {
					version = &app.Version
				}
				
				confidence := 0.5
				if version != nil {
					confidence = 0.9 // Higher confidence if version is detected
				}
				
				techStack = append(techStack, shared.TechStackEntry{
					Name:       strings.TrimSpace(app.Name),
					Category:   mapCategory(app.Categories),
					Version:    version,
					Confidence: confidence,
				})
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
