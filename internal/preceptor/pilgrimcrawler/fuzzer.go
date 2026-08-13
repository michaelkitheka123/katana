package pilgrimcrawler

import (
	"strings"
	"sync"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/tools"
)

// Fuzz orchestrates ffuf, feroxbuster, and x8 to find hidden paths and parameters
func Fuzz(targets []string, existingEndpoints []shared.DiscoveredEndpoint) ([]shared.DiscoveredEndpoint, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	// Index existing endpoints by URL and Method
	epMap := make(map[string]*shared.DiscoveredEndpoint)
	for i, ep := range existingEndpoints {
		key := ep.Method + "|" + ep.URL
		epMap[key] = &existingEndpoints[i]
	}
	
	addEndpoint := func(url, method, source string) {
		url = strings.TrimSpace(url)
		if url == "" {
			return
		}
		
		key := method + "|" + url
		mu.Lock()
		defer mu.Unlock()
		
		if existing, ok := epMap[key]; ok {
			hasSource := false
			for _, s := range existing.Source {
				if s == source {
					hasSource = true
					break
				}
			}
			if !hasSource {
				existing.Source = append(existing.Source, source)
			}
		} else {
			epMap[key] = &shared.DiscoveredEndpoint{
				URL:    url,
				Method: method,
				Source: []string{source},
			}
		}
	}
	
	// Cap targets to avoid fuzzing thousands of dead subdomains
	fuzzTargets := targets
	if len(fuzzTargets) > 10 {
		fuzzTargets = fuzzTargets[:10]
	}

	// Fuzzing for new paths (ffuf/feroxbuster) is mocked for MVP, simulating output
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, target := range fuzzTargets {
			out, _, exit, _ := tools.Execute("ffuf", []string{"-u", target + "/FUZZ", "-w", "wordlist.txt", "-s"}, 300)
			if exit == 0 {
				for _, line := range strings.Split(out, "\n") {
					addEndpoint(target+"/"+line, "GET", "ffuf")
				}
			}
		}
	}()
	
	// x8 for hidden parameter discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		fuzzEndpoints := existingEndpoints
		if len(fuzzEndpoints) > 10 {
			fuzzEndpoints = fuzzEndpoints[:10]
		}
		
		for _, ep := range fuzzEndpoints {
			// Mock x8 execution
			out, _, exit, _ := tools.Execute("x8", []string{"-u", ep.URL}, 300)
			if exit == 0 && out != "" {
				// Naive parse for discovered parameters
				// e.g. "x8 found parameter: admin=true"
				for _, line := range strings.Split(out, "\n") {
					if strings.Contains(line, "found parameter") {
						parts := strings.Split(line, ":")
						if len(parts) >= 2 {
							paramName := strings.TrimSpace(strings.Split(parts[1], "=")[0])
							
							mu.Lock()
							key := ep.Method + "|" + ep.URL
							if ptr, ok := epMap[key]; ok {
								ptr.Parameters = append(ptr.Parameters, shared.DiscoveredParameter{
									Name: paramName,
									Values: []string{},
									Source: []string{"x8"},
								})
							}
							mu.Unlock()
						}
					}
				}
			}
		}
	}()
	
	wg.Wait()
	
	var final []shared.DiscoveredEndpoint
	for _, ep := range epMap {
		final = append(final, *ep)
	}
	
	return final, nil
}
