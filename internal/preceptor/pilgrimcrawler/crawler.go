// Package pilgrimcrawler implements endpoint discovery using MCP servers
// (fetch-mcp, pd-tools-mcp/katana) with local exec fallback.
package pilgrimcrawler

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/mcp"
	"github.com/templar-framework/templar/internal/shared/tools"
)

// maxCrawlTargets limits how many targets we deep-crawl to avoid running
// hundreds of goroutines against dead subdomains.
const maxCrawlTargets = 10

// crawlTimeoutSecs is the per-tool timeout for a single target crawl.
const crawlTimeoutSecs = 60

// maxConcurrentCrawls limits simultaneous crawler goroutines.
const maxConcurrentCrawls = 5

// Crawl discovers endpoints across targets. It deep-crawls only the first
// maxCrawlTargets to prevent hanging on hundreds of dead subdomains.
func Crawl(targets []string, reg *mcp.Registry) ([]shared.DiscoveredEndpoint, error) {
	results := make(map[string]*shared.DiscoveredEndpoint)
	var mu sync.Mutex

	addEndpoint := func(rawURL, method, source string) {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" || !strings.HasPrefix(rawURL, "http") {
			return
		}
		key := method + "|" + rawURL
		mu.Lock()
		defer mu.Unlock()
		if existing, ok := results[key]; ok {
			for _, s := range existing.Source {
				if s == source {
					return
				}
			}
			existing.Source = append(existing.Source, source)
		} else {
			results[key] = &shared.DiscoveredEndpoint{
				URL:    rawURL,
				Method: method,
				Source: []string{source},
			}
		}
	}

	// Cap targets to avoid crawling hundreds of dead subdomains.
	crawlTargets := targets
	if len(crawlTargets) > maxCrawlTargets {
		crawlTargets = crawlTargets[:maxCrawlTargets]
	}

	sem := make(chan struct{}, maxConcurrentCrawls)
	var wg sync.WaitGroup

	for _, target := range crawlTargets {
		t := target

		// ── MCP: fetch-mcp ───────────────────────────────────────────────────
		if reg != nil {
			if client, ok := reg.Get(mcp.ServerFetch); ok {
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					raw, err := client.CallTool("fetch", map[string]interface{}{
						"url":           t,
						"max_length":    50000,
						"extract_links": true,
					})
					if err == nil {
						parseFetchMCPLinks(raw, t, addEndpoint)
					}
				}()
			}
		}

		// ── Local: gospider ──────────────────────────────────────────────────
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out, _, exit, _ := tools.Execute("gospider",
				[]string{"-s", t, "-q", "--depth", "2"}, crawlTimeoutSecs)
			if exit == 0 {
				for _, line := range strings.Split(out, "\n") {
					if strings.Contains(line, "[url]") {
						parts := strings.SplitN(line, "- ", 2)
						if len(parts) == 2 {
							addEndpoint(strings.TrimSpace(parts[1]), "GET", "gospider")
						}
					}
				}
			}
		}()

		// ── Local: gau (historical URLs, root domain only) ───────────────────
		// Only run gau against the primary target, not every subdomain.
		if t == crawlTargets[0] {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				out, _, exit, _ := tools.Execute("gau", []string{t}, crawlTimeoutSecs)
				if exit == 0 {
					for _, line := range strings.Split(out, "\n") {
						addEndpoint(line, "GET", "gau")
					}
				}
			}()
		}
	}

	wg.Wait()

	final := make([]shared.DiscoveredEndpoint, 0, len(results))
	for _, ep := range results {
		final = append(final, *ep)
	}
	return final, nil
}

// parseFetchMCPLinks parses links from the fetch MCP tool response.
func parseFetchMCPLinks(raw []byte, baseURL string, add func(string, string, string)) {
	var resp struct {
		Links   []string `json:"links"`
		Content string   `json:"content"`
	}
	if json.Unmarshal(raw, &resp) != nil {
		return
	}
	for _, link := range resp.Links {
		add(link, "GET", "mcp:fetch")
	}
}

// parseKatanaMCPResult parses URLs from the pd-tools-mcp katana tool response.
func parseKatanaMCPResult(raw []byte, add func(string, string, string)) {
	var resp struct {
		URLs   []string `json:"urls"`
		Output string   `json:"output"`
	}
	if json.Unmarshal(raw, &resp) != nil {
		return
	}
	for _, u := range resp.URLs {
		add(u, "GET", "mcp:katana")
	}
	for _, line := range strings.Split(resp.Output, "\n") {
		add(strings.TrimSpace(line), "GET", "mcp:katana")
	}
}
