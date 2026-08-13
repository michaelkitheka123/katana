// Package crusademapper implements subdomain enumeration using MCP servers
// (pd-tools-mcp / subfinder) with local exec fallback.
package crusademapper

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/mcp"
	"github.com/templar-framework/templar/internal/shared/tools"
)

// MapDomains enumerates subdomains for the given domain.
// If an MCP registry is provided and contains "pd-tools-mcp", it uses the
// MCP subfinder tool. Otherwise it falls back to local exec.
func MapDomains(domain string, reg *mcp.Registry) ([]shared.DiscoveredSubdomain, error) {
	results := make(map[string]*shared.DiscoveredSubdomain)
	var mu sync.Mutex

	addResult := func(subdomain, source string) {
		subdomain = strings.ToLower(strings.TrimSpace(subdomain))
		if subdomain == "" || !strings.Contains(subdomain, ".") {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if existing, ok := results[subdomain]; ok {
			for _, s := range existing.Source {
				if s == source {
					return
				}
			}
			existing.Source = append(existing.Source, source)
		} else {
			results[subdomain] = &shared.DiscoveredSubdomain{
				Domain: subdomain,
				Source: []string{source},
			}
		}
	}

	var wg sync.WaitGroup

	// ── MCP: pd-tools-mcp subfinder ──────────────────────────────────────────
	if reg != nil {
		if client, ok := reg.Get(mcp.ServerPDTools); ok {
			wg.Add(1)
			go func() {
				defer wg.Done()
				raw, err := client.CallTool("subfinder", map[string]interface{}{
					"domain": domain,
					"silent": true,
				})
				if err != nil {
					return
				}
				// pd-tools-mcp returns {"subdomains": ["sub1.example.com", ...]}
				var resp struct {
					Subdomains []string `json:"subdomains"`
					Output     string   `json:"output"`
				}
				if json.Unmarshal(raw, &resp) == nil {
					for _, s := range resp.Subdomains {
						addResult(s, "mcp:subfinder")
					}
					// Also parse plain text output if present.
					for _, line := range strings.Split(resp.Output, "\n") {
						addResult(line, "mcp:subfinder")
					}
				}
			}()
		}
	}

	// ── Local: subfinder ─────────────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		out, _, exit, _ := tools.Execute("subfinder", []string{"-d", domain, "-silent"}, 300)
		if exit == 0 {
			for _, line := range strings.Split(out, "\n") {
				addResult(line, "subfinder")
			}
		}
	}()

	// ── Local: amass ─────────────────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		out, _, exit, _ := tools.Execute("amass", []string{"enum", "-passive", "-d", domain, "-silent"}, 600)
		if exit == 0 {
			for _, line := range strings.Split(out, "\n") {
				addResult(line, "amass")
			}
		}
	}()

	// ── crt.sh (always HTTP — uses its own client bypassing scope enforcer) ─────
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Use a plain http.Client (not the scope-enforced one) — crt.sh is
		// a tool infrastructure call, not a scan target.
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
		if err != nil || resp.StatusCode != 200 {
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var certs []struct {
			NameValue string `json:"name_value"`
		}
		if json.Unmarshal(body, &certs) == nil {
			for _, cert := range certs {
				for _, name := range strings.Split(cert.NameValue, "\n") {
					addResult(name, "crt.sh")
				}
			}
		}
	}()

	wg.Wait()

	var final []shared.DiscoveredSubdomain
	for _, sub := range results {
		sub.IP = "pending-dns-resolution"
		final = append(final, *sub)
	}
	return final, nil
}
