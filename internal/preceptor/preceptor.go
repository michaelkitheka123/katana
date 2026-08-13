package preceptor

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/templar-framework/templar/internal/preceptor/cartographer"
	"github.com/templar-framework/templar/internal/preceptor/crusademapper"
	"github.com/templar-framework/templar/internal/preceptor/pilgrimcrawler"
	"github.com/templar-framework/templar/internal/preceptor/vanguard"
	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/mcp"
)

type Preceptor struct {
	Scope shared.ScopeConfig
	MCP   *mcp.Registry
}

func NewPreceptor(scope shared.ScopeConfig) *Preceptor {
	return &Preceptor{Scope: scope}
}

// NewPreceptorWithMCP creates a Preceptor with an MCP registry for tool calls.
func NewPreceptorWithMCP(scope shared.ScopeConfig, reg *mcp.Registry) *Preceptor {
	return &Preceptor{Scope: scope, MCP: reg}
}

func (p *Preceptor) Run(config shared.CrusadeConfig) (shared.AttackSurface, error) {
	var surface shared.AttackSurface
	var partialFlags []string

	// NOTE: Do NOT set http.DefaultTransport — that would block LLM and other
	// infrastructure calls. The ScopeEnforcingTransport is only used for
	// explicit scan HTTP clients (e.g. crt.sh fetcher), not globally.

	var wg sync.WaitGroup
	var mu sync.Mutex

	targetDomain := config.TargetURL
	if strings.HasPrefix(targetDomain, "http") {
		targetDomain = strings.Split(strings.Split(targetDomain, "://")[1], "/")[0]
	}

	// 1. Crusade Mapper
	wg.Add(1)
	go func() {
		defer wg.Done()
		subs, err := crusademapper.MapDomains(targetDomain, p.MCP)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			partialFlags = append(partialFlags, "crusade_mapper")
			shared.LogAudit(shared.AuditEvent{Timestamp: time.Now().UTC().Format(time.RFC3339), EventType: "TOOL_FAILURE", Message: "Crusade Mapper failed"})
		} else {
			surface.Subdomains = subs
			// Emit discovery events
			if shared.GlobalBus != nil {
				shared.GlobalBus.Emit(shared.EventSubdomain, "preceptor",
					fmt.Sprintf("Found %d subdomains for %s", len(subs), targetDomain), "")
				
				maxEmit := 15
				if len(subs) < maxEmit {
					maxEmit = len(subs)
				}
				for i := 0; i < maxEmit; i++ {
					s := subs[i]
					shared.GlobalBus.Emit(shared.EventSubdomain, "preceptor",
						fmt.Sprintf("%s  →  %s", s.Domain, s.IP), "via "+strings.Join(s.Source, ","))
				}
				if len(subs) > maxEmit {
					shared.GlobalBus.Emit(shared.EventSubdomain, "preceptor",
						fmt.Sprintf("... and %d more subdomains hidden", len(subs)-maxEmit), "")
				}
			}
		}
	}()

	// 2. Vanguard
	var ips []string
	ips = append(ips, targetDomain) // Initial seed
	wg.Add(1)
	go func() {
		defer wg.Done()
		hosts, err := vanguard.ScanPorts(ips, p.MCP)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			partialFlags = append(partialFlags, "vanguard")
			shared.LogAudit(shared.AuditEvent{Timestamp: time.Now().UTC().Format(time.RFC3339), EventType: "TOOL_FAILURE", Message: "Vanguard failed"})
		} else {
			surface.Hosts = hosts
			// Emit port discovery events
			if shared.GlobalBus != nil {
				for _, h := range hosts {
					if len(h.OpenPorts) > 0 {
						var portStrs []string
						for _, p := range h.OpenPorts {
							portStrs = append(portStrs, fmt.Sprintf("%d", p))
						}
						shared.GlobalBus.Emit(shared.EventPort, "preceptor",
							fmt.Sprintf("naabu: %s  open ports: %s", h.IP, strings.Join(portStrs, ", ")),
							"services: "+strings.Join(h.Services, ", "))
					}
				}
			}
		}
	}()

	wg.Wait()

	// 3. Cartographer (Needs Hosts from Vanguard)
	var techStack []shared.TechStackEntry
	if len(surface.Hosts) > 0 {
		stack, err := cartographer.Fingerprint(surface.Hosts)
		if err != nil {
			partialFlags = append(partialFlags, "cartographer")
			shared.LogAudit(shared.AuditEvent{Timestamp: time.Now().UTC().Format(time.RFC3339), EventType: "TOOL_FAILURE", Message: "Cartographer failed"})
		} else {
			techStack = stack
		}
	}
	
	// Add tech stack globally for now (MVP simplifaction, ideally per host)
	fmt.Printf("Discovered %d TechStack entries\n", len(techStack))

	// 4. Pilgrim Crawler (Start after others complete)
	var targets []string
	targets = append(targets, config.TargetURL)
	for _, sub := range surface.Subdomains {
		targets = append(targets, "https://"+sub.Domain)
	}

	endpoints, err := pilgrimcrawler.Crawl(targets, p.MCP)
	if err != nil {
		partialFlags = append(partialFlags, "pilgrimcrawler_crawl")
	}

	// 5. Pilgrim Fuzzer
	finalEndpoints, err := pilgrimcrawler.Fuzz(targets, endpoints)
	if err != nil {
		partialFlags = append(partialFlags, "pilgrimcrawler_fuzz")
	}

	// Deduplicate endpoints by (url, method)
	surface.Endpoints = deduplicateEndpoints(finalEndpoints)

	if len(partialFlags) > 0 {
		shared.LogAudit(shared.AuditEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			EventType: "RECON_PARTIAL",
			Message:   strings.Join(partialFlags, ","),
		})
	}

	return surface, nil
}

// deduplicateEndpoints enforces Property 8 idempotency for endpoints
func deduplicateEndpoints(endpoints []shared.DiscoveredEndpoint) []shared.DiscoveredEndpoint {
	epMap := make(map[string]*shared.DiscoveredEndpoint)
	for _, ep := range endpoints {
		key := ep.Method + "|" + ep.URL
		if existing, ok := epMap[key]; ok {
			// merge sources
			sourceMap := make(map[string]bool)
			for _, s := range existing.Source {
				sourceMap[s] = true
			}
			for _, s := range ep.Source {
				if !sourceMap[s] {
					existing.Source = append(existing.Source, s)
					sourceMap[s] = true
				}
			}
			
			// merge parameters
			paramMap := make(map[string]*shared.DiscoveredParameter)
			for i, p := range existing.Parameters {
				paramMap[p.Name] = &existing.Parameters[i]
			}
			for _, p := range ep.Parameters {
				if pExisting, pOk := paramMap[p.Name]; pOk {
					// merge param sources
					pSourceMap := make(map[string]bool)
					for _, ps := range pExisting.Source {
						pSourceMap[ps] = true
					}
					for _, ps := range p.Source {
						if !pSourceMap[ps] {
							pExisting.Source = append(pExisting.Source, ps)
							pSourceMap[ps] = true
						}
					}
				} else {
					existing.Parameters = append(existing.Parameters, p)
					paramMap[p.Name] = &existing.Parameters[len(existing.Parameters)-1]
				}
			}
		} else {
			copyEp := ep
			epMap[key] = &copyEp
		}
	}

	var final []shared.DiscoveredEndpoint
	for _, ep := range epMap {
		final = append(final, *ep)
	}
	return final
}

// DeduplicateEndpoints exposes the internal logic for testing idempotency
func DeduplicateEndpoints(endpoints []shared.DiscoveredEndpoint) []shared.DiscoveredEndpoint {
	return deduplicateEndpoints(endpoints)
}
