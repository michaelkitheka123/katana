package mcp

import (
	"fmt"
	"log"
	"sync"

	"github.com/templar-framework/templar/internal/shared"
)

// Registry holds all active MCP client connections, keyed by server name.
// It is initialised once at campaign start and shared across all Knights.
type Registry struct {
	mu      sync.RWMutex
	clients map[string]*MCPClient
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{clients: make(map[string]*MCPClient)}
}

// InitFromConfig starts MCP server processes for every MCPServerConfig in the
// CrusadeConfig. Servers that fail to start are logged and skipped — Knights
// will fall back to local exec for those tools.
func InitFromConfig(cfgs []shared.MCPServerConfig) *Registry {
	r := NewRegistry()
	for _, cfg := range cfgs {
		client, err := NewMCPClient(ServerConfig{
			Name:    cfg.Name,
			Command: cfg.Command,
			Args:    cfg.Args,
			Env:     cfg.Env,
		})
		if err != nil {
			log.Printf("mcp registry: failed to start %q (%s %v): %v — falling back to local exec",
				cfg.Name, cfg.Command, cfg.Args, err)
			continue
		}
		r.mu.Lock()
		r.clients[cfg.Name] = client
		r.mu.Unlock()
		log.Printf("mcp registry: connected to %q", cfg.Name)
	}
	return r
}

// Get returns the MCPClient for the named server, or (nil, false) if not registered.
func (r *Registry) Get(name string) (*MCPClient, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[name]
	return c, ok
}

// CallTool is a convenience helper that looks up a server by name and calls a tool.
// Returns an error if the server is not registered or the tool call fails.
func (r *Registry) CallTool(serverName, toolName string, args map[string]interface{}) ([]byte, error) {
	client, ok := r.Get(serverName)
	if !ok {
		return nil, fmt.Errorf("mcp registry: server %q not registered", serverName)
	}
	raw, err := client.CallTool(toolName, args)
	if err != nil {
		return nil, fmt.Errorf("mcp[%s].%s: %w", serverName, toolName, err)
	}
	return raw, nil
}

// Close shuts down all registered MCP server processes.
func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, client := range r.clients {
		if err := client.Close(); err != nil {
			log.Printf("mcp registry: error closing %q: %v", name, err)
		}
	}
}

// ── Well-known server name constants ─────────────────────────────────────────
// These match the Name field in MCPServerConfig and are used by Knight
// sub-agents to look up the correct client.

const (
	// ServerPDTools is the intelligent-ears/pd-tools-mcp server wrapping
	// ProjectDiscovery tools: subfinder, dnsx, naabu, httpx, katana, nuclei.
	ServerPDTools = "pd-tools-mcp"

	// ServerNuclei is the addcontent/nuclei-mcp server for Nuclei scanning.
	ServerNuclei = "nuclei-mcp"

	// ServerSecurity is the cyproxio/mcp-for-security server wrapping
	// nmap, masscan, sqlmap, ffuf.
	ServerSecurity = "mcp-for-security"

	// ServerFetch is the official @modelcontextprotocol/server-fetch for HTTP
	// fetching and basic web crawling.
	ServerFetch = "fetch-mcp"

	// ServerShodan is an MCP wrapper for Shodan (requires SHODAN_API_KEY env).
	ServerShodan = "shodan-mcp"
)
