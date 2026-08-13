// Package vanguard implements port and service scanning using naabu
// (ProjectDiscovery) as the primary scanner, replacing nmap/masscan.
// naabu is a pure-Go binary: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
package vanguard

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/templar-framework/templar/internal/shared"
	"github.com/templar-framework/templar/internal/shared/mcp"
	"github.com/templar-framework/templar/internal/shared/tools"
)

// ScanPorts scans the given hosts for open ports using naabu then httpx for
// service identification. Falls back gracefully if tools are not installed.
func ScanPorts(ips []string, reg *mcp.Registry) ([]shared.DiscoveredHost, error) {
	if len(ips) == 0 {
		return nil, nil
	}

	hostMap := make(map[string]*shared.DiscoveredHost)
	for _, ip := range ips {
		hostMap[ip] = &shared.DiscoveredHost{IP: ip}
	}

	// ── MCP: pd-tools-mcp naabu ──────────────────────────────────────────────
	if reg != nil {
		if client, ok := reg.Get(mcp.ServerPDTools); ok {
			for _, ip := range ips {
				raw, err := client.CallTool("naabu", map[string]interface{}{
					"host":   ip,
					"silent": true,
				})
				if err == nil {
					parseNaabuMCPResult(raw, hostMap, ip)
				}
			}
			if hasServices(flattenHostMap(hostMap)) {
				return flattenHostMap(hostMap), nil
			}
		}
	}

	// ── Local: naabu (replaces nmap + masscan) ────────────────────────────────
	for _, ip := range ips {
		out, _, exit, _ := tools.Execute("naabu", []string{
			"-host", ip,
			"-silent",
			"-top-ports", "1000",
			"-json",
		}, 300)
		if exit == 0 {
			parseNaabuJSONLines(out, hostMap, ip)
		}
	}

	// ── Local: httpx — identify HTTP services on discovered ports ────────────
	var httpTargets []string
	for _, h := range hostMap {
		for _, port := range h.OpenPorts {
			httpTargets = append(httpTargets, h.IP+":"+strconv.Itoa(port))
		}
	}
	if len(httpTargets) > 0 {
		out, _, exit, _ := tools.Execute("httpx", []string{
			"-silent", "-status-code",
			"-l", strings.Join(httpTargets, "\n"),
		}, 120)
		if exit == 0 {
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "http") {
					// Extract host from URL like http://1.2.3.4:80
					parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
					if len(parts) >= 2 {
						host := strings.TrimPrefix(parts[1], "//")
						if h, ok := hostMap[host]; ok {
							h.Services = appendUniq(h.Services, "http")
						}
					}
				}
			}
		}
	}

	// Default service label for hosts with open ports but no identified service.
	for _, h := range hostMap {
		if len(h.OpenPorts) > 0 && len(h.Services) == 0 {
			h.Services = []string{"unknown"}
		}
	}

	return flattenHostMap(hostMap), nil
}

func appendUniq(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func flattenHostMap(m map[string]*shared.DiscoveredHost) []shared.DiscoveredHost {
	hosts := make([]shared.DiscoveredHost, 0, len(m))
	for _, h := range m {
		hosts = append(hosts, *h)
	}
	return hosts
}

func hasServices(hosts []shared.DiscoveredHost) bool {
	for _, h := range hosts {
		if len(h.Services) > 0 {
			return true
		}
	}
	return false
}

// parseNaabuJSONLines parses naabu -json output (one JSON object per line).
// Example line: {"ip":"93.184.216.34","port":80}
func parseNaabuJSONLines(output string, hostMap map[string]*shared.DiscoveredHost, fallbackIP string) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Port > 0 {
			target := entry.IP
			if target == "" {
				target = fallbackIP
			}
			if h, ok := hostMap[target]; ok {
				h.OpenPorts = append(h.OpenPorts, entry.Port)
			}
		}
	}
}

// parseNaabuMCPResult parses JSON from an MCP naabu tool call.
func parseNaabuMCPResult(raw []byte, hostMap map[string]*shared.DiscoveredHost, ip string) {
	var resp struct {
		Ports  []int  `json:"ports"`
		Output string `json:"output"`
	}
	if json.Unmarshal(raw, &resp) != nil {
		return
	}
	if h, ok := hostMap[ip]; ok {
		h.OpenPorts = append(h.OpenPorts, resp.Ports...)
	}
	parseNaabuJSONLines(resp.Output, hostMap, ip)
}
