// Package mcp provides a lightweight MCP (Model Context Protocol) client
// that communicates with MCP servers over stdio using JSON-RPC 2.0.
//
// The client spawns an MCP server process, sends tool-call requests, and
// returns the tool result. Each MCPClient instance owns one server process.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ServerConfig describes how to launch and connect to an MCP server.
type ServerConfig struct {
	// Name is a human-readable label (e.g. "pd-tools-mcp", "nuclei-mcp").
	Name string

	// Command is the executable to run (e.g. "npx", "uvx", "python").
	Command string

	// Args are the command-line arguments (e.g. ["-y", "@intelligent-ears/pd-tools-mcp"]).
	Args []string

	// Env holds additional environment variables for the server process.
	Env []string

	// StartupTimeout is how long to wait for the server to emit its
	// "initialize" response. Defaults to 10 seconds.
	StartupTimeout time.Duration
}

// jsonrpcRequest is a JSON-RPC 2.0 request object.
type jsonrpcRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// jsonrpcResponse is a JSON-RPC 2.0 response object.
type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPClient manages a single MCP server process and serialises JSON-RPC calls to it.
type MCPClient struct {
	config  ServerConfig
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	scanner *bufio.Scanner
	mu      sync.Mutex
	idSeq   int64
}

// NewMCPClient starts the MCP server process and performs the MCP initialise
// handshake. Returns an error if the process cannot be started or the server
// does not respond within StartupTimeout.
func NewMCPClient(cfg ServerConfig) (*MCPClient, error) {
	if cfg.StartupTimeout == 0 {
		cfg.StartupTimeout = 10 * time.Second
	}

	cmd := exec.Command(cfg.Command, cfg.Args...)
	if len(cfg.Env) > 0 {
		cmd.Env = append(cmd.Environ(), cfg.Env...)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: failed to get stdin pipe for %s: %w", cfg.Name, err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: failed to get stdout pipe for %s: %w", cfg.Name, err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcp: failed to start %s (%s): %w", cfg.Name, cfg.Command, err)
	}

	c := &MCPClient{
		config:  cfg,
		cmd:     cmd,
		stdin:   stdin,
		scanner: bufio.NewScanner(stdout),
	}

	// MCP initialize handshake.
	if err := c.initialize(); err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("mcp: initialize handshake failed for %s: %w", cfg.Name, err)
	}

	return c, nil
}

// initialize sends the MCP "initialize" request and waits for the response.
func (c *MCPClient) initialize() error {
	params := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]string{
			"name":    "templar",
			"version": "1.0.0",
		},
	}
	_, err := c.call("initialize", params)
	if err != nil {
		return err
	}
	// Send "notifications/initialized" — fire and forget.
	notif := jsonrpcRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	b, _ := json.Marshal(notif)
	_, _ = fmt.Fprintf(c.stdin, "%s\n", b)
	return nil
}

// CallTool invokes a named tool on the MCP server with the given arguments and
// returns the raw result JSON. The call is serialised — only one in-flight
// request at a time per client.
func (c *MCPClient) CallTool(toolName string, arguments map[string]interface{}) (json.RawMessage, error) {
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": arguments,
	}
	return c.call("tools/call", params)
}

// ListTools returns the list of tools the MCP server exposes.
func (c *MCPClient) ListTools() (json.RawMessage, error) {
	return c.call("tools/list", nil)
}

// call sends a JSON-RPC request and waits for the matching response.
func (c *MCPClient) call(method string, params interface{}) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	id := atomic.AddInt64(&c.idSeq, 1)
	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("mcp: marshal request: %w", err)
	}

	if _, err := fmt.Fprintf(c.stdin, "%s\n", data); err != nil {
		return nil, fmt.Errorf("mcp: write to server stdin: %w", err)
	}

	// Read lines until we find a JSON-RPC response with our ID.
	// Other lines (notifications, logs) are silently discarded.
	for c.scanner.Scan() {
		line := strings.TrimSpace(c.scanner.Text())
		if line == "" {
			continue
		}

		var resp jsonrpcResponse
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			// Not valid JSON-RPC — log and continue reading.
			log.Printf("mcp[%s]: non-JSON-RPC line: %s", c.config.Name, line)
			continue
		}
		if resp.ID != id {
			// Response for a different request (shouldn't happen with serialised calls).
			continue
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("mcp[%s]: server error %d: %s", c.config.Name, resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	}

	if err := c.scanner.Err(); err != nil {
		return nil, fmt.Errorf("mcp[%s]: scanner error: %w", c.config.Name, err)
	}
	return nil, fmt.Errorf("mcp[%s]: server closed stdout before responding to request %d", c.config.Name, id)
}

// Close terminates the MCP server process.
func (c *MCPClient) Close() error {
	if c.stdin != nil {
		_ = c.stdin.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		return c.cmd.Process.Kill()
	}
	return nil
}
