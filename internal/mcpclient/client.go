// Package mcpclient implements a minimal MCP client for stdio and HTTP/SSE transports.
package mcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

const initTimeout = 15 * time.Second

// ClientVersion is set by the caller (cmd/aspex-scan) at startup so the MCP
// initialize handshake reports the real binary version rather than a hardcoded string.
var ClientVersion = "dev"

// Tool represents a tool exposed by an MCP server.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

// Resource represents a resource exposed by an MCP server.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType,omitempty"`
}

// Prompt represents a prompt exposed by an MCP server.
type Prompt struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ServerInfo holds the metadata returned during MCP initialization.
type ServerInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Capabilities map[string]json.RawMessage `json:"capabilities,omitempty"`
}

// InspectResult holds everything retrieved from one MCP server.
type InspectResult struct {
	ServerInfo ServerInfo
	Tools      []Tool
	Resources  []Resource
	Prompts    []Prompt
}

// jsonrpcMsg is a minimal JSON-RPC 2.0 message.
type jsonrpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// stdioClient communicates with an MCP server over stdin/stdout of a subprocess.
type stdioClient struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
	idSeq  atomic.Int64
	mu     sync.Mutex
}

// InspectStdio launches the given command and inspects the MCP server.
func InspectStdio(ctx context.Context, command string, args []string) (*InspectResult, error) {
	ctx, cancel := context.WithTimeout(ctx, initTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start server: %w", err)
	}
	defer func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
	}()

	c := &stdioClient{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewScanner(stdoutPipe),
	}

	info, err := c.initialize()
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}

	tools, err := c.listTools()
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}

	resources, _ := c.listResources()
	prompts, _ := c.listPrompts()

	return &InspectResult{
		ServerInfo: info,
		Tools:      tools,
		Resources:  resources,
		Prompts:    prompts,
	}, nil
}

func (c *stdioClient) nextID() int64 {
	return c.idSeq.Add(1)
}

func (c *stdioClient) send(method string, params interface{}) (json.RawMessage, error) {
	id := c.nextID()
	var rawParams json.RawMessage
	if params != nil {
		var err error
		rawParams, err = json.Marshal(params)
		if err != nil {
			return nil, err
		}
	}
	msg := jsonrpcMsg{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  method,
		Params:  rawParams,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	_, err = fmt.Fprintf(c.stdin, "%s\n", data)
	c.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	// Read response lines until we get one with a matching id.
	for c.stdout.Scan() {
		line := c.stdout.Bytes()
		var resp jsonrpcMsg
		if err := json.Unmarshal(line, &resp); err != nil {
			continue
		}
		if resp.ID == nil || *resp.ID != id {
			continue
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	}
	if err := c.stdout.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("server closed without responding to %q", method)
}

func (c *stdioClient) initialize() (ServerInfo, error) {
	params := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"clientInfo": map[string]string{
			"name":    "aspex-scan",
			"version": ClientVersion,
		},
		"capabilities": map[string]interface{}{},
	}
	raw, err := c.send("initialize", params)
	if err != nil {
		return ServerInfo{}, err
	}
	var result struct {
		ServerInfo   ServerInfo             `json:"serverInfo"`
		Capabilities map[string]json.RawMessage `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return ServerInfo{}, err
	}
	result.ServerInfo.Capabilities = result.Capabilities
	// Send initialized notification (no response expected).
	notif := jsonrpcMsg{JSONRPC: "2.0", Method: "notifications/initialized"}
	data, _ := json.Marshal(notif)
	fmt.Fprintf(c.stdin, "%s\n", data)
	return result.ServerInfo, nil
}

func (c *stdioClient) listTools() ([]Tool, error) {
	raw, err := c.send("tools/list", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var result struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result.Tools, nil
}

func (c *stdioClient) listResources() ([]Resource, error) {
	raw, err := c.send("resources/list", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var result struct {
		Resources []Resource `json:"resources"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result.Resources, nil
}

func (c *stdioClient) listPrompts() ([]Prompt, error) {
	raw, err := c.send("prompts/list", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	var result struct {
		Prompts []Prompt `json:"prompts"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result.Prompts, nil
}
