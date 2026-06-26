package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
)

// httpClient communicates with an MCP server over HTTP, supporting both SSE and plain JSON-RPC.
type httpClient struct {
	serverURL  string
	httpClient *http.Client
	idSeq      atomic.Int64
	useSSE     bool // set after probing during initialize
}

// InspectHTTP connects to an MCP server at serverURL and inspects it.
// It tries HTTP/SSE transport first, then falls back to plain HTTP JSON-RPC.
func InspectHTTP(ctx context.Context, serverURL string) (*InspectResult, error) {
	ctx, cancel := context.WithTimeout(ctx, initTimeout)
	defer cancel()

	c := &httpClient{
		serverURL: serverURL,
		httpClient: &http.Client{
			Timeout: initTimeout,
		},
	}

	info, err := c.initialize(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}

	tools, err := c.listTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}

	resources, _ := c.listResources(ctx)
	prompts, _ := c.listPrompts(ctx)

	return &InspectResult{
		ServerInfo: info,
		Tools:      tools,
		Resources:  resources,
		Prompts:    prompts,
	}, nil
}

func (c *httpClient) nextID() int64 {
	return c.idSeq.Add(1)
}

// send sends a JSON-RPC request and returns the result.
// It probes SSE on the first call; subsequent calls use the detected transport.
func (c *httpClient) send(ctx context.Context, method string, params interface{}, isFirst bool) (json.RawMessage, error) {
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
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream, application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/event-stream") {
		if isFirst {
			c.useSSE = true
		}
		return parseSSEResponse(resp.Body, id)
	}

	// Plain JSON response — cap at 10 MB to prevent memory exhaustion from a
	// malicious server returning an unbounded body.
	const maxResponseBytes = 10 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	var rpcResp jsonrpcMsg
	if err := json.Unmarshal(data, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

// parseSSEResponse reads an SSE stream and returns the first JSON-RPC result matching id.
// The reader is capped at 10 MB to prevent memory exhaustion from a malicious server.
func parseSSEResponse(r io.Reader, id int64) (json.RawMessage, error) {
	const maxSSEBytes = 10 * 1024 * 1024
	scanner := bufio.NewScanner(io.LimitReader(r, maxSSEBytes))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip comments and empty lines.
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		var data string
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
		} else if strings.HasPrefix(line, "data:") {
			data = strings.TrimPrefix(line, "data:")
		} else {
			continue
		}
		data = strings.TrimSpace(data)
		if data == "" || data == "[DONE]" {
			continue
		}
		var msg jsonrpcMsg
		if err := json.Unmarshal([]byte(data), &msg); err != nil {
			continue
		}
		if msg.ID == nil || *msg.ID != id {
			continue
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("rpc error %d: %s", msg.Error.Code, msg.Error.Message)
		}
		return msg.Result, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("sse read: %w", err)
	}
	return nil, fmt.Errorf("sse stream ended without response for id %d", id)
}

func (c *httpClient) initialize(ctx context.Context) (ServerInfo, error) {
	params := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"clientInfo": map[string]string{
			"name":    "aspex-scan",
			"version": ClientVersion,
		},
		"capabilities": map[string]interface{}{},
	}
	raw, err := c.send(ctx, "initialize", params, true)
	if err != nil {
		return ServerInfo{}, err
	}
	var result struct {
		ServerInfo   ServerInfo                `json:"serverInfo"`
		Capabilities map[string]json.RawMessage `json:"capabilities"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return ServerInfo{}, err
	}
	result.ServerInfo.Capabilities = result.Capabilities

	// Send initialized notification (best-effort, no response expected).
	notif := jsonrpcMsg{JSONRPC: "2.0", Method: "notifications/initialized"}
	notifBody, _ := json.Marshal(notif)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL, bytes.NewReader(notifBody))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}

	return result.ServerInfo, nil
}

func (c *httpClient) listTools(ctx context.Context) ([]Tool, error) {
	raw, err := c.send(ctx, "tools/list", map[string]interface{}{}, false)
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

func (c *httpClient) listResources(ctx context.Context) ([]Resource, error) {
	raw, err := c.send(ctx, "resources/list", map[string]interface{}{}, false)
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

func (c *httpClient) listPrompts(ctx context.Context) ([]Prompt, error) {
	raw, err := c.send(ctx, "prompts/list", map[string]interface{}{}, false)
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
