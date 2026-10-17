// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package mcpclient is the CLI's minimal MCP client (section 2.2 of the
// specification): JSON-RPC over the server's MCP socket, one message per
// line, without the MCP SDK, which the CLI never links.
package mcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// protocolVersion is the MCP version the client speaks.
const protocolVersion = "2025-06-18"

// maxMessageBytes bounds one message from the server.
const maxMessageBytes = 4 << 20

// ToolError is a tool's error result: a stable code, a message and a hint
// (section 4.1).
type ToolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

func (e *ToolError) Error() string { return e.Code + ": " + e.Message }

// Client is one MCP session. It is safe for concurrent use; calls go one at
// a time.
type Client struct {
	mu   sync.Mutex
	conn net.Conn
	in   *bufio.Scanner
	next int
}

// Dial connects to the server's socket and opens the session.
func Dial(ctx context.Context, socket, version string) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("mcpclient: cannot reach the server at %s: %w", socket, err)
	}
	c := &Client{conn: conn, in: bufio.NewScanner(conn)}
	c.in.Buffer(make([]byte, 64<<10), maxMessageBytes)
	init := map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcpcardano", "version": version},
	}
	if _, err := c.request(ctx, "initialize", init); err != nil {
		conn.Close()
		return nil, err
	}
	if err := c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Close ends the session.
func (c *Client) Close() error { return c.conn.Close() }

// Call calls a tool and decodes its structured answer into out. A tool that
// fails returns a *ToolError.
func (c *Client) Call(ctx context.Context, tool string, args, out any) error {
	raw, err := c.CallRaw(ctx, tool, args)
	if err != nil {
		return err
	}
	var res struct {
		IsError bool `json:"isError"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent json.RawMessage `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("mcpclient: %s: %w", tool, err)
	}
	if res.IsError {
		var e ToolError
		if len(res.Content) == 0 || json.Unmarshal([]byte(res.Content[0].Text), &e) != nil || e.Code == "" {
			return fmt.Errorf("mcpclient: %s failed without an error object", tool)
		}
		return &e
	}
	if out == nil {
		return nil
	}
	if len(res.StructuredContent) == 0 {
		return fmt.Errorf("mcpclient: %s gave no structured answer", tool)
	}
	return json.Unmarshal(res.StructuredContent, out)
}

// CallRaw calls a tool and returns its result as the server sent it, with
// its content, its structured content and isError.
func (c *Client) CallRaw(ctx context.Context, tool string, args any) (json.RawMessage, error) {
	return c.request(ctx, "tools/call", map[string]any{"name": tool, "arguments": args})
}

func (c *Client) send(msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(append(b, '\n'))
	return err
}

// request sends a request and waits for its answer, skipping notifications.
func (c *Client) request(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Minute)
	}
	c.conn.SetDeadline(deadline)
	defer c.conn.SetDeadline(time.Time{})
	c.next++
	id := c.next
	if err := c.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return nil, fmt.Errorf("mcpclient: %s: %w", method, err)
	}
	for c.in.Scan() {
		var msg struct {
			ID     *int            `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(c.in.Bytes(), &msg); err != nil {
			return nil, fmt.Errorf("mcpclient: %s: %w", method, err)
		}
		if msg.ID == nil || *msg.ID != id {
			continue // a notification, or an answer to nothing we wait for
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("mcpclient: %s: %d %s", method, msg.Error.Code, msg.Error.Message)
		}
		return msg.Result, nil
	}
	if err := c.in.Err(); err != nil {
		return nil, fmt.Errorf("mcpclient: %s: %w", method, err)
	}
	return nil, errors.New("mcpclient: the server closed the session")
}
