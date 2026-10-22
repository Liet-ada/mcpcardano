// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"context"
	"errors"
	"sync"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
)

// Conn is the wallet's admin socket as the view uses it: one connection,
// made at the first call and made again after a call breaks it, as when the
// wallet restarts.
type Conn struct {
	Socket string
	Hello  ipc.Hello

	mu     sync.Mutex
	client *ipc.Client
}

func (c *Conn) call(ctx context.Context, t string, req, resp ipc.Body) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		cl, err := ipc.Dial(ctx, c.Socket, c.Hello)
		if err != nil {
			return err
		}
		c.client = cl
	}
	err := c.client.Call(ctx, t, req, resp)
	var e *ipc.Error
	if err != nil && !errors.As(err, &e) {
		c.client.Close()
		c.client = nil
	}
	return err
}

// Close closes the connection.
func (c *Conn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
}

func (c *Conn) Status(ctx context.Context) (*ipc.StatusReport, error) {
	var st ipc.StatusReport
	if err := c.call(ctx, ipc.MsgStatus, &ipc.Empty{}, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (c *Conn) Begin(ctx context.Context, action string, params ipc.Body) (*ipc.Challenge, error) {
	raw, err := ipc.NewCodec().Encode(params)
	if err != nil {
		return nil, err
	}
	var ch ipc.Challenge
	if err := c.call(ctx, ipc.MsgBeginAuthorization, &ipc.BeginAuthorization{Action: action, Params: raw}, &ch); err != nil {
		return nil, err
	}
	return &ch, nil
}

func (c *Conn) Complete(ctx context.Context, a *ipc.CompleteAuthorization) error {
	return c.call(ctx, ipc.MsgCompleteAuthorization, a, &ipc.Completed{})
}

func (c *Conn) Reject(ctx context.Context, id string) error {
	return c.call(ctx, ipc.MsgReject, &ipc.ApprovalRef{ApprovalID: id}, &ipc.Empty{})
}

func (c *Conn) FreezeAll(ctx context.Context) error {
	return c.call(ctx, ipc.MsgFreeze, &ipc.Freeze{}, &ipc.Empty{})
}
