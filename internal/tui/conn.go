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
	defer clear(raw) // restore_wallet carries the recovery phrase
	var ch ipc.Challenge
	if err := c.call(ctx, ipc.MsgBeginAuthorization, &ipc.BeginAuthorization{Action: action, Params: raw}, &ch); err != nil {
		return nil, err
	}
	return &ch, nil
}

func (c *Conn) Complete(ctx context.Context, a *ipc.CompleteAuthorization) ([]byte, error) {
	var done ipc.Completed
	err := c.call(ctx, ipc.MsgCompleteAuthorization, a, &done)
	return done.Result, err
}

func (c *Conn) Reject(ctx context.Context, id string) error {
	return c.call(ctx, ipc.MsgReject, &ipc.ApprovalRef{ApprovalID: id}, &ipc.Empty{})
}

func (c *Conn) Freeze(ctx context.Context, walletID string) error {
	return c.call(ctx, ipc.MsgFreeze, &ipc.Freeze{WalletID: walletID}, &ipc.Empty{})
}

func (c *Conn) CloseSession(ctx context.Context, walletID string) error {
	return c.call(ctx, ipc.MsgCloseSession, &ipc.WalletRef{WalletID: walletID}, &ipc.Empty{})
}

func (c *Conn) Expired(ctx context.Context, walletID string) ([]ipc.Expired, error) {
	var l ipc.ExpiredList
	err := c.call(ctx, ipc.MsgListExpired, &ipc.ListExpired{WalletID: walletID}, &l)
	return l.Entries, err
}

func (c *Conn) ShowPolicy(ctx context.Context, walletID string) (*ipc.WalletPolicy, error) {
	var w ipc.WalletPolicy
	if err := c.call(ctx, ipc.MsgShowPolicy, &ipc.WalletRef{WalletID: walletID}, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

func (c *Conn) ShowTemplate(ctx context.Context) (*ipc.Template, error) {
	var t ipc.Template
	if err := c.call(ctx, ipc.MsgShowTemplate, &ipc.Empty{}, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (c *Conn) PolicyStatus(ctx context.Context, walletID string) (*ipc.PolicyStatus, error) {
	var ps ipc.PolicyStatus
	if err := c.call(ctx, ipc.MsgGetPolicyStatus, &ipc.GetPolicyStatus{WalletID: walletID}, &ps); err != nil {
		return nil, err
	}
	return &ps, nil
}
