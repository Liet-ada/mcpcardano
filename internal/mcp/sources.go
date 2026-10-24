// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package mcp

import (
	"context"
	"slices"
	"strings"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Liet-ada/mcpcardano/internal/datasource"
)

// The person configures which data sources the server reads the chain from,
// and in what order. The agent may choose, for its own session, which of
// them and in what order (decision 137); never another source. The choice
// lives in memory and ends with the session. The watcher and what the
// server does on its own follow the configured order.

// sessionKey carries the MCP session of a tool call in its context.
type sessionKey struct{}

// orders are the orders of data sources the sessions chose.
type orders struct {
	mu sync.Mutex
	by map[*sdk.ServerSession][]string
}

func (o *orders) get(ss *sdk.ServerSession) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.by[ss]
}

func (o *orders) set(ss *sdk.ServerSession, order []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.by == nil {
		o.by = map[*sdk.ServerSession][]string{}
	}
	if len(order) == 0 {
		delete(o.by, ss)
		return
	}
	o.by[ss] = slices.Clone(order)
}

// relay is the configured relay of data sources.
func (s *Server) relay() *datasource.Relay {
	r, _ := s.d.Source.(*datasource.Relay)
	return r
}

func session(ctx context.Context) *sdk.ServerSession {
	ss, _ := ctx.Value(sessionKey{}).(*sdk.ServerSession)
	return ss
}

// src is the data source of the session that ctx belongs to: the relay in
// the order the session chose, or in the configured one.
func (s *Server) src(ctx context.Context) datasource.Source {
	if order := s.orders.get(session(ctx)); order != nil {
		if v, err := s.relay().Prefer(order); err == nil {
			return v
		}
	}
	return s.d.Source
}

// order is the order of data sources of the session that ctx belongs to.
func (s *Server) order(ctx context.Context) []string {
	if order := s.orders.get(session(ctx)); order != nil {
		return order
	}
	return s.relay().Names()
}

type sourcesArg struct {
	Order []string `json:"order" jsonschema:"Names of data sources from datasources of get_network_status, each once, in the order to ask them: the first answers while it can, the next take over when it does not. Empty goes back to the person's order."`
}

func (s *Server) setDataSources(ctx context.Context, a sourcesArg) (networkStatus, error) {
	ss := session(ctx)
	if ss == nil {
		return networkStatus{}, invalid("there is no session to choose the data sources of")
	}
	if _, err := s.relay().Prefer(a.Order); err != nil {
		return networkStatus{}, invalid("%s", strings.TrimPrefix(err.Error(), "datasource: "))
	}
	s.orders.set(ss, a.Order)
	s.note(ctx, "datasources", map[string]any{"order": s.order(ctx)})
	return s.networkStatus(ctx, noArgs{})
}

// forget drops what a session chose, when it ends.
func (s *Server) forget(ss *sdk.ServerSession) { s.orders.set(ss, nil) }
