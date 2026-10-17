// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package e8

import (
	"context"
	"path/filepath"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/mcpclient"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/server"
)

// Server is the real server on the hostile chain.
type Server struct {
	Chain   *Chain
	DataDir string
	Socket  string
	stop    context.CancelFunc
	done    chan error
}

// Start runs the server on a new chain, realistic or not (see NewChain), in
// dir, which must be short enough for a socket path, until Stop.
func Start(ctx context.Context, dir string, realistic bool) (*Server, error) {
	c, err := NewChain(time.Now().UTC(), realistic)
	if err != nil {
		return nil, err
	}
	wallets, err := Wallets()
	if err != nil {
		c.Close()
		return nil, err
	}
	s := &Server{Chain: c, DataDir: filepath.Join(dir, "data"), Socket: filepath.Join(dir, "mcp.sock"), done: make(chan error, 1)}
	settings := server.Settings{Network: model.Preprod, DataDir: s.DataDir, Socket: s.Socket, ConfirmationDepth: 3, Wallets: wallets}
	ctx, s.stop = context.WithCancel(ctx)
	go func() { s.done <- server.Run(ctx, settings, server.Options{Source: c, Version: "e8"}) }()
	// Wait for the socket.
	for range 200 {
		cl, err := mcpclient.Dial(ctx, s.Socket, "e8")
		if err == nil {
			cl.Close()
			return s, nil
		}
		select {
		case err := <-s.done:
			c.Close()
			return nil, err
		case <-time.After(10 * time.Millisecond):
		}
	}
	s.Stop()
	return nil, context.DeadlineExceeded
}

// Stop ends the server and returns its error.
func (s *Server) Stop() error {
	s.stop()
	err := <-s.done
	s.Chain.Close()
	return err
}
