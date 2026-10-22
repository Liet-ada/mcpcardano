// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package server starts mcpcardano-server: it reads the configuration, opens
// the audit log, connects to the data source and serves MCP on a Unix socket
// (section 10.2 of the specification). An MCP client reaches the socket
// through the bridge, `mcpcardano mcp`, which it starts as a stdio server.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/datasource"
	"github.com/Liet-ada/mcpcardano/internal/drafts"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/mcp"
)

// MaxConnections bounds the MCP sessions at once: the agent, the mode A
// signer and a few to spare.
const MaxConnections = 8

// Options are what the caller may set besides the configuration.
type Options struct {
	Logger  *slog.Logger
	Now     func() time.Time
	Version string
	// Source replaces the data source of the configuration, for tests.
	Source datasource.Source
	// WatchEvery replaces how often the chain is asked about sent
	// transactions, for tests.
	WatchEvery time.Duration
}

// Run serves until ctx ends, then closes every session and returns.
func Run(ctx context.Context, s Settings, o Options) error {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	log := o.Logger
	if err := privateDir(s.DataDir); err != nil {
		return err
	}
	unlock, err := lockDir(s.DataDir)
	if err != nil {
		return err
	}
	defer unlock()
	chain.Configure()

	auditLog, recovery, err := audit.Open(ctx, filepath.Join(s.DataDir, "audit.log"), audit.Options{Kind: "audit", Now: o.Now})
	if err != nil {
		return fmt.Errorf("server: audit log: %w", err)
	}
	defer auditLog.Close()
	rec := recorder{auditLog}
	if recovery.Discarded > 0 {
		log.Warn("audit log: cut off an incomplete last entry", "bytes", recovery.Discarded)
		rec.Append(ctx, "recovered", map[string]any{"discarded_bytes": recovery.Discarded})
	}

	src := o.Source
	if src == nil {
		k, err := datasource.NewKoios(datasource.KoiosConfig{Network: s.Network, BaseURL: s.KoiosURL})
		if err != nil {
			return fmt.Errorf("server: data source: %w", err)
		}
		src = k
	}
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = src.CheckNetwork(checkCtx)
	cancel()
	switch {
	case errors.Is(err, datasource.ErrNetworkMismatch):
		return fmt.Errorf("server: %w", err)
	case err != nil:
		// Not fatal: each call reports DATASOURCE_UNAVAILABLE until it answers.
		log.Warn("the data source does not answer yet", "source", src.Name(), "err", err)
	}

	var wallet *mcp.WalletConn
	if s.WalletSocket != "" {
		wallet = &mcp.WalletConn{Path: s.WalletSocket,
			Hello: ipc.Hello{Software: "mcpcardano-server " + o.Version, Network: string(s.Network)}}
		defer wallet.Close()
	}
	store := drafts.New(o.Now, nil)
	srv, err := mcp.New(mcp.Deps{
		Network: s.Network, Source: src, Drafts: store, Wallets: s.Wallets, Wallet: wallet,
		Audit: rec, Logger: log, Now: o.Now, Version: o.Version,
	})
	if err != nil {
		return err
	}
	// The wallets of the wallet process, and the transactions it signed that
	// may still reach the chain (section 9.5). If it does not answer yet,
	// the watcher tries again.
	srv.Sync(ctx)
	ln, err := listen(s.Socket)
	if err != nil {
		return err
	}
	defer os.Remove(s.Socket)
	if err := rec.Append(ctx, "server_start", map[string]any{"version": o.Version, "network": string(s.Network), "wallets": len(s.Wallets)}); err != nil {
		ln.Close()
		return fmt.Errorf("server: audit log: %w", err)
	}
	log.Info("serving MCP", "socket", s.Socket, "network", s.Network, "wallets", len(s.Wallets))
	w := &watcher{store: store, src: src, rec: rec, now: o.Now, depth: s.ConfirmationDepth, log: log, srv: srv}
	every := o.WatchEvery
	if every == 0 {
		every = watchEvery
	}
	watchCtx, stopWatch := context.WithCancel(ctx)
	var watching sync.WaitGroup
	watching.Go(func() { w.run(watchCtx, every) })
	serve(ctx, ln, srv, log)
	stopWatch()
	watching.Wait()
	rec.Append(context.WithoutCancel(ctx), "server_stop", map[string]any{})
	return nil
}

// serve accepts sessions until ctx ends or the socket closes, then closes
// them and waits.
func serve(ctx context.Context, ln net.Listener, srv *mcp.Server, log *slog.Logger) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		conns = map[net.Conn]struct{}{}
	)
	wg.Go(func() {
		<-ctx.Done()
		ln.Close()
	})
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				log.Error("accept", "err", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			break
		}
		mu.Lock()
		if len(conns) >= MaxConnections {
			mu.Unlock()
			log.Warn("too many MCP sessions; refusing one")
			conn.Close()
			continue
		}
		conns[conn] = struct{}{}
		mu.Unlock()
		wg.Go(func() {
			defer func() {
				mu.Lock()
				delete(conns, conn)
				mu.Unlock()
				conn.Close()
			}()
			if err := srv.Serve(ctx, conn); err != nil && ctx.Err() == nil {
				log.Info("MCP session ended", "err", err)
			}
		})
	}
	cancel()
	mu.Lock()
	for c := range conns {
		c.Close()
	}
	mu.Unlock()
	wg.Wait()
}

// listen opens the MCP socket. A socket file left by a server that crashed
// is removed; one that still answers belongs to a running server.
func listen(path string) (net.Listener, error) {
	if _, err := os.Lstat(path); err == nil {
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("server: another server is listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("server: removing the old socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	// In H-1 the agent's bridge runs as the same user; H-2 opens the socket
	// to the person's group (section 10.1).
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("server: %w", err)
	}
	return ln, nil
}

// privateDir creates the data directory, or checks that nobody else can
// read it (section 7.1).
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("server: data directory: %w", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("server: data directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("server: %s must be a directory with mode 0700, not %v", dir, info.Mode().Perm())
	}
	return nil
}

// lockDir makes sure no other server uses the data directory, before
// anything in it is opened: the audit log mends an incomplete last entry on
// opening, which must never happen under a running server. The kernel drops
// the lock if the process dies.
func lockDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "server.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("server: lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("server: another server uses %s: %w", dir, err)
	}
	return func() { f.Close() }, nil
}

// recorder adapts the audit log to the tools.
type recorder struct{ log *audit.Log }

func (r recorder) Append(ctx context.Context, typ string, body any) error {
	_, err := r.log.Append(ctx, typ, body)
	return err
}
