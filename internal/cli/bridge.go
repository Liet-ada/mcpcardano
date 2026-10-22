// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package cli holds the commands of the mcpcardano CLI (section 6.1 of the
// specification): the MCP bridge, the mode A signer, and the person's
// commands on the wallet's admin socket.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
)

// SocketEnv names the environment variable that overrides the socket path.
const SocketEnv = "MCPCARDANO_SOCKET"

// DefaultSocket is where the server's MCP socket lives once installed: in the
// server's own runtime directory (section 10.2). In development the path
// comes from MCPCARDANO_SOCKET or -socket.
func DefaultSocket() string {
	if s := os.Getenv(SocketEnv); s != "" {
		return s
	}
	if runtime.GOOS == "darwin" {
		return "/private/var/run/mcpcardano-server/mcp.sock"
	}
	return "/run/mcpcardano-server/mcp.sock"
}

// Bridge joins an MCP client's standard input and output to the server's MCP
// socket (section 10.2). It has no logic: it copies bytes both ways. When the
// client closes its input, the bridge half-closes the socket and waits for
// the server to finish; when the server closes, the bridge returns. The
// bridge is a process of its own for one session, so the copy from the
// client's input may still be blocked in a read when it returns.
func Bridge(ctx context.Context, socket string, in io.Reader, out io.Writer) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("cli: cannot reach the server at %s: %w", socket, err)
	}
	defer conn.Close()
	go func() {
		io.Copy(conn, in)
		conn.(*net.UnixConn).CloseWrite()
	}()
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(out, conn)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("cli: %w", err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
