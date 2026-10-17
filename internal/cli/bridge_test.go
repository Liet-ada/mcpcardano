// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBridge copies a client's lines to a server that answers each one, and
// the answers back, until the client closes its input.
func TestBridge(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "mcpb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "mcp.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		in := bufio.NewScanner(conn)
		for in.Scan() {
			conn.Write([]byte("re: " + in.Text() + "\n"))
		}
	}()
	var out bytes.Buffer
	if err := Bridge(t.Context(), path, strings.NewReader("one\ntwo\n"), &out); err != nil {
		t.Fatal(err)
	}
	<-served
	if out.String() != "re: one\nre: two\n" {
		t.Errorf("got %q", out.String())
	}
}

func TestBridgeWithoutServer(t *testing.T) {
	err := Bridge(t.Context(), filepath.Join(t.TempDir(), "none.sock"), strings.NewReader(""), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "cannot reach the server") {
		t.Errorf("got %v", err)
	}
}
