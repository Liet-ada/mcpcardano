// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package mcp

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/drafts"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// pipeConn is one end of a session: what the client writes and what the
// server answers.
type pipeConn struct {
	io.Reader
	io.Writer
	close func() error
}

func (c pipeConn) Close() error { return c.close() }

// FuzzSession feeds arbitrary bytes to a session, as a client on the MCP
// socket could: the SDK's JSON-RPC parser and the tools behind it never
// panic, and the session ends when the client does.
func FuzzSession(f *testing.F) {
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"f","version":"0"}}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	for _, s := range []string{
		init + `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n",
		init + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_wallets","arguments":{}}}` + "\n",
		init + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_wallet_overview","arguments":{"wallet_id":"` + walletID + `"}}}` + "\n",
		init + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"decode_transaction","arguments":{"cbor_hex":"84a0a0f5f6"}}}` + "\n",
		init + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_wallets","name\u0000":"authorize_draft","arguments":{}}}` + "\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","CAPABILITIES":{}}}` + "\n",
		"\xff\xfe{[\n",
	} {
		f.Add([]byte(s))
	}
	e := fixture(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		s, err := New(Deps{
			Network: model.Preprod, Source: e.src, Drafts: drafts.New(e.clock, nil),
			Wallets: []Wallet{e.wallet}, Now: e.clock, Version: "fuzz",
		})
		if err != nil {
			t.Fatal(err)
		}
		toServer, fromClient := io.Pipe()
		toClient, fromServer := io.Pipe()
		go io.Copy(io.Discard, toClient)
		conn := pipeConn{Reader: toServer, Writer: fromServer, close: func() error {
			toServer.Close()
			return fromServer.Close()
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done := make(chan struct{})
		go func() {
			s.Serve(ctx, conn)
			close(done)
		}()
		// The server may stop reading at the first bad message, so the
		// client writes on its own and is unblocked when the session ends.
		go func() {
			fromClient.Write(input)
			fromClient.Close()
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the session did not end when the client did")
		}
		conn.Close()
		toServer.CloseWithError(io.ErrClosedPipe)
	})
}
