// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/mcpclient"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/test/softkey"
)

// fakeServer answers as the server would, and counts what costs quota.
type fakeServer struct {
	mu        sync.Mutex
	overviews map[string]*Overview
	drafts    []Draft
	wallets   []ServerWallet
	chain     *ChainStatus
	down      error // what every call answers
	refused   error // what Overview and Network answer
	asked     []string
	networks  int
}

func (s *fakeServer) Wallets(context.Context) ([]ServerWallet, error) { return s.wallets, s.down }
func (s *fakeServer) Drafts(context.Context) ([]Draft, error)         { return s.drafts, s.down }
func (s *fakeServer) Overview(_ context.Context, id string) (*Overview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, id)
	if s.down != nil || s.refused != nil {
		return nil, errors.Join(s.down, s.refused)
	}
	return s.overviews[id], nil
}
func (s *fakeServer) Network(context.Context) (*ChainStatus, error) {
	s.networks++
	if s.down != nil || s.refused != nil {
		return nil, errors.Join(s.down, s.refused)
	}
	return s.chain, nil
}

// overviewOf is what the server says of a wallet of the fake wallet.
func overviewOf(id string, f *fakeWallet, lovelace string) *Overview {
	o := &Overview{WalletID: id, Address: model.Address{Raw: f.st.Wallets[0].Wallet.Address}.Bech32(), UTxOs: 3919, LiveDrafts: 2}
	o.Balance.Lovelace = lovelace
	return o
}

// withServer starts the view with a server, on the wallets' tab.
func withServer(t *testing.T, f *fakeWallet, s *fakeServer) Model {
	t.Helper()
	m := New(context.Background(), f, (&softkey.Slot{}).Open, "preprod")
	m.server = s
	m.now = func() time.Time { return at }
	m = drive(t, m, tea.WindowSizeMsg{Width: 110, Height: 32})
	m = drive(t, m, m.Init()())
	return press(t, m, "2")
}

// settle answers the wish for the wallet on show, as the wait would.
func settle(t *testing.T, m Model) Model {
	t.Helper()
	w, ok := m.chosen()
	if !ok {
		t.Fatal("no wallet on show")
	}
	return drive(t, m, overviewWanted{wallet: w.ID})
}

// TestBalance: the balance is the server's, read as text from outside.
func TestBalance(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	s := &fakeServer{overviews: map[string]*Overview{walletA: overviewOf(walletA, f, "5477175325")}}
	m := withServer(t, f, s)
	if v := plain(m); !strings.Contains(v, "BALANCE  asking the server…") || !strings.Contains(v, "│  SERVER  │") {
		t.Fatalf("before the balance:\n%s", v)
	}
	m = settle(t, m)
	v := plain(m)
	if !strings.Contains(v, "BALANCE  5477.175325 ADA  3919 UTxO  2 drafts") {
		t.Fatalf("the balance:\n%s", v)
	}
	s.overviews[walletA].UTxOHealth.Suggestion, s.overviews[walletA].Balance.AssetsCount = "consolidate", 3
	if v = plain(press(t, m, "r")); !strings.Contains(v, "3 tokens") || !strings.Contains(v, "▲ consolidate") {
		t.Errorf("tokens and health:\n%s", v)
	}
}

// TestBalanceOfAnother: a server that names another address, another wallet
// or no amount is not believed.
func TestBalanceOfAnother(t *testing.T) {
	for name, spoil := range map[string]func(*Overview){
		"address": func(o *Overview) { o.Address = "addr_test1evil" },
		"wallet":  func(o *Overview) { o.WalletID = walletB },
	} {
		f := newFake(ipc.MethodPassword)
		o := overviewOf(walletA, f, "9000000000")
		spoil(o)
		m := settle(t, withServer(t, f, &fakeServer{overviews: map[string]*Overview{walletA: o}}))
		if v := plain(m); !strings.Contains(v, "the server names another address") || strings.Contains(v, "9000.000000") {
			t.Errorf("another %s:\n%s", name, v)
		}
	}
	f := newFake(ipc.MethodPassword)
	m := settle(t, withServer(t, f, &fakeServer{overviews: map[string]*Overview{walletA: overviewOf(walletA, f, "lots")}}))
	if !strings.Contains(plain(m), "the server gave no amount") {
		t.Errorf("no amount:\n%s", plain(m))
	}
}

// TestQuota: a balance asks every UTxO of a wallet from the data sources, so
// the view asks for the wallet on show alone, once it stays on show, not again
// for a minute, not twice at once, and not while another tab is on show.
func TestQuota(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	s := &fakeServer{overviews: map[string]*Overview{walletA: overviewOf(walletA, f, "1"), walletB: overviewOf(walletB, f, "2")}}
	now := at
	m := withServer(t, f, s)
	m.now = func() time.Time { return now }

	// The wish of a wallet the person already left asks nothing.
	m = drive(t, press(t, m, "down"), overviewWanted{wallet: walletA})
	if len(s.asked) != 0 {
		t.Fatalf("walking past a wallet asked %v", s.asked)
	}
	m = settle(t, m)
	if !slices.Equal(s.asked, []string{walletB}) {
		t.Fatalf("asked %v", s.asked)
	}
	m = settle(t, m)
	if len(s.asked) != 1 {
		t.Fatalf("within the minute: asked %v", s.asked)
	}
	m = press(t, m, "r")
	if len(s.asked) != 2 {
		t.Fatalf("r did not ask: %v", s.asked)
	}
	now = now.Add(overviewAge)
	if m = settle(t, m); len(s.asked) != 3 {
		t.Fatalf("after the minute: asked %v", s.asked)
	}

	// One at a time.
	m.link.overviews[walletB].busy = true
	if m = press(t, m, "r"); len(s.asked) != 3 {
		t.Fatalf("while one is under way: asked %v", s.asked)
	}
	m.link.overviews[walletB].busy = false

	// On another tab, nothing.
	now = now.Add(overviewAge)
	m = press(t, m, "1")
	if m = drive(t, m, overviewWanted{wallet: walletB}); len(s.asked) != 3 {
		t.Fatalf("on another tab: asked %v", s.asked)
	}

	// A source that refuses is not asked again at once.
	m = press(t, m, "2")
	s.refused = &mcpclient.ToolError{Code: "RATE_LIMITED"}
	m = settle(t, m)
	if len(s.asked) != 4 || !strings.Contains(plain(m), "0.000002 ADA  as of 14:33:08, RATE_LIMITED") {
		t.Fatalf("refused: asked %v\n%s", s.asked, plain(m))
	}
	if m = settle(t, m); len(s.asked) != 4 {
		t.Errorf("refused again at once: asked %v", s.asked)
	}
}

// TestRefusedFirst: with no balance yet, a refusal says so.
func TestRefusedFirst(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	s := &fakeServer{refused: &mcpclient.ToolError{Code: "SOURCE_UNAVAILABLE"}}
	m := settle(t, withServer(t, f, s))
	if !strings.Contains(plain(m), "unavailable: SOURCE_UNAVAILABLE") {
		t.Errorf("refused:\n%s", plain(m))
	}
}

// TestNoServer: the view goes on without one, and the frame says so; when it
// comes back the view finds it.
func TestNoServer(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	s := &fakeServer{down: errors.New("no socket"), overviews: map[string]*Overview{walletA: overviewOf(walletA, f, "1000000")}}
	m := withServer(t, f, s)
	v := plain(m)
	if !strings.Contains(v, "NO SERVER") || !strings.Contains(v, "BALANCE  the server does not answer") || strings.Contains(v, "ERROR") {
		t.Fatalf("no server:\n%s", v)
	}
	if !strings.Contains(plain(press(t, m, "6")), "DOES NOT ANSWER") {
		t.Errorf("the system tab:\n%s", plain(press(t, m, "6")))
	}
	m = settle(t, m)
	if len(s.asked) != 0 {
		t.Errorf("a server that is down was asked for a balance: %v", s.asked)
	}
	if m = press(t, m, "r"); len(s.asked) != 1 {
		t.Errorf("r asks anyway, to see if it came back: %v", s.asked)
	}
	s.down = nil
	m = drive(t, m, m.pollServer())
	if v = plain(press(t, m, "r")); strings.Contains(v, "NO SERVER") || !strings.Contains(v, "1.000000 ADA") {
		t.Errorf("back:\n%s", v)
	}
}

// TestOneServerChain: each answer asks for the next once, so one chain of it
// runs.
func TestOneServerChain(t *testing.T) {
	m := withServer(t, newFake(ipc.MethodPassword), &fakeServer{})
	if _, cmd := m.Update(serverMsg{err: errors.New("down")}); cmd == nil {
		t.Fatal("no next round after a failure")
	}
	next, cmd := m.Update(tickServer())
	if cmd == nil {
		t.Fatal("the tick asked nothing")
	}
	if _, ok := cmd().(serverMsg); !ok || next == nil {
		t.Error("the tick did not poll")
	}
}

func tickServer() serverTick { return serverTick{} }

// TestDrafts: the live drafts show under the approvals, by the wallet's name,
// and what the server wrote goes through visible.
func TestDrafts(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	s := &fakeServer{drafts: []Draft{{ID: "d_abc", WalletID: walletA, State: "pending\x1b[2J", Kind: "payment", Fee: "170000", NetEffect: "-5170000", ExpiresAt: "2026-10-28T15:00:00Z"}}}
	m := withServer(t, f, s)
	m = press(t, m, "3")
	bare := sgr.ReplaceAllString(m.render(), "")
	if strings.Contains(bare, "\x1b") {
		t.Errorf("the view draws what the server sent: %q", bare)
	}
	v := plain(m)
	if !strings.Contains(v, "DRAFTS OF THE AGENT") || !strings.Contains(v, "d_abc") || !strings.Contains(v, "AGENTE") || !strings.Contains(v, "0.17") {
		t.Errorf("the drafts:\n%s", v)
	}
	s.drafts = nil
	if m = drive(t, m, m.pollServer()); strings.Contains(plain(m), "DRAFTS OF THE AGENT") {
		t.Errorf("no drafts left:\n%s", plain(m))
	}
}

// TestModeACount: wallets only the server knows are counted on the overview.
func TestModeACount(t *testing.T) {
	m := withServer(t, newFake(ipc.MethodPassword), &fakeServer{wallets: []ServerWallet{{Mode: "A"}, {Mode: "C"}}})
	if v := plain(press(t, m, "1")); !strings.Contains(v, "1 of mode A lives only in the server's config.json") {
		t.Errorf("mode A:\n%s", v)
	}
}

// TestNetwork: it probes every data source, so opening the tab asks once a
// minute at most, and n asks now.
func TestNetwork(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	s := &fakeServer{chain: &ChainStatus{Network: "preprod", DataSource: SourceStatus{Name: "blockfrost", Status: "ok"},
		DataSources: []SourceStatus{{Name: "blockfrost", Status: "ok"}, {Name: "koios", Status: "unavailable"}}}}
	s.chain.Tip = &struct {
		Slot   string `json:"slot"`
		Height string `json:"height"`
		Epoch  string `json:"epoch"`
		Time   string `json:"time"`
	}{"123", "45", "6", "2026-10-28T14:32:00Z"}
	now := at
	m := withServer(t, f, s)
	m.now = func() time.Time { return now }
	if s.networks != 0 {
		t.Fatalf("asked before the tab: %d", s.networks)
	}
	m = press(t, m, "6")
	v := plain(m)
	if s.networks != 1 || !strings.Contains(v, "slot 123, height 45, epoch 6") || !strings.Contains(v, "koios unavailable") || !strings.Contains(v, "IN USE      blockfrost") {
		t.Fatalf("the network, %d asked:\n%s", s.networks, v)
	}
	m = press(t, m, "1", "6")
	if s.networks != 1 {
		t.Fatalf("coming back within the minute: %d", s.networks)
	}
	m = press(t, m, "n")
	if s.networks != 2 {
		t.Fatalf("n: %d", s.networks)
	}
	now = now.Add(overviewAge)
	m = press(t, m, "1", "6")
	if s.networks != 3 {
		t.Fatalf("after the minute: %d", s.networks)
	}
	s.refused = &mcpclient.ToolError{Code: "SOURCE_UNAVAILABLE"}
	if m = press(t, m, "n"); !strings.Contains(plain(m), "unavailable: SOURCE_UNAVAILABLE") {
		t.Errorf("refused:\n%s", plain(m))
	}
}

// mcpSocket is a minimal MCP server on a socket that records the tools it is
// called with.
type mcpSocket struct {
	mu    sync.Mutex
	tools []string
}

func (s *mcpSocket) called() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.tools)
}

func (s *mcpSocket) serve(t *testing.T, c net.Conn) {
	defer c.Close()
	in := bufio.NewScanner(c)
	in.Buffer(nil, 1<<20)
	for in.Scan() {
		var req struct {
			ID     *int   `json:"id"`
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if json.Unmarshal(in.Bytes(), &req) != nil || req.ID == nil {
			continue
		}
		result := map[string]any{"serverInfo": map[string]any{"version": "test"}}
		if req.Method == "tools/call" {
			s.mu.Lock()
			s.tools = append(s.tools, req.Params.Name)
			s.mu.Unlock()
			result = map[string]any{"content": []any{}, "structuredContent": map[string]any{"wallet_id": walletA, "wallets": []any{}, "drafts": []any{},
				"balance": map[string]any{"lovelace": "1"}}}
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": *req.ID, "result": result})
		c.Write(append(b, '\n'))
	}
}

func listenMCP(t *testing.T) (string, *mcpSocket) {
	t.Helper()
	dir, err := os.MkdirTemp("", "mcp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	s := &mcpSocket{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(t, c)
		}
	}()
	return path, s
}

// TestOnlyReadTools: at the socket, everything the view does calls the four
// tools of the plan and no other, and any other does not leave the view.
func TestOnlyReadTools(t *testing.T) {
	want := []string{"get_network_status", "get_wallet_overview", "list_drafts", "list_wallets"}
	if got := slices.Sorted(maps.Keys(readTools)); !slices.Equal(got, want) {
		t.Fatalf("readTools: %v", got)
	}
	path, sock := listenMCP(t)
	c := &ServerConn{Socket: path, Version: "test"}
	defer c.Close()
	f := newFake(ipc.MethodPassword)
	addAudit(t, f, 2)
	m := New(context.Background(), f, (&softkey.Slot{}).Open, "preprod")
	m.server, m.now = c, func() time.Time { return at }
	m = drive(t, m, m.Init()())
	for _, k := range []string{"2", "r", "down", "r", "3", "4", "5", "6", "n", "1"} {
		m = press(t, m, k)
	}
	used := sock.called()
	for _, tool := range used {
		if !readTools[tool] {
			t.Errorf("the view called %s", tool)
		}
	}
	for _, tool := range want {
		if !slices.Contains(used, tool) {
			t.Errorf("the view never called %s: %v", tool, used)
		}
	}
	for _, tool := range []string{"build_payment", "authorize_draft", "cancel_draft", "submit_transaction", "set_datasources", "create_wallet", ""} {
		if err := c.call(context.Background(), tool, map[string]any{}, nil); err == nil {
			t.Errorf("%q left the view", tool)
		}
	}
	if got := sock.called(); len(got) != len(used) {
		t.Errorf("reached the socket: %v", got[len(used):])
	}
}

// TestOneWayToTheServer: only server.go reaches the MCP client, and only
// through the one call that checks the tool.
func TestOneWayToTheServer(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		if name != "server.go" && strings.Contains(text, "mcpclient") {
			t.Errorf("%s uses the MCP client", name)
		}
		if n := strings.Count(text, "c.client.Call("); name == "server.go" && n != 1 {
			t.Errorf("%d calls to the MCP client", n)
		}
		if strings.Contains(text, "CallRaw") {
			t.Errorf("%s calls a tool past readTools", name)
		}
	}
}

// TestServerConnReconnects: a session that breaks opens again at the next
// call, and a tool's error keeps it.
func TestServerConnReconnects(t *testing.T) {
	path, sock := listenMCP(t)
	c := &ServerConn{Socket: path, Version: "test"}
	defer c.Close()
	if _, err := c.Wallets(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.client.Close()
	if _, err := c.Drafts(context.Background()); err == nil {
		t.Fatal("a broken session answered")
	}
	if c.client != nil {
		t.Fatal("the broken session stayed")
	}
	if _, err := c.Drafts(context.Background()); err != nil {
		t.Errorf("after reconnecting: %v", err)
	}
	if len(sock.called()) != 2 {
		t.Errorf("called %v", sock.called())
	}
}
