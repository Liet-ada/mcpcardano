// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package mcp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// TestWalletErrors: what the wallet process answers reaches the agent with
// the codes of section 4.5, and what only a bug explains is INTERNAL.
func TestWalletErrors(t *testing.T) {
	rejections := map[ipc.Code]string{
		ipc.Frozen:             CodeWalletFrozen,
		ipc.NeedsSession:       CodeNeedsSession,
		ipc.BudgetExceeded:     CodeBudgetExceeded,
		ipc.PolicyBlocked:      CodePolicyBlocked,
		ipc.TTLTooLong:         CodeInvalidParams,
		ipc.TxUnsupportedField: CodeInternal,
		ipc.TxNotCanonical:     CodeInternal,
	}
	for c, want := range rejections {
		if got := rejectionError(&ipc.Error{Code: c, Detail: "rule: detail"}); got.Code != want || got.Hint == "" {
			t.Errorf("rejection %s: got %s", c, got.Code)
		}
	}
	failures := map[error]string{
		&ipc.Error{Code: ipc.Locked}:                            CodeWalletUnavailable,
		&ipc.Error{Code: ipc.UnknownWallet}:                     CodeUnknownWallet,
		&ipc.Error{Code: ipc.RateLimited}:                       CodeRateLimited,
		&ipc.Error{Code: ipc.NotFound}:                          CodeDraftNotFound,
		&ipc.Error{Code: ipc.Malformed}:                         CodeInternal,
		&ipc.Error{Code: ipc.Internal}:                          CodeInternal,
		fmt.Errorf("%w: refused", ErrWalletUnavailable):         CodeWalletUnavailable,
		fmt.Errorf("wrapped: %w", &ipc.Error{Code: ipc.Locked}): CodeWalletUnavailable,
		errors.New("something else"):                            CodeInternal,
	}
	for err, want := range failures {
		if got := translate(err); got.Code != want {
			t.Errorf("%v: got %s, want %s", err, got.Code, want)
		}
	}
	// A server without a wallet process says so.
	var none *WalletConn
	if err := none.Call(t.Context(), ipc.MsgPing, &ipc.Empty{}, &ipc.PingResult{}); !errors.Is(err, ErrWalletUnavailable) {
		t.Errorf("no wallet process: %v", err)
	}
}

// TestUsage: the server's verdict on a draft of mode B or C counts what the
// wallet process reports, the budget spent included.
func TestUsage(t *testing.T) {
	ps := &ipc.PolicyStatus{SpentHour: 7, SpentDay: 9, BudgetRemaining: 30, Session: &ipc.Session{Remaining: 4}}
	ps.Policy.Limits.Budget = 100
	u := usage(ps)
	if u.Hour.Lovelace != 7 || u.Day.Lovelace != 9 || u.BudgetSpent != 70 || u.Session == nil || u.Session.Remaining != 4 {
		t.Errorf("usage %+v", u)
	}
	ps.BudgetRemaining, ps.Session = 0, nil
	if u := usage(ps); u.BudgetSpent != 100 || u.Session != nil {
		t.Errorf("a spent budget: %+v", u)
	}
}

// TestOrphans: what the wallet signed before the server's restart is
// followed with the rules of the drafts the server sent (section 9.5): it is
// confirmed once deep enough, and expired only two minutes after its TTL
// (decision 78).
func TestOrphans(t *testing.T) {
	e := newEnv(t)
	slot := chain.Clock(model.Preprod).Slot(e.clock())
	gone, late, deep := [32]byte{1}, [32]byte{2}, [32]byte{3}
	e.server.ws.orphans = map[[32]byte]orphan{
		gone: {wallet: walletID, ttl: slot - 121},
		late: {wallet: walletID, ttl: slot - 60},
		deep: {wallet: walletID, ttl: slot - 121},
	}
	e.src.confirmations[deep] = 3
	for range 2 { // each outcome is noted once
		e.server.FollowOrphans(t.Context(), 3, 2*time.Minute)
	}
	if n := len(e.audit.entries); n != 2 {
		t.Errorf("%d entries in the audit log, want 2", n)
	}
	for id, want := range map[[32]byte]string{gone: "expired", late: "unknown", deep: "confirmed"} {
		got, failure := e.call("get_transaction_status", map[string]any{"tx_id": hex.EncodeToString(id[:])})
		if failure != nil || got["status"] != want {
			t.Errorf("%x: got %v, %v; want %s", id[0], got["status"], failure, want)
		}
	}
}

// TestCreateWalletArgs: the server checks the label and the key before it
// asks the wallet process, which this server does not have.
func TestCreateWalletArgs(t *testing.T) {
	e := newEnv(t)
	for _, a := range []map[string]any{
		{"label": ""}, {"label": strings.Repeat("a", 65)}, {"label": "a\nb"},
		{"label": "agent", "idempotency_key": strings.Repeat("k", 65)}, {"label": "agent", "idempotency_key": "k\u200b"},
	} {
		if _, failure := e.call("create_wallet", a); failure == nil || failure.Code != CodeInvalidParams {
			t.Errorf("%q: %v", a, failure)
		}
	}
	if _, failure := e.call("create_wallet", map[string]any{"label": strings.Repeat("a", 64)}); failure == nil || failure.Code != CodeWalletUnavailable {
		t.Errorf("without a wallet process: %v", failure)
	}
}

// fakeWallet is a wallet process that answers from a function, for what the
// real one does not do: drop a connection, or list a wallet the server must
// not take.
type fakeWallet struct {
	path   string
	answer func(typ string) ipc.Body

	mu   sync.Mutex
	drop int        // requests to answer by closing the connection
	seen []ipc.Body // the requests, but the greetings
}

func startFakeWallet(t *testing.T, answer func(typ string) ipc.Body) *fakeWallet {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mcpw") // a short socket path
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, "w.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); os.RemoveAll(dir) })
	f := &fakeWallet{path: ln.Addr().String(), answer: answer}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeWallet) serve(conn net.Conn) {
	defer conn.Close()
	codec, limits := ipc.NewCodec(), ipc.DefaultConnLimits()
	for {
		frame, err := ipc.ReadFrame(conn, limits)
		if err != nil {
			return
		}
		r, err := codec.DecodeRequest(ipc.Service, frame)
		if err != nil {
			return
		}
		req := ipc.NewRequest(r.T)
		if codec.DecodeBody(r.B, req) != nil {
			return
		}
		var resp ipc.Body = &ipc.Hello{Software: "fake", Network: string(model.Preprod)}
		if r.T != ipc.MsgHello {
			f.mu.Lock()
			f.seen = append(f.seen, req)
			drop := f.drop > 0
			if drop {
				f.drop--
			}
			f.mu.Unlock()
			if drop {
				return
			}
			resp = f.answer(r.T)
		}
		out, err := codec.EncodeResponse(r.ID, resp)
		if err != nil || ipc.WriteFrame(conn, out, limits) != nil {
			return
		}
	}
}

// connect makes f the server's wallet process.
func (e *env) connect(f *fakeWallet) {
	e.server.d.Wallet = &WalletConn{Path: f.path, Hello: ipc.Hello{Software: "test", Network: string(model.Preprod)}}
	e.t.Cleanup(e.server.d.Wallet.Close)
}

// agentWallet is a wallet of the wallet process, on preprod.
func agentWallet() ipc.Wallet {
	return ipc.Wallet{ID: "w_bbbbbbbbbbbbbbbbbbbbbbbbba", Label: "agent", Network: string(model.Preprod), Mode: string(model.ModeC),
		Address: append([]byte{0x60}, bytes.Repeat([]byte{0x44}, 28)...), CreatedBy: string(model.ByAgent)}
}

// TestWalletConn: when the wallet process drops the connection, the request
// goes again once, on a new one, and create_wallet sends the same key both
// times, so the wallet creates one wallet (section 9.4). A second drop is
// WALLET_UNAVAILABLE.
func TestWalletConn(t *testing.T) {
	e := newEnv(t)
	agent, pol := agentWallet(), ipc.PolicyFrom(e.wallet.Policy)
	f := startFakeWallet(t, func(typ string) ipc.Body {
		switch typ {
		case ipc.MsgCreateWallet:
			return &ipc.WalletCreated{Wallet: agent, Policy: pol}
		case ipc.MsgListWallets:
			return &ipc.WalletList{Wallets: []ipc.Wallet{agent}}
		}
		return &ipc.PolicyStatus{Mode: agent.Mode, Policy: pol, Pending: []ipc.PendingTx{}}
	})
	e.connect(f)
	f.drop = 1
	if got, failure := e.call("create_wallet", map[string]any{"label": "agent"}); failure != nil || got["wallet_id"] != agent.ID {
		t.Fatalf("create_wallet: %v, %v", got, failure)
	}
	f.mu.Lock()
	var keys []string
	for _, r := range f.seen {
		if c, ok := r.(*ipc.CreateWallet); ok {
			keys = append(keys, c.IdempotencyKey)
		}
	}
	f.drop = 2
	f.mu.Unlock()
	if len(keys) != 2 || !strings.HasPrefix(keys[0], "server-") || keys[1] != keys[0] {
		t.Errorf("keys %q", keys)
	}
	if _, failure := e.call("get_policy_status", map[string]any{"wallet_id": agent.ID}); failure == nil || failure.Code != CodeWalletUnavailable {
		t.Errorf("two drops: %v", failure)
	}
}

// TestRemoteWallets: of the wallets of the wallet process, the server takes
// those of its network whose ids are not those of its mode A wallets.
func TestRemoteWallets(t *testing.T) {
	e := newEnv(t)
	agent, pol := agentWallet(), ipc.PolicyFrom(e.wallet.Policy)
	mainnet, clash := agent, agent
	mainnet.ID, mainnet.Network, mainnet.Address = "w_ccccccccccccccccccccccccca", string(model.Mainnet), append([]byte{0x61}, agent.Address[1:]...)
	clash.ID = walletID
	e.connect(startFakeWallet(t, func(typ string) ipc.Body {
		if typ == ipc.MsgListWallets {
			return &ipc.WalletList{Wallets: []ipc.Wallet{clash, agent, mainnet}}
		}
		return &ipc.PolicyStatus{Mode: agent.Mode, Policy: pol, Pending: []ipc.PendingTx{}}
	}))
	got, failure := e.call("list_wallets", nil)
	if failure != nil {
		t.Fatal(failure)
	}
	var ids []string
	for _, w := range got["wallets"].([]any) {
		w := w.(map[string]any)
		ids = append(ids, fmt.Sprint(w["wallet_id"], " ", w["mode"]))
	}
	if want := []string{walletID + " A", frozenID + " A", agent.ID + " C"}; !slices.Equal(ids, want) {
		t.Errorf("wallets %q, want %q", ids, want)
	}
}
