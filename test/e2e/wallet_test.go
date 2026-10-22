// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/mcpclient"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/server"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

// stack is the server on a real socket, talking to a real wallet process,
// with an agent connected over MCP and the person connected to the wallet's
// admin socket, on a chain that confirms what it is told.
type stack struct {
	t        *testing.T
	src      *ledger
	wallet   *walletkit.Wallet
	admin    *ipc.Client
	settings server.Settings
	agent    *mcpclient.Client
	stop     func()
}

func newStack(t *testing.T) *stack {
	now := time.Now().UTC()
	st := &stack{t: t, src: &ledger{now: now, submitted: map[[32]byte][]byte{}, confirmed: map[[32]byte]uint64{}}}
	st.wallet = walletkit.StartAt(t, walletkit.RealClock())
	st.admin = st.wallet.Admin(t)
	walletkit.Unlock(t, st.admin)
	dir, err := os.MkdirTemp("/tmp", "mcpe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	st.settings = server.Settings{Network: model.Preprod, DataDir: filepath.Join(dir, "data"),
		Socket: filepath.Join(dir, "mcp.sock"), WalletSocket: st.wallet.Config.ServiceSocket, ConfirmationDepth: 3}
	st.startServer()
	return st
}

// startServer runs the server and connects the agent.
func (st *stack) startServer() {
	t := st.t
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Run(ctx, st.settings, server.Options{Source: st.src, WatchEvery: 30 * time.Millisecond, Version: "e2e"})
	}()
	var err error
	for range 200 {
		if st.agent, err = mcpclient.Dial(ctx, st.settings.Socket, "e2e"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	st.stop = func() {
		st.agent.Close()
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(st.stopServer)
}

// stopServer stops the server once; a cleanup after a restart finds it
// stopped.
func (st *stack) stopServer() {
	if st.stop != nil {
		st.stop()
		st.stop = nil
	}
}

func (st *stack) call(tool string, args map[string]any, out any) error {
	return st.agent.Call(context.Background(), tool, args, out)
}

// fund gives an address UTxOs of the given lovelace each.
func (st *stack) fund(address string, n int, lovelace uint64) {
	addr, err := chain.ParseAddress(model.Preprod, address)
	if err != nil {
		st.t.Fatal(err)
	}
	st.src.mu.Lock()
	defer st.src.mu.Unlock()
	for i := range n {
		id := [32]byte{0xbb, byte(len(st.src.utxos)), byte(i)}
		st.src.utxos = append(st.src.utxos, chain.UTxO{In: chain.TxIn{TxID: id}, Address: addr, Value: model.Value{Lovelace: lovelace}})
	}
}

type draft struct {
	DraftID string `json:"draft_id"`
	State   string `json:"state"`
	Reason  string `json:"reason"`
	Next    string `json:"next"`
	Summary struct {
		TxID string `json:"tx_id"`
	} `json:"summary"`
}

func (st *stack) pay(wallet, to string, lovelace string) draft {
	st.t.Helper()
	var d draft
	if err := st.call("build_payment", map[string]any{"wallet_id": wallet,
		"outputs": []any{map[string]any{"address": to, "lovelace": lovelace}}}, &d); err != nil {
		st.t.Fatalf("build_payment: %v", err)
	}
	return d
}

// wait polls the draft until it reaches a state.
func (st *stack) wait(d *draft, want string) {
	st.t.Helper()
	for range 300 {
		if err := st.call("get_draft", map[string]any{"draft_id": d.DraftID}, d); err != nil {
			st.t.Fatal(err)
		}
		if d.State == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	st.t.Fatalf("draft %s is %s, want %s", d.DraftID, d.State, want)
}

func (st *stack) confirm(d draft) {
	id, _ := hex.DecodeString(d.Summary.TxID)
	st.src.mu.Lock()
	defer st.src.mu.Unlock()
	if st.src.submitted[[32]byte(id)] == nil {
		st.t.Fatalf("draft %s did not reach the network", d.DraftID)
	}
	st.src.confirmed[[32]byte(id)] = 3
}

func code(err error) string {
	var te *mcpclient.ToolError
	if errors.As(err, &te) {
		return te.Code
	}
	return ""
}

// addresses of other people, on preprod.
var (
	shop   = "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz"
	others = []string{enterprise(1), enterprise(2)}
)

// enterprise is the preprod enterprise address of a key hash of b's.
func enterprise(b byte) string {
	return model.Address{Raw: append([]byte{0x60}, bytes.Repeat([]byte{b}, 28)...)}.Bech32()
}

// TestModesBAndCEndToEnd runs the wallet process of milestone H-2 end to
// end, without network: the agent creates a wallet, the wallet signs within
// its template and refuses beyond it, asks the person above the threshold
// of mode B, waits while locked, and the server follows what the wallet
// signed across its own restart (section 9.5).
func TestModesBAndCEndToEnd(t *testing.T) {
	st := newStack(t)

	// The agent creates a wallet with the template; the person funds it.
	var w struct {
		WalletID         string `json:"wallet_id"`
		Mode             string `json:"mode"`
		Address          string `json:"address"`
		OpenDestinations bool   `json:"open_destinations"`
		Limits           struct {
			PerTx  string `json:"per_tx"`
			Budget string `json:"budget"`
		} `json:"limits"`
	}
	if err := st.call("create_wallet", map[string]any{"label": "agent", "idempotency_key": "k1"}, &w); err != nil {
		t.Fatal(err)
	}
	if w.Mode != "C" || !w.OpenDestinations || w.Limits.PerTx != "20000000" || w.Limits.Budget != "100000000" ||
		!strings.HasPrefix(w.Address, "addr_test1q") {
		t.Fatalf("created %+v", w)
	}
	st.fund(w.Address, 6, 30_000_000)
	var list struct {
		Wallets []struct {
			WalletID  string `json:"wallet_id"`
			Mode      string `json:"mode"`
			CreatedBy string `json:"created_by"`
		} `json:"wallets"`
	}
	if err := st.call("list_wallets", nil, &list); err != nil || len(list.Wallets) != 1 || list.Wallets[0].CreatedBy != "agent" {
		t.Fatalf("list_wallets %+v, %v", list, err)
	}

	// Mode C: the wallet signs, the server sends at once.
	d := st.pay(w.WalletID, shop, "5000000")
	if err := st.call("authorize_draft", map[string]any{"draft_id": d.DraftID}, &d); err != nil || d.State != "submitted" {
		t.Fatalf("authorize in mode C: %+v, %v", d, err)
	}
	st.confirm(d)
	st.wait(&d, "confirmed")
	var ps struct {
		Mode            string `json:"mode"`
		SpendTracked    bool   `json:"spend_tracked"`
		SpentHour       string `json:"spent_hour"`
		BudgetRemaining string `json:"budget_remaining"`
	}
	if err := st.call("get_policy_status", map[string]any{"wallet_id": w.WalletID}, &ps); err != nil ||
		!ps.SpendTracked || ps.SpentHour == "" || ps.SpentHour == "0" || ps.BudgetRemaining == "100000000" {
		t.Fatalf("policy status %+v, %v", ps, err)
	}

	// Beyond what the server can see: a third new destination within the
	// hour passes the server's verdict and the wallet refuses it.
	second := st.pay(w.WalletID, others[0], "2000000")
	if err := st.call("authorize_draft", map[string]any{"draft_id": second.DraftID}, &second); err != nil || second.State != "submitted" {
		t.Fatalf("second destination: %+v, %v", second, err)
	}
	third := st.pay(w.WalletID, others[1], "2000000")
	err := st.call("authorize_draft", map[string]any{"draft_id": third.DraftID}, &third)
	if code(err) != "BUDGET_EXCEEDED" || !strings.Contains(err.Error(), "limits.new_destinations_per_hour") {
		t.Fatalf("a third new destination: %v", err)
	}
	st.call("get_draft", map[string]any{"draft_id": third.DraftID}, &third)
	if third.State != "rejected" {
		t.Errorf("the refused draft is %s", third.State)
	}

	// A wallet the person creates is one the server learns of when the
	// agent names it.
	var saving ipc.Wallet
	if _, err := walletkit.Authorize(st.admin, ipc.ActCreateWallet, &ipc.CreateWallet{Label: "saving"}, &saving); err != nil {
		t.Fatal(err)
	}
	var sp struct {
		WalletID string `json:"wallet_id"`
	}
	if err := st.call("get_policy_status", map[string]any{"wallet_id": saving.ID}, &sp); err != nil || sp.WalletID != saving.ID {
		t.Fatalf("a wallet the person created: %+v, %v", sp, err)
	}

	// Frozen by the person: the server sees it at once, and again once the
	// person unfreezes.
	if err := st.admin.Call(context.Background(), ipc.MsgFreeze, &ipc.Freeze{WalletID: w.WalletID}, &ipc.Empty{}); err != nil {
		t.Fatal(err)
	}
	var none draft
	err = st.call("build_payment", map[string]any{"wallet_id": w.WalletID,
		"outputs": []any{map[string]any{"address": shop, "lovelace": "1000000"}}}, &none)
	if code(err) != "WALLET_FROZEN" {
		t.Fatalf("build_payment on a frozen wallet: %v", err)
	}
	if _, err := walletkit.Authorize(st.admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: w.WalletID}, nil); err != nil {
		t.Fatal(err)
	}
	var again struct {
		Wallets []struct {
			WalletID string `json:"wallet_id"`
			Frozen   bool   `json:"frozen"`
		} `json:"wallets"`
	}
	if err := st.call("list_wallets", nil, &again); err != nil || len(again.Wallets) != 2 || again.Wallets[0].Frozen {
		t.Fatalf("list_wallets after unfreezing: %+v, %v", again, err)
	}

	// Locked: authorize_draft says so and the draft waits; once the person
	// unlocks, it goes through.
	st.wallet.Restart(t)
	locked := st.pay(w.WalletID, shop, "1000000")
	if err := st.call("authorize_draft", map[string]any{"draft_id": locked.DraftID}, &locked); code(err) != "WALLET_UNAVAILABLE" {
		t.Fatalf("authorize while locked: %v", err)
	}
	st.call("get_draft", map[string]any{"draft_id": locked.DraftID}, &locked)
	if locked.State != "authorizing" || !strings.Contains(locked.Next, "authorize_draft again") {
		t.Errorf("while locked the draft is %s: %q", locked.State, locked.Next)
	}
	st.admin = st.wallet.Admin(t)
	walletkit.Unlock(t, st.admin)
	if err := st.call("authorize_draft", map[string]any{"draft_id": locked.DraftID}, &locked); err != nil || locked.State != "submitted" {
		t.Fatalf("authorize after unlocking: %+v, %v", locked, err)
	}

	// Mode B: above the threshold the draft waits for the person, and the
	// server sends it once the person approves.
	var pol ipc.WalletPolicy
	if err := st.admin.Call(context.Background(), ipc.MsgShowPolicy, &ipc.WalletRef{WalletID: w.WalletID}, &pol); err != nil {
		t.Fatal(err)
	}
	pol.Mode, pol.Policy.Limits.ApprovalThreshold = "B", 1_000_000
	if _, err := walletkit.Authorize(st.admin, ipc.ActChangePolicy, &pol, &ipc.PolicyHash{}); err != nil {
		t.Fatal(err)
	}
	b := st.pay(w.WalletID, shop, "3000000")
	if err := st.call("authorize_draft", map[string]any{"draft_id": b.DraftID}, &b); err != nil || b.State != "pending_approval" ||
		!strings.Contains(b.Next, "mcpcardano approve") {
		t.Fatalf("authorize in mode B: %+v, %v", b, err)
	}
	var status ipc.StatusReport
	st.admin.Call(context.Background(), ipc.MsgStatus, &ipc.Empty{}, &status)
	if len(status.Approvals) != 1 {
		t.Fatalf("approvals %+v", status.Approvals)
	}
	if _, err := walletkit.Authorize(st.admin, ipc.ActApproveDraft, &ipc.ApproveDraft{ApprovalID: status.Approvals[0].ID}, nil); err != nil {
		t.Fatal(err)
	}
	st.wait(&b, "submitted")
	no := st.pay(w.WalletID, shop, "3000000")
	if err := st.call("authorize_draft", map[string]any{"draft_id": no.DraftID}, &no); err != nil || no.State != "pending_approval" {
		t.Fatalf("authorize in mode B: %+v, %v", no, err)
	}
	st.admin.Call(context.Background(), ipc.MsgStatus, &ipc.Empty{}, &status)
	if len(status.Approvals) != 1 {
		t.Fatalf("approvals %+v", status.Approvals)
	}
	if err := st.admin.Call(context.Background(), ipc.MsgReject, &ipc.ApprovalRef{ApprovalID: status.Approvals[0].ID}, &ipc.Empty{}); err != nil {
		t.Fatal(err)
	}
	st.wait(&no, "rejected")

	// The server restarts: it lost its drafts, and it follows what the wallet
	// signed (section 9.5).
	st.stopServer()
	st.startServer()
	var ts struct {
		Status string `json:"status"`
	}
	if err := st.call("get_transaction_status", map[string]any{"tx_id": b.Summary.TxID}, &ts); err != nil || ts.Status != "unknown" {
		t.Fatalf("status after the restart: %+v, %v", ts, err)
	}
	entries, _, err := audit.Read(context.Background(), filepath.Join(st.settings.DataDir, "audit.log"), audit.Options{Kind: "audit"})
	if err != nil {
		t.Fatal(err)
	}
	synced := false
	for _, e := range entries {
		if e.Type == "wallet_sync" && bytes.Contains(e.Body, []byte(b.Summary.TxID)) {
			synced = true
		}
	}
	if !synced {
		t.Error("the restarted server does not follow what the wallet signed")
	}
	st.confirm(b)
	if err := st.call("get_transaction_status", map[string]any{"tx_id": b.Summary.TxID}, &ts); err != nil || ts.Status != "confirmed" {
		t.Fatalf("status once confirmed: %+v, %v", ts, err)
	}
}

// TestWithoutWalletProcess: a server whose wallet process does not run still
// reads, and says what is missing when asked for a wallet.
func TestWithoutWalletProcess(t *testing.T) {
	st := &stack{t: t, src: &ledger{now: time.Now().UTC(), submitted: map[[32]byte][]byte{}, confirmed: map[[32]byte]uint64{}}}
	dir, _ := os.MkdirTemp("/tmp", "mcpe")
	t.Cleanup(func() { os.RemoveAll(dir) })
	st.settings = server.Settings{Network: model.Preprod, DataDir: filepath.Join(dir, "data"),
		Socket: filepath.Join(dir, "mcp.sock"), WalletSocket: filepath.Join(dir, "nobody.sock"), ConfirmationDepth: 3}
	st.startServer()
	var list struct {
		Wallets []any `json:"wallets"`
	}
	if err := st.call("list_wallets", nil, &list); err != nil || len(list.Wallets) != 0 {
		t.Fatalf("list_wallets %+v, %v", list, err)
	}
	if err := st.call("create_wallet", map[string]any{"label": "agent"}, &struct{}{}); code(err) != "WALLET_UNAVAILABLE" {
		t.Fatalf("create_wallet: %v", err)
	}
}
