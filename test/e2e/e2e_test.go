// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package e2e runs the mode A path of milestone H-1 end to end, without
// hardware: the server on a real socket, an agent's calls through the CLI's
// MCP client, the signer with a device that signs in software, and a chain
// that confirms what it receives.
package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/datasource"
	"github.com/Liet-ada/mcpcardano/internal/mcp"
	"github.com/Liet-ada/mcpcardano/internal/mcpclient"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/server"
	"github.com/Liet-ada/mcpcardano/internal/signer"
)

// ledger is a data source with funded addresses, which keeps what is
// submitted and confirms it when told.
type ledger struct {
	mu        sync.Mutex
	now       time.Time
	utxos     []chain.UTxO
	submitted map[[32]byte][]byte
	confirmed map[[32]byte]uint64
}

func (l *ledger) Name() string                       { return "ledger" }
func (l *ledger) Network() model.Network             { return model.Preprod }
func (l *ledger) CheckNetwork(context.Context) error { return nil }
func (l *ledger) Tip(context.Context) (datasource.Tip, error) {
	return datasource.Tip{Slot: chain.Clock(model.Preprod).Slot(l.now), Height: 5_000_000, Epoch: 319, Time: l.now}, nil
}
func (l *ledger) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{
		Epoch: 319, MinFeeA: 44, MinFeeB: 155381, MaxTxSize: 16384, MaxValueSize: 5000, CoinsPerUTxOByte: 4310,
		KeyDeposit: 2_000_000, PoolDeposit: 500_000_000, DRepDeposit: 500_000_000, GovActionDeposit: 1_000_000_000,
		PriceMem: chain.Rational{Num: 577, Den: 10000}, PriceStep: chain.Rational{Num: 721, Den: 10000000},
		MaxTxExMem: 17_500_000, MaxTxExSteps: 10_000_000_000, CollateralPercent: 150, MaxCollateralInputs: 3,
		MinFeeRefScriptByte: chain.Rational{Num: 15, Den: 1}, ProtocolMajor: 11,
	}, nil
}
func (l *ledger) UTxOs(_ context.Context, a model.Address) ([]chain.UTxO, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []chain.UTxO
	for _, u := range l.utxos {
		if u.Address.Equal(a) {
			out = append(out, u)
		}
	}
	return out, nil
}
func (l *ledger) Account(context.Context, string) (datasource.Account, error) {
	return datasource.Account{}, datasource.ErrNotFound
}
func (l *ledger) Asset(context.Context, model.AssetID) (datasource.Asset, error) {
	return datasource.Asset{}, datasource.ErrNotFound
}
func (l *ledger) AssetByFingerprint(context.Context, string) (model.AssetID, error) {
	return model.AssetID{}, datasource.ErrNotFound
}
func (l *ledger) Transaction(context.Context, [32]byte) (datasource.Transaction, error) {
	return datasource.Transaction{}, datasource.ErrNotFound
}
func (l *ledger) Submit(_ context.Context, tx []byte, id [32]byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.submitted[id] = tx
	return nil
}
func (l *ledger) Confirmations(_ context.Context, ids [][32]byte) (map[[32]byte]uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[[32]byte]uint64{}
	for _, id := range ids {
		out[id] = l.confirmed[id]
	}
	return out, nil
}

// device signs in software, as the hardware wallet would after the person
// confirms.
type device struct{ key ed25519.PrivateKey }

func (d device) KeyGen(_ context.Context, dir string) error {
	c, _ := cborx.New(cborx.RecordLimits())
	raw, _ := c.Marshal([]byte(d.key.Public().(ed25519.PublicKey)))
	for _, name := range []string{"payment", "stake"} {
		b, _ := json.Marshal(map[string]string{"type": "PaymentVerificationKeyShelley_ed25519", "description": "", "cborHex": hex.EncodeToString(raw)})
		os.WriteFile(filepath.Join(dir, name+".vkey"), b, 0o600)
		os.WriteFile(filepath.Join(dir, name+".hwsfile"), []byte("{}"), 0o600)
	}
	return nil
}

func (d device) ShowAddress(context.Context, string) error { return nil }

func (d device) Version(context.Context) (string, error) { return "e2e device", nil }

func (d device) Witness(_ context.Context, _ model.Network, tx []byte, _ string) ([]byte, []byte, error) {
	c, _ := cborx.New(cborx.Limits{MaxDepth: 64, MaxArrayElements: 1 << 16, MaxMapPairs: 1 << 16, AllowTags: true})
	var parts []cborx.Raw
	if err := c.Unmarshal(tx, &parts); err != nil {
		return nil, nil, err
	}
	id := blake2b.Sum256(parts[0])
	return d.key.Public().(ed25519.PublicKey), ed25519.Sign(d.key, id[:]), nil
}

func TestModeAEndToEnd(t *testing.T) {
	now := time.Now().UTC()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	sign := &signer.Signer{Device: device{key}, KeysDir: t.TempDir()}
	bech, err := sign.Init(t.Context(), model.Preprod)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := chain.ParseAddress(model.Preprod, bech)
	if err != nil {
		t.Fatalf("the signer's address does not parse on the server: %v", err)
	}
	src := &ledger{
		now:       now,
		utxos:     []chain.UTxO{{In: chain.TxIn{TxID: [32]byte{0xaa}}, Address: addr, Value: model.Value{Lovelace: 100_000_000}}},
		submitted: map[[32]byte][]byte{}, confirmed: map[[32]byte]uint64{},
	}
	dir, err := os.MkdirTemp("/tmp", "mcpe")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	settings := server.Settings{
		Network: model.Preprod, DataDir: filepath.Join(dir, "data"), Socket: filepath.Join(dir, "mcp.sock"), ConfirmationDepth: 3,
		Wallets: []mcp.Wallet{{
			Wallet: model.Wallet{ID: "w_k3fq2mx7c4v6bn5ta2sd7hpely", Label: "Trezor", Network: model.Preprod, Mode: model.ModeA, Address: addr, CreatedBy: model.ByPerson},
			Policy: model.Policy{
				Networks:     []model.Network{model.Preprod},
				Limits:       model.Limits{PerTx: 50_000_000, MaxFee: 2_000_000, MaxLiveDrafts: 3, MaxTTLSeconds: 3600},
				Destinations: model.Destinations{Any: true},
			},
		}},
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- server.Run(ctx, settings, server.Options{Source: src, WatchEvery: 50 * time.Millisecond, Version: "e2e"})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()

	var agent *mcpclient.Client
	for range 100 {
		if agent, err = mcpclient.Dial(t.Context(), settings.Socket, "e2e"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	// The agent builds and authorizes a payment.
	var d struct {
		DraftID string `json:"draft_id"`
		State   string `json:"state"`
		Summary struct {
			TxID string `json:"tx_id"`
		} `json:"summary"`
	}
	shop := "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz"
	if err := agent.Call(t.Context(), "build_payment", map[string]any{"wallet_id": "w_k3fq2mx7c4v6bn5ta2sd7hpely",
		"outputs": []any{map[string]any{"address": shop, "lovelace": "5000000"}}, "message": "e2e"}, &d); err != nil {
		t.Fatal(err)
	}
	if err := agent.Call(t.Context(), "authorize_draft", map[string]any{"draft_id": d.DraftID}, &d); err != nil || d.State != "pending_approval" {
		t.Fatalf("authorize: %s, %v", d.State, err)
	}

	// The signer, on its own session, finds the draft and signs it.
	conn, err := mcpclient.Dial(t.Context(), settings.Socket, "e2e")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sign.Client = conn
	signCtx, stopSigner := context.WithCancel(t.Context())
	signerDone := make(chan error, 1)
	go func() { signerDone <- sign.Run(signCtx, 20*time.Millisecond) }()

	wait := func(want string) {
		t.Helper()
		for range 200 {
			if err := agent.Call(t.Context(), "get_draft", map[string]any{"draft_id": d.DraftID}, &d); err != nil {
				t.Fatal(err)
			}
			if d.State == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("the draft is %s, want %s", d.State, want)
	}
	wait("submitted")
	stopSigner()
	if err := <-signerDone; err != nil {
		t.Fatal(err)
	}
	txID, _ := hex.DecodeString(d.Summary.TxID)
	signed := src.submitted[[32]byte(txID)]
	if signed == nil {
		t.Fatal("nothing reached the network")
	}

	// The chain takes it; the server sees it confirmed at depth 3.
	src.mu.Lock()
	src.confirmed[[32]byte(txID)] = 3
	src.mu.Unlock()
	wait("confirmed")
	var st struct {
		Status string `json:"status"`
		Depth  uint64 `json:"depth"`
	}
	if err := agent.Call(t.Context(), "get_transaction_status", map[string]any{"tx_id": d.Summary.TxID}, &st); err != nil || st.Status != "confirmed" || st.Depth != 3 {
		t.Fatalf("status %+v, %v", st, err)
	}
	if err := agent.Call(t.Context(), "get_draft", map[string]any{"draft_id": "d_k3fq2mx7c4v6bn5ta2sd7hpely"}, &d); err == nil {
		t.Error("an unknown draft answered")
	} else if te, ok := err.(*mcpclient.ToolError); !ok || te.Code != "DRAFT_NOT_FOUND" {
		t.Errorf("error %v", err)
	}
}
