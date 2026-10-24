// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"log/slog"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/datasource"
	"github.com/Liet-ada/mcpcardano/internal/drafts"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// chainSource answers Confirmations from a table the test changes.
type chainSource struct {
	source
	mu    sync.Mutex
	confs map[[32]byte]uint64
}

// relayOf is the relay the server builds over its sources.
func relayOf(t *testing.T, sources ...datasource.Source) *datasource.Relay {
	t.Helper()
	r, err := datasource.NewRelay(sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (c *chainSource) set(id [32]byte, n uint64) { c.mu.Lock(); c.confs[id] = n; c.mu.Unlock() }

func (c *chainSource) Confirmations(_ context.Context, ids [][32]byte) (map[[32]byte]uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[[32]byte]uint64{}
	for _, id := range ids {
		out[id] = c.confs[id]
	}
	return out, nil
}

type entries struct {
	mu   sync.Mutex
	list []map[string]any
}

func (e *entries) Append(_ context.Context, _ string, body any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.list = append(e.list, body.(map[string]any))
	return nil
}

// sentDraft builds, authorizes, signs and marks as sent a draft of a mode A
// wallet whose key the test holds.
func sentDraft(t *testing.T, store *drafts.Store, now time.Time) drafts.Draft {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	h, _ := blake2b.New(28, nil)
	h.Write(priv.Public().(ed25519.PublicKey))
	addr, err := chain.AddressFromBytes(append(append([]byte{0x00}, h.Sum(nil)...), bytes.Repeat([]byte{0x5a}, 28)...))
	if err != nil {
		t.Fatal(err)
	}
	shop, _ := chain.AddressFromBytes(append([]byte{0x60}, bytes.Repeat([]byte{0x77}, 28)...))
	d, err := store.Create(drafts.Request{
		Wallet: model.Wallet{ID: "w_k3fq2mx7c4v6bn5ta2sd7hpely", Network: model.Preprod, Mode: model.ModeA, Address: addr},
		Policy: model.Policy{
			Networks:     []model.Network{model.Preprod},
			Limits:       model.Limits{PerTx: 100_000_000, MaxFee: 2_000_000, MaxLiveDrafts: 3, MaxTTLSeconds: 3600},
			Destinations: model.Destinations{Any: true},
		},
		Intent: model.Intent{Kind: model.IntentPayment, Payment: &model.Payment{Outputs: []model.PaymentOutput{{Address: shop, Value: model.Value{Lovelace: 5_000_000}}}}},
		UTxOs:  []chain.UTxO{{In: chain.TxIn{TxID: [32]byte{0xee}}, Address: addr, Value: model.Value{Lovelace: 50_000_000}}},
		Params: chain.ProtocolParameters{
			Epoch: 319, MinFeeA: 44, MinFeeB: 155381, MaxTxSize: 16384, MaxValueSize: 5000, CoinsPerUTxOByte: 4310,
			KeyDeposit: 2_000_000, PoolDeposit: 500_000_000, PriceMem: chain.Rational{Num: 577, Den: 10000},
			PriceStep: chain.Rational{Num: 721, Den: 10000000}, CollateralPercent: 150, MaxCollateralInputs: 3,
			MinFeeRefScriptByte: chain.Rational{Num: 15, Den: 1}, ProtocolMajor: 11,
		},
		TipSlot: chain.Clock(model.Preprod).Slot(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.Authorize(d.ID)
	c, _ := cborx.New(cborx.Limits{MaxDepth: 8, MaxArrayElements: 16, MaxMapPairs: 16, AllowTags: true})
	w, _ := c.Marshal(map[uint64]any{0: cborx.Tag{Number: 258, Content: []any{
		[]any{[]byte(priv.Public().(ed25519.PublicKey)), ed25519.Sign(priv, d.Tx.ID[:])}}}})
	if _, err := store.Sign(d.ID, w); err != nil {
		t.Fatal(err)
	}
	if d, err = store.Submitted(d.ID); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestWatcher follows a sent transaction through every state the chain can
// give it.
func TestWatcher(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	store := drafts.New(clock, nil)
	d := sentDraft(t, store, now)
	src := &chainSource{confs: map[[32]byte]uint64{}}
	rec := &entries{}
	w := &watcher{store: store, src: relayOf(t, src), rec: rec, now: clock, depth: 3, log: slog.New(slog.DiscardHandler)}

	steps := []struct {
		confs uint64
		state drafts.State
		depth uint32
	}{
		{0, drafts.StateSubmitted, 0},  // not in a block yet
		{1, drafts.StateSubmitted, 0},  // in a block, not deep enough
		{3, drafts.StateConfirmed, 3},  // deep enough
		{5, drafts.StateConfirmed, 5},  // deeper
		{0, drafts.StateRolledBack, 0}, // a reorganization took it out
		{2, drafts.StateSubmitted, 0},  // it entered again
		{4, drafts.StateConfirmed, 4},
		{stableDepth, drafts.StateConfirmed, stableDepth}, // as deep as k
		{0, drafts.StateConfirmed, stableDepth},           // no longer asked about
	}
	for i, s := range steps {
		src.set(d.Tx.ID, s.confs)
		w.once(t.Context())
		got, _ := store.Get(d.ID)
		if got.State != s.state || got.Depth != s.depth {
			t.Fatalf("step %d: %s at depth %d, want %s at %d", i, got.State, got.Depth, s.state, s.depth)
		}
	}
	if len(rec.list) != 4 {
		t.Errorf("%d state changes in the audit log: %v", len(rec.list), rec.list)
	}

	// A transaction that never enters expires only once its TTL and the
	// grace have passed, and frees its inputs.
	store2 := drafts.New(clock, nil)
	e := sentDraft(t, store2, now)
	w2 := &watcher{store: store2, src: relayOf(t, src), rec: rec, now: clock, depth: 3, log: slog.New(slog.DiscardHandler)}
	src.set(e.Tx.ID, 0) // the same transaction as before, built at the same time, now never in the chain
	mu.Lock()
	now = e.ExpiresAt.Add(ttlGrace - time.Second)
	mu.Unlock()
	w2.once(t.Context())
	if got, _ := store2.Get(e.ID); got.State != drafts.StateSubmitted {
		t.Fatalf("expired within the grace: %s", got.State)
	}
	mu.Lock()
	now = e.ExpiresAt.Add(ttlGrace + time.Second)
	mu.Unlock()
	w2.once(t.Context())
	if got, _ := store2.Get(e.ID); got.State != drafts.StateExpired || len(store2.Reserved(got.Wallet)) != 0 {
		t.Fatalf("after the grace: %s", got.State)
	}
}

// switchingSource is a chainSource with a name, which can go down.
type switchingSource struct {
	*chainSource
	name string
	down sync.Mutex // held while the source is down
	off  bool
}

func (s *switchingSource) Name() string { return s.name }

func (s *switchingSource) Confirmations(ctx context.Context, ids [][32]byte) (map[[32]byte]uint64, error) {
	s.down.Lock()
	off := s.off
	s.down.Unlock()
	if off {
		return nil, datasource.ErrUnavailable
	}
	return s.chainSource.Confirmations(ctx, ids)
}

// TestWatcherAfterASwitch: a source that takes over from another and does
// not see a confirmed transaction yet does not roll it back on its first
// round; on the second, it does (decision 136).
func TestWatcherAfterASwitch(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := drafts.New(clock, nil)
	d := sentDraft(t, store, now)
	first := &switchingSource{chainSource: &chainSource{confs: map[[32]byte]uint64{}}, name: "first"}
	second := &switchingSource{chainSource: &chainSource{confs: map[[32]byte]uint64{}}, name: "second"}
	w := &watcher{store: store, src: relayOf(t, first, second), rec: &entries{}, now: clock, depth: 3, log: slog.New(slog.DiscardHandler)}

	first.set(d.Tx.ID, 3)
	w.once(t.Context())
	if got, _ := store.Get(d.ID); got.State != drafts.StateConfirmed {
		t.Fatalf("confirmed by the first source: %s", got.State)
	}
	first.down.Lock()
	first.off = true
	first.down.Unlock()
	w.once(t.Context()) // the second, a block behind, does not see it
	if got, _ := store.Get(d.ID); got.State != drafts.StateConfirmed {
		t.Fatalf("rolled back on the word of a source that just took over: %s", got.State)
	}
	w.once(t.Context())
	if got, _ := store.Get(d.ID); got.State != drafts.StateRolledBack {
		t.Fatalf("the second source's second round: %s", got.State)
	}
}
