// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package txbuild

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/txdecode"
)

// The parameters of preprod at epoch 319.
func params() chain.ProtocolParameters {
	return chain.ProtocolParameters{
		Epoch: 319, MinFeeA: 44, MinFeeB: 155381, MaxTxSize: 16384, MaxValueSize: 5000, CoinsPerUTxOByte: 4310,
		KeyDeposit: 2_000_000, PoolDeposit: 500_000_000, DRepDeposit: 500_000_000, GovActionDeposit: 1_000_000_000,
		PriceMem: chain.Rational{Num: 577, Den: 10000}, PriceStep: chain.Rational{Num: 721, Den: 10000000},
		MaxTxExMem: 17_500_000, MaxTxExSteps: 10_000_000_000, CollateralPercent: 150, MaxCollateralInputs: 3,
		MinFeeRefScriptByte: chain.Rational{Num: 15, Den: 1}, ProtocolMajor: 11,
	}
}

const tip = 136_515_214

// wallet is a test wallet whose payment key the tests hold, so they can sign
// what the builder produces and run every phase-1 rule, signatures included.
type wallet struct {
	priv ed25519.PrivateKey
	addr model.Address
}

func newWallet(t testing.TB, seed byte) wallet {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	h, _ := blake2b.New(28, nil)
	h.Write(priv.Public().(ed25519.PublicKey))
	raw := append([]byte{0x00}, h.Sum(nil)...)           // base address, testnet
	raw = append(raw, bytes.Repeat([]byte{0x5a}, 28)...) // any stake key
	addr, err := chain.AddressFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return wallet{priv: priv, addr: addr}
}

func enterprise(t testing.TB, b byte) model.Address {
	a, err := chain.AddressFromBytes(append([]byte{0x60}, bytes.Repeat([]byte{b}, 28)...))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func asset(t testing.TB, p byte, name string) model.AssetID {
	a, err := model.NewAssetID(bytes.Repeat([]byte{p}, 28), []byte(name))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (w wallet) utxo(tx byte, ix uint32, v model.Value) chain.UTxO {
	return chain.UTxO{In: chain.TxIn{TxID: [32]byte{0: 0xee, 31: tx}, Index: ix}, Address: w.addr, Value: v}
}

func defaultPolicy() model.UTxOPolicy {
	return model.UTxOPolicy{TargetADAOnly: 1, MinSplit: 5_000_000, DustThreshold: 1_000_000, MaxDustSweep: 2}
}

func input(w wallet, intent model.Intent, pool []chain.UTxO) Input {
	return Input{
		Network: model.Preprod, Wallet: w.addr, Intent: intent, Available: pool,
		Params: params(), UTxO: defaultPolicy(), MaxFee: 2_000_000, TipSlot: tip, TTLSeconds: 3600,
	}
}

func pay(to model.Address, v model.Value) model.Intent {
	return model.Intent{Kind: model.IntentPayment, Payment: &model.Payment{Outputs: []model.PaymentOutput{{Address: to, Value: v}}}}
}

// signAndValidate signs tx with the wallet's key and runs every Conway rule.
func signAndValidate(t testing.TB, w wallet, tx *Tx) {
	t.Helper()
	c := newCodec()
	sig := ed25519.Sign(w.priv, tx.ID[:])
	wits, err := c.Marshal(map[uint64]any{0: cborx.Tag{Number: setTag, Content: []any{[]any{[]byte(w.priv.Public().(ed25519.PublicKey)), sig}}}})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := assemble(c, tx.Body, wits, tx.AuxData)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed)-1 != tx.Size {
		t.Errorf("signed size %d, fee computed for %d", len(signed)-1, tx.Size)
	}
	spent := make([]chain.Spent, len(tx.Inputs))
	for i, u := range tx.Inputs {
		out, _ := c.Marshal(outputCBOR(u.Address, u.Value))
		spent[i] = chain.Spent{In: u.In, Output: out}
	}
	if err := chain.ValidateSigned(model.Preprod, params(), tip, signed, spent); err != nil {
		t.Fatalf("signed transaction rejected: %v", err)
	}
}

// checkBalance verifies inputs = outputs + fee, per lovelace and per token.
func checkBalance(t testing.TB, tx *Tx) {
	t.Helper()
	var in, out model.Value
	for _, u := range tx.Inputs {
		in, _ = in.Add(u.Value)
	}
	for _, o := range tx.Outputs {
		out, _ = out.Add(o.Value)
	}
	out, _ = out.Add(model.Value{Lovelace: tx.Fee})
	if in.Lovelace != out.Lovelace {
		t.Fatalf("lovelace in %d, out+fee %d", in.Lovelace, out.Lovelace)
	}
	for a, q := range in.Assets {
		if out.Assets[a] != q {
			t.Fatalf("token %s: in %d, out %d", a, q, out.Assets[a])
		}
	}
	for a, q := range out.Assets {
		if in.Assets[a] != q {
			t.Fatalf("token %s appears from nowhere", a)
		}
	}
}

func TestSimplePayment(t *testing.T) {
	w := newWallet(t, 1)
	shop := enterprise(t, 7)
	pool := []chain.UTxO{w.utxo(1, 0, model.Value{Lovelace: ada(100)}), w.utxo(2, 0, model.Value{Lovelace: ada(20)})}
	tx, err := Build(input(w, pay(shop, model.Value{Lovelace: ada(5)}), pool))
	if err != nil {
		t.Fatal(err)
	}
	signAndValidate(t, w, tx)
	checkBalance(t, tx)
	// Both UTxOs are 40 ADA from the mean of 60; MACS breaks the tie with
	// the larger value, as Apollo does.
	if len(tx.Inputs) != 1 || tx.Inputs[0].Value.Lovelace != ada(100) {
		t.Errorf("inputs %v", tx.Inputs)
	}
	if len(tx.Outputs) != 2 || !tx.Outputs[0].Address.Equal(shop) || tx.Outputs[0].Own || !tx.Outputs[1].Own {
		t.Errorf("outputs %+v", tx.Outputs)
	}
	if tx.Fee < 160_000 || tx.Fee > 200_000 || tx.TTL != tip+3600 {
		t.Errorf("fee %d, ttl %d", tx.Fee, tx.TTL)
	}
	// The same state gives the same bytes.
	again, _ := Build(input(w, pay(shop, model.Value{Lovelace: ada(5)}), pool))
	if !bytes.Equal(again.Body, tx.Body) {
		t.Error("the build is not deterministic")
	}
	unsigned, err := tx.Unsigned()
	if err != nil || !bytes.Contains(unsigned, tx.Body) {
		t.Errorf("unsigned: %v", err)
	}
}

func TestMinimumADA(t *testing.T) {
	c := newCodec()
	w := newWallet(t, 1)
	// (160 + 65 bytes) × 4310 for a base address, (160 + 37) × 4310 for an
	// enterprise one.
	if got, _ := minADA(c, w.addr, nil, 4310); got != 969_750 {
		t.Errorf("base address: %d", got)
	}
	if got, _ := minADA(c, enterprise(t, 1), nil, 4310); got != 849_070 {
		t.Errorf("enterprise address: %d", got)
	}
	pool := []chain.UTxO{w.utxo(1, 0, model.Value{Lovelace: ada(100)})}
	_, err := Build(input(w, pay(enterprise(t, 7), model.Value{Lovelace: 849_069}), pool))
	var below *BelowMinimumError
	if !errors.As(err, &below) || below.Minimum != 849_070 || !errors.Is(err, ErrInvalidOutput) {
		t.Fatalf("got %v", err)
	}
	if tx, err := Build(input(w, pay(enterprise(t, 7), model.Value{Lovelace: 849_070}), pool)); err != nil {
		t.Fatal(err)
	} else {
		signAndValidate(t, w, tx)
	}
}

func TestTokensOnlyOutputGetsMinimumADA(t *testing.T) {
	w := newWallet(t, 1)
	tok := asset(t, 0xa1, "MC")
	pool := []chain.UTxO{
		w.utxo(1, 0, model.Value{Lovelace: ada(3), Assets: map[model.AssetID]uint64{tok: 100}}),
		w.utxo(2, 0, model.Value{Lovelace: ada(50)}),
	}
	in := input(w, pay(enterprise(t, 7), model.Value{Assets: map[model.AssetID]uint64{tok: 40}}), pool)
	in.Verified = func(a model.AssetID) bool { return a == tok }
	tx, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	signAndValidate(t, w, tx)
	checkBalance(t, tx)
	first := tx.Outputs[0]
	if first.Value.Assets[tok] != 40 || first.Value.Lovelace == 0 {
		t.Errorf("payment output %+v", first.Value)
	}
	var change uint64
	for _, o := range tx.Outputs[1:] {
		change += o.Value.Assets[tok]
	}
	if change != 60 {
		t.Errorf("token change %d", change)
	}
}

func TestChangeSplitsTowardsTarget(t *testing.T) {
	w := newWallet(t, 1)
	pool := []chain.UTxO{w.utxo(1, 0, model.Value{Lovelace: ada(200)})}
	in := input(w, pay(enterprise(t, 7), model.Value{Lovelace: ada(10)}), pool)
	in.UTxO.TargetADAOnly = 4
	tx, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	signAndValidate(t, w, tx)
	checkBalance(t, tx)
	if n := len(tx.Outputs) - 1; n != 4 {
		t.Fatalf("%d change outputs, want 4", n)
	}
	// With two ADA-only UTxOs held by other drafts, two pieces are enough.
	in.ReservedADAOnly = 2
	tx, err = Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(tx.Outputs) - 1; n != 2 {
		t.Fatalf("%d change outputs, want 2", n)
	}
	// Pieces never go below the minimum split.
	in.ReservedADAOnly, in.UTxO.MinSplit = 0, ada(80)
	tx, err = Build(in)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(tx.Outputs) - 1; n != 2 {
		t.Fatalf("%d change outputs with an 80 ADA minimum split", n)
	}
}

func TestDeadBand(t *testing.T) {
	w := newWallet(t, 1)
	// 6 ADA in, 5 out: the change after the fee is below the minimum of an
	// output, and there is nothing else to spend.
	pool := []chain.UTxO{w.utxo(1, 0, model.Value{Lovelace: ada(5.9)})}
	in := input(w, pay(enterprise(t, 7), model.Value{Lovelace: ada(5)}), pool)
	tx, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	signAndValidate(t, w, tx)
	checkBalance(t, tx)
	if len(tx.Outputs) != 1 || tx.Fee != ada(0.9) {
		t.Errorf("outputs %d, fee %d", len(tx.Outputs), tx.Fee)
	}
	// The policy's maximum fee forbids giving that much away.
	in.MaxFee = ada(0.5)
	if _, err := Build(in); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("got %v", err)
	}
	// With another UTxO the builder adds it instead.
	in.Available = append(in.Available, w.utxo(2, 0, model.Value{Lovelace: ada(3)}))
	tx, err = Build(in)
	if err != nil {
		t.Fatal(err)
	}
	signAndValidate(t, w, tx)
	if len(tx.Inputs) != 2 || len(tx.Outputs) != 2 {
		t.Errorf("inputs %d, outputs %d", len(tx.Inputs), len(tx.Outputs))
	}
}

func TestUnverifiedTokensAvoided(t *testing.T) {
	w := newWallet(t, 1)
	spam := asset(t, 0x66, "spam")
	pool := []chain.UTxO{
		w.utxo(1, 0, model.Value{Lovelace: ada(20), Assets: map[model.AssetID]uint64{spam: 1}}),
		w.utxo(2, 0, model.Value{Lovelace: ada(12)}),
	}
	tx, err := Build(input(w, pay(enterprise(t, 7), model.Value{Lovelace: ada(8)}), pool))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range tx.Inputs {
		if u.Value.HasAssets() {
			t.Fatal("spent a UTxO with an unverified token although ADA-only ones sufficed")
		}
	}
	// When only the spam UTxO can pay, it is used and its token goes to change.
	tx, err = Build(input(w, pay(enterprise(t, 7), model.Value{Lovelace: ada(25)}), pool))
	if err != nil {
		t.Fatal(err)
	}
	signAndValidate(t, w, tx)
	checkBalance(t, tx)
}

func TestReferenceScriptUTxOsAreLeftAlone(t *testing.T) {
	w := newWallet(t, 1)
	u := w.utxo(1, 0, model.Value{Lovelace: ada(100)})
	u.HasScript = true
	_, err := Build(input(w, pay(enterprise(t, 7), model.Value{Lovelace: ada(5)}), []chain.UTxO{u}))
	if !errors.Is(err, ErrNoFreeUTxOs) {
		t.Fatalf("got %v", err)
	}
}

// checkDecoded compares the transaction read back from its bytes with what
// the builder says it wrote: the same outputs, the same own ones, and a net
// effect equal to the change minus the inputs.
func checkDecoded(t testing.TB, w wallet, tx *Tx) {
	t.Helper()
	d := tx.Decoded
	if d == nil || d.ID() != tx.ID {
		t.Fatal("the transaction was not read back")
	}
	view := d.View(w.addr)
	if len(view.Outputs) != len(tx.Outputs) || view.Fee != tx.Fee || view.TTL == nil || *view.TTL != tx.TTL {
		t.Fatalf("view %+v does not match the built transaction", view)
	}
	var net big.Int
	for i, o := range tx.Outputs {
		got := view.Outputs[i]
		if !got.Address.Equal(o.Address) || got.Own != o.Own || got.Value.Lovelace != o.Value.Lovelace || !maps.Equal(got.Value.Assets, o.Value.Assets) {
			t.Fatalf("output %d read back as %+v, built as %+v", i, got, o)
		}
		if o.Own {
			net.Add(&net, new(big.Int).SetUint64(o.Value.Lovelace))
		}
	}
	for _, u := range tx.Inputs {
		net.Sub(&net, new(big.Int).SetUint64(u.Value.Lovelace))
	}
	s, err := d.Summary(txdecode.Options{Wallet: &w.addr, Spent: tx.Inputs})
	if err != nil {
		t.Fatal(err)
	}
	if s.NetEffect == nil || s.NetEffect.Lovelace != net.String() {
		t.Fatalf("net effect %+v, want %s lovelace", s.NetEffect, net.String())
	}
}

// TestDecodedDraft reads a payment with a token and a message back from its
// bytes, as the draft will show it.
func TestDecodedDraft(t *testing.T) {
	w := newWallet(t, 1)
	tok := asset(t, 0xa1, "MC")
	shop := enterprise(t, 7)
	intent := pay(shop, model.Value{Lovelace: ada(5), Assets: map[model.AssetID]uint64{tok: 40}})
	intent.Payment.Message = strings.Repeat("ñ", 40) + " Invoice 42"
	pool := []chain.UTxO{
		w.utxo(1, 0, model.Value{Lovelace: ada(3), Assets: map[model.AssetID]uint64{tok: 100}}),
		w.utxo(2, 0, model.Value{Lovelace: ada(50)}),
	}
	in := input(w, intent, pool)
	in.Verified = func(a model.AssetID) bool { return a == tok }
	tx, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	checkDecoded(t, w, tx)
	s, err := tx.Decoded.Summary(txdecode.Options{Wallet: &w.addr, Spent: tx.Inputs})
	if err != nil {
		t.Fatal(err)
	}
	if s.Outputs[0].Own == nil || *s.Outputs[0].Own || s.Outputs[0].Lovelace != "5000000" {
		t.Errorf("payment output %+v", s.Outputs[0])
	}
	if got := s.NetEffect.Assets; len(got) != 1 || got[0].Asset != tok.String() || got[0].Quantity != "-40" || got[0].NameUnverified != "MC" {
		t.Errorf("token net effect %+v", got)
	}
	if want := -int64(ada(5) + tx.Fee); s.NetEffect.Lovelace != fmt.Sprint(want) {
		t.Errorf("net effect %s lovelace, want %d", s.NetEffect.Lovelace, want)
	}
	if strings.Join(s.MessageUnverified, "") != intent.Payment.Message {
		t.Errorf("message %q", s.MessageUnverified)
	}
}

func TestMessage(t *testing.T) {
	w := newWallet(t, 1)
	msg := strings.Repeat("ñ", 40) + " Invoice 42" // 80 + 11 bytes, multi-byte runes on the cut
	intent := pay(enterprise(t, 7), model.Value{Lovelace: ada(5)})
	intent.Payment.Message = msg
	tx, err := Build(input(w, intent, []chain.UTxO{w.utxo(1, 0, model.Value{Lovelace: ada(50)})}))
	if err != nil {
		t.Fatal(err)
	}
	signAndValidate(t, w, tx)
	if tx.AuxData == nil {
		t.Fatal("no auxiliary data")
	}
	parts := splitMessage(msg)
	if strings.Join(parts, "") != msg || len(parts) != 2 || len(parts[0]) > 64 {
		t.Fatalf("parts %q", parts)
	}
	for _, p := range parts {
		if !strings.HasPrefix(p, "ñ") && !strings.HasPrefix(p, " ") {
			t.Fatalf("cut inside a character: %q", p)
		}
	}
}

func TestErrors(t *testing.T) {
	w := newWallet(t, 1)
	shop := enterprise(t, 7)
	if _, err := Build(input(w, pay(shop, model.Value{Lovelace: ada(5)}), nil)); !errors.Is(err, ErrNoFreeUTxOs) {
		t.Errorf("empty wallet: %v", err)
	}
	poor := []chain.UTxO{w.utxo(1, 0, model.Value{Lovelace: ada(5)})}
	if _, err := Build(input(w, pay(shop, model.Value{Lovelace: ada(5)}), poor)); !errors.Is(err, ErrInsufficientFunds) {
		t.Errorf("insufficient: %v", err)
	}
	// A payment needing hundreds of dust inputs does not fit in 16 KB.
	var dust []chain.UTxO
	for i := range 600 {
		dust = append(dust, w.utxo(byte(i), uint32(i), model.Value{Lovelace: ada(1.2)}))
	}
	if _, err := Build(input(w, pay(shop, model.Value{Lovelace: ada(600)}), dust)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("too large: %v", err)
	}
	mainnet, _ := chain.ParseAddress(model.Mainnet, "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8")
	if _, err := Build(input(w, pay(mainnet, model.Value{Lovelace: ada(5)}), poor)); !errors.Is(err, ErrInvalidOutput) {
		t.Errorf("other network: %v", err)
	}
	stranger := w.utxo(9, 0, model.Value{Lovelace: ada(50)})
	stranger.Address = shop
	if _, err := Build(input(w, pay(shop, model.Value{Lovelace: ada(5)}), []chain.UTxO{stranger})); !errors.Is(err, ErrInternal) {
		t.Errorf("foreign input: %v", err)
	}
}

func TestConsolidation(t *testing.T) {
	w := newWallet(t, 1)
	tokA, tokB := asset(t, 0xa1, "A"), asset(t, 0xb2, "B")
	var pool []chain.UTxO
	for i := range 30 {
		v := model.Value{Lovelace: ada(0.5 + float64(i))}
		if i%7 == 0 {
			v.Assets = map[model.AssetID]uint64{tokA: uint64(i + 1), tokB: 5}
		}
		pool = append(pool, w.utxo(byte(i), 0, v))
	}
	in := input(w, model.Intent{Kind: model.IntentConsolidation}, pool)
	in.UTxO.TargetADAOnly, in.UTxO.MinSplit = 3, ada(20)
	tx, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	signAndValidate(t, w, tx)
	checkBalance(t, tx)
	if len(tx.Inputs) != 30 {
		t.Errorf("%d inputs", len(tx.Inputs))
	}
	tokenOuts, adaOuts := 0, 0
	for _, o := range tx.Outputs {
		if !o.Own {
			t.Fatal("a consolidation pays someone else")
		}
		if o.Value.HasAssets() {
			tokenOuts++
		} else {
			adaOuts++
		}
	}
	if tokenOuts != 1 || adaOuts != 3 {
		t.Errorf("%d token outputs and %d ADA-only outputs", tokenOuts, adaOuts)
	}
}

func TestConsolidationTooLargeTakesSmallestFirst(t *testing.T) {
	w := newWallet(t, 1)
	var pool []chain.UTxO
	for i := range 700 {
		pool = append(pool, w.utxo(byte(i), uint32(i), model.Value{Lovelace: ada(2) + uint64(i)}))
	}
	tx, err := Build(input(w, model.Intent{Kind: model.IntentConsolidation}, pool))
	if err != nil {
		t.Fatal(err)
	}
	signAndValidate(t, w, tx)
	if len(tx.Inputs) >= 700 || len(tx.Inputs) < 300 {
		t.Fatalf("%d inputs", len(tx.Inputs))
	}
	for _, u := range tx.Inputs {
		if u.Value.Lovelace > ada(2)+uint64(len(tx.Inputs)) {
			t.Fatal("a larger UTxO was taken before a smaller one")
		}
	}
}

func TestTokenChangeGrouping(t *testing.T) {
	c := newCodec()
	w := newWallet(t, 1)
	assets := map[model.AssetID]uint64{}
	for i := range 12 {
		assets[asset(t, 0x01, fmt.Sprintf("big%02d", i))] = 1 // one policy with 12 tokens
	}
	for p := byte(0x10); p < 0x13; p++ {
		assets[asset(t, p, "x")] = 1 // three small policies
		assets[asset(t, p, "y")] = 1
	}
	outs, err := tokenChange(c, w.addr, assets, 4310)
	if err != nil {
		t.Fatal(err)
	}
	var sizes []int
	for _, o := range outs {
		sizes = append(sizes, len(o.Assets))
		policies := map[model.PolicyID]bool{}
		for a := range o.Assets {
			policies[a.Policy] = true
		}
		if len(o.Assets) > maxAssetsPerChange {
			t.Fatalf("output with %d tokens", len(o.Assets))
		}
	}
	if !slices.Equal(sizes, []int{10, 2, 6}) {
		t.Fatalf("groups of %v, want [10 2 6]", sizes)
	}
}

// TestRandomBuilds is the property test of section 11.1: random wallets and
// payments either fail with an agent-facing error or give a transaction that,
// signed, passes every phase-1 rule, balances to the lovelace, never repeats
// an input, fits in the maximum size and is canonical and deterministic.
func TestRandomBuilds(t *testing.T) {
	r := rand.New(rand.NewPCG(11, 1016))
	w := newWallet(t, 3)
	tokens := []model.AssetID{asset(t, 0xa1, "A"), asset(t, 0xa1, "B"), asset(t, 0xc3, ""), asset(t, 0x7f, "long-token-name")}
	built := 0
	const runs = 400
	for run := range runs {
		var pool []chain.UTxO
		for i := range 1 + r.IntN(40) {
			v := model.Value{Lovelace: 1_000_000 + r.Uint64N(300_000_000)}
			if r.IntN(10) < 3 {
				v.Assets = map[model.AssetID]uint64{}
				for range 1 + r.IntN(3) {
					v.Assets[tokens[r.IntN(len(tokens))]] = 1 + r.Uint64N(1000)
				}
			}
			pool = append(pool, w.utxo(byte(run), uint32(i), v))
		}
		var intent model.Intent
		if r.IntN(6) == 0 {
			intent = model.Intent{Kind: model.IntentConsolidation}
		} else {
			p := &model.Payment{}
			for range 1 + r.IntN(4) {
				v := model.Value{Lovelace: 1_000_000 + r.Uint64N(80_000_000)}
				if r.IntN(5) == 0 {
					v.Assets = map[model.AssetID]uint64{tokens[r.IntN(len(tokens))]: 1 + r.Uint64N(50)}
				}
				p.Outputs = append(p.Outputs, model.PaymentOutput{Address: enterprise(t, byte(r.IntN(200))), Value: v})
			}
			if r.IntN(3) == 0 {
				p.Message = strings.Repeat("x", r.IntN(200))
			}
			intent = model.Intent{Kind: model.IntentPayment, Payment: p}
		}
		in := input(w, intent, pool)
		in.UTxO = model.UTxOPolicy{TargetADAOnly: uint32(r.IntN(6)), MinSplit: uint64(r.IntN(30)) * 1_000_000,
			DustThreshold: 1_000_000, MaxDustSweep: uint32(r.IntN(3))}
		in.ReservedADAOnly = r.IntN(3)
		if r.IntN(2) == 0 {
			in.Verified = func(a model.AssetID) bool { return a.Policy[0] == 0xa1 }
		}
		tx, err := Build(in)
		if err != nil {
			if errors.Is(err, ErrInternal) {
				t.Fatalf("run %d: %v", run, err)
			}
			if !errors.Is(err, ErrInsufficientFunds) && !errors.Is(err, ErrInvalidOutput) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("run %d: unexpected error %v", run, err)
			}
			continue
		}
		built++
		signAndValidate(t, w, tx)
		checkBalance(t, tx)
		checkDecoded(t, w, tx)
		seen := map[chain.TxIn]bool{}
		for _, u := range tx.Inputs {
			if seen[u.In] {
				t.Fatalf("run %d: input %s twice", run, u.In)
			}
			seen[u.In] = true
		}
		if tx.Size > 16384 || tx.Fee < in.Params.MinFeeA*uint64(tx.Size)+in.Params.MinFeeB {
			t.Fatalf("run %d: size %d, fee %d", run, tx.Size, tx.Fee)
		}
		if intent.Kind == model.IntentPayment {
			for i, o := range intent.Payment.Outputs {
				got := tx.Outputs[i]
				if !got.Address.Equal(o.Address) || (o.Value.Lovelace > 0 && got.Value.Lovelace != o.Value.Lovelace) {
					t.Fatalf("run %d: output %d is %+v, asked for %+v", run, i, got, o)
				}
			}
			for _, o := range tx.Outputs[len(intent.Payment.Outputs):] {
				if !o.Own || !o.Address.Equal(w.addr) {
					t.Fatalf("run %d: change to another address", run)
				}
			}
		}
		again, err := Build(in)
		if err != nil || !bytes.Equal(again.Body, tx.Body) {
			t.Fatalf("run %d: not deterministic", run)
		}
	}
	if built < runs/2 {
		t.Fatalf("only %d of %d builds succeeded", built, runs)
	}
	t.Logf("%d of %d random builds succeeded and validated", built, runs)
}

// TestManyAssetsMinimumADA covers the check left by decision 49: for maps of
// up to 255 entries the definite header we write (0xb8 n) takes the same two
// bytes as the ledger's indefinite one (0xbf … 0xff), and from 256 ours is
// one byte longer, so the minimum ADA is never too low. The phase-1 rules
// accept both cases.
func TestManyAssetsMinimumADA(t *testing.T) {
	w := newWallet(t, 1)
	for _, n := range []int{30, 300} {
		assets := map[model.AssetID]uint64{}
		for i := range n {
			assets[asset(t, 0xa1, fmt.Sprintf("%03d", i))] = 1
		}
		pool := []chain.UTxO{
			w.utxo(1, 0, model.Value{Lovelace: ada(30), Assets: assets}),
			w.utxo(2, 0, model.Value{Lovelace: ada(100)}),
		}
		in := input(w, pay(enterprise(t, 7), model.Value{Assets: assets}), pool)
		in.Verified = func(model.AssetID) bool { return true }
		tx, err := Build(in)
		if err != nil {
			t.Fatalf("%d tokens: %v", n, err)
		}
		signAndValidate(t, w, tx)
		checkBalance(t, tx)
		if got := len(tx.Outputs[0].Value.Assets); got != n {
			t.Fatalf("%d tokens in the payment, want %d", got, n)
		}
	}
}
