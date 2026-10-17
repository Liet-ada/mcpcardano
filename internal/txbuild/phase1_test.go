// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package txbuild

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// TestPhase1CatchesDefects shows that the validator the builder relies on is
// not vacuous: each defect, made on purpose, is rejected.
func TestPhase1CatchesDefects(t *testing.T) {
	c := newCodec()
	w := newWallet(t, 1)
	shop := enterprise(t, 7)
	in := w.utxo(1, 0, model.Value{Lovelace: ada(50)})
	out, _ := c.Marshal(outputCBOR(in.Address, in.Value))
	spent := []chain.Spent{{In: in.In, Output: out}}
	wits, _ := placeholderWitnesses(c, 1)

	const fee = 170_000
	good := func() body {
		return body{
			inputs: []chain.TxIn{in.In},
			outputs: []model.Output{
				{Address: shop, Value: model.Value{Lovelace: ada(5)}},
				{Address: w.addr, Value: model.Value{Lovelace: ada(45) - fee}},
			},
			fee: fee, ttl: tip + 100,
		}
	}
	sign := func(key ed25519.PrivateKey, raw []byte) []byte {
		id := blake2b256(raw)
		ws, _ := c.Marshal(map[uint64]any{0: cborx.Tag{Number: setTag, Content: []any{[]any{[]byte(key.Public().(ed25519.PublicKey)), ed25519.Sign(key, id[:])}}}})
		tx, _ := assemble(c, raw, ws, nil)
		return tx
	}
	encode := func(b body) []byte {
		raw, err := b.encode(c)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	raw := encode(good())
	if err := chain.ValidateSigned(model.Preprod, params(), tip, sign(w.priv, raw), spent); err != nil {
		t.Fatalf("the good transaction is rejected: %v", err)
	}
	draft, _ := assemble(c, raw, wits, nil)
	if err := chain.ValidateDraft(model.Preprod, params(), tip, draft, spent); err != nil {
		t.Fatalf("the good draft is rejected: %v", err)
	}

	mainnet, _ := chain.ParseAddress(model.Mainnet, "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8")
	defects := map[string]func(*body){
		"fee one lovelace short": func(b *body) { b.fee = 100_000; b.outputs[1].Value.Lovelace += fee - 100_000 },
		"value not conserved":    func(b *body) { b.outputs[1].Value.Lovelace++ },
		"output below minimum": func(b *body) {
			b.outputs[0].Value.Lovelace = 500_000
			b.outputs[1].Value.Lovelace += ada(5) - 500_000
		},
		"output on mainnet": func(b *body) { b.outputs[0].Address = mainnet },
		"TTL passed":        func(b *body) { b.ttl = tip - 1 },
		"unknown input":     func(b *body) { b.inputs = []chain.TxIn{{TxID: [32]byte{1}}} },
	}
	for name, change := range defects {
		b := good()
		change(&b)
		tx, _ := assemble(c, encode(b), wits, nil)
		if err := chain.ValidateDraft(model.Preprod, params(), tip, tx, spent); !errors.Is(err, chain.ErrPhase1) {
			t.Errorf("%s: draft accepted (%v)", name, err)
		}
	}
	// The minimum fee is exact: one lovelace less than a·size + b fails, where
	// the size leaves out the is_valid byte, as the ledger measures it.
	b := good()
	size := len(sign(w.priv, encode(b))) - 1
	minimum := params().MinFeeA*uint64(size) + params().MinFeeB
	b.fee, b.outputs[1].Value.Lovelace = minimum-1, ada(45)-(minimum-1)
	if err := chain.ValidateSigned(model.Preprod, params(), tip, sign(w.priv, encode(b)), spent); !errors.Is(err, chain.ErrPhase1) {
		t.Errorf("a fee of minimum−1 passes: %v", err)
	}
	b.fee, b.outputs[1].Value.Lovelace = minimum, ada(45)-minimum
	if err := chain.ValidateSigned(model.Preprod, params(), tip, sign(w.priv, encode(b)), spent); err != nil {
		t.Errorf("the minimum fee fails: %v", err)
	}

	// Signatures: the draft check skips them, the signed check does not.
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	if err := chain.ValidateSigned(model.Preprod, params(), tip, sign(other, raw), spent); !errors.Is(err, chain.ErrPhase1) {
		t.Errorf("a signature by another key passes: %v", err)
	}
}
