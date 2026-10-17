// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package txbuild

import (
	"fmt"
	"slices"
	"unicode/utf8"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Everything that is signed is encoded here with cborx, never with
// gouroboros, whose encoders follow cardano-ledger instead of CIP-21
// (decision 49).

// setTag marks a CBOR array as a set (Conway).
const setTag = 258

// cip20Label is the metadata label of transaction messages (CIP-20).
const cip20Label = 674

// maxMetadataText is the longest text string metadata accepts.
const maxMetadataText = 64

func newCodec() *cborx.Codec {
	c, err := cborx.New(cborx.Limits{MaxDepth: 32, MaxArrayElements: 1 << 16, MaxMapPairs: 1 << 16, AllowTags: true})
	if err != nil {
		panic(err) // constant limits
	}
	return c
}

// valueCBOR encodes a value: a coin, or [coin, {policy: {name: quantity}}].
func valueCBOR(v model.Value) any {
	if !v.HasAssets() {
		return v.Lovelace
	}
	ma := map[cborx.ByteString]map[cborx.ByteString]uint64{}
	for a, q := range v.Assets {
		if q == 0 {
			continue
		}
		p := cborx.ByteString(a.Policy[:])
		if ma[p] == nil {
			ma[p] = map[cborx.ByteString]uint64{}
		}
		ma[p][cborx.ByteString(a.Name)] = q
	}
	return []any{v.Lovelace, ma}
}

// outputCBOR encodes an output in the legacy form [address, value], the
// smallest one, which every hardware wallet accepts. The MVP's outputs carry
// no datum or script.
func outputCBOR(addr model.Address, v model.Value) any {
	return []any{addr.Raw, valueCBOR(v)}
}

func inputsCBOR(ins []chain.TxIn) cborx.Tag {
	sorted := slices.Clone(ins)
	slices.SortFunc(sorted, chain.TxIn.Compare)
	arr := make([]any, len(sorted))
	for i, in := range sorted {
		arr[i] = []any{in.TxID[:], uint64(in.Index)}
	}
	return cborx.Tag{Number: setTag, Content: arr}
}

// splitMessage cuts a CIP-20 message into strings of at most 64 bytes,
// never inside a UTF-8 character.
func splitMessage(msg string) []string {
	var out []string
	for len(msg) > 0 {
		n := min(len(msg), maxMetadataText)
		for n < len(msg) && !utf8.RuneStart(msg[n]) {
			n--
		}
		out = append(out, msg[:n])
		msg = msg[n:]
	}
	return out
}

// auxDataCBOR encodes the auxiliary data of a CIP-20 message as a plain
// metadata map {674: {"msg": [...]}}, or returns nil if there is none.
func auxDataCBOR(c *cborx.Codec, msg string) ([]byte, error) {
	if msg == "" {
		return nil, nil
	}
	return c.Marshal(map[uint64]any{cip20Label: map[string]any{"msg": splitMessage(msg)}})
}

// body is a transaction body before encoding.
type body struct {
	inputs  []chain.TxIn
	outputs []model.Output
	fee     uint64
	ttl     uint64
	auxHash []byte
}

func (b body) encode(c *cborx.Codec) ([]byte, error) {
	outs := make([]any, len(b.outputs))
	for i, o := range b.outputs {
		outs[i] = outputCBOR(o.Address, o.Value)
	}
	m := map[uint64]any{
		0: inputsCBOR(b.inputs),
		1: outs,
		2: b.fee,
		3: b.ttl,
	}
	if b.auxHash != nil {
		m[7] = b.auxHash
	}
	return c.Marshal(m)
}

// placeholderWitnesses is a witness set with one vkey witness of the real
// size, so the fee covers the signed transaction (section 8.1, step 5). It
// uses the tagged set form, the larger of the two, and the signed
// transaction must be assembled the same way.
func placeholderWitnesses(c *cborx.Codec, keys int) ([]byte, error) {
	ws := make([]any, keys)
	for i := range ws {
		vkey := make([]byte, 32)
		vkey[0] = byte(i + 1) // distinct, so the set has no duplicates
		ws[i] = []any{vkey, make([]byte, 64)}
	}
	return c.Marshal(map[uint64]any{0: cborx.Tag{Number: setTag, Content: ws}})
}

// assemble encodes [body, witnesses, true, auxiliary data or null].
func assemble(c *cborx.Codec, body, witnesses, aux []byte) ([]byte, error) {
	var auxItem any
	if aux != nil {
		auxItem = cborx.Raw(aux)
	}
	return c.Marshal([]any{cborx.Raw(body), cborx.Raw(witnesses), true, auxItem})
}

func blake2b256(b []byte) [32]byte { return blake2b.Sum256(b) }

// minADA returns the least lovelace an output with these tokens may hold:
// (160 + its size in bytes) × coins per byte (Babbage and Conway). The size
// depends on the lovelace field itself, so it iterates to the fixed point.
func minADA(c *cborx.Codec, addr model.Address, assets map[model.AssetID]uint64, perByte uint64) (uint64, error) {
	var l uint64
	for range 5 {
		b, err := c.Marshal(outputCBOR(addr, model.Value{Lovelace: l, Assets: assets}))
		if err != nil {
			return 0, err
		}
		need := (160 + uint64(len(b))) * perByte
		if need <= l {
			return l, nil
		}
		l = need
	}
	return 0, fmt.Errorf("%w: minimum ADA does not converge", ErrInternal)
}

// valueSize is the encoded size of a value, bounded by max_val_size.
func valueSize(c *cborx.Codec, v model.Value) (int, error) {
	b, err := c.Marshal(valueCBOR(v))
	return len(b), err
}
