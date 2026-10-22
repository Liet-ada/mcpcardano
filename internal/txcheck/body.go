// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package txcheck

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The readers below take the generic tree that cborx decodes: uint64 for
// unsigned integers, int64 for negative ones, []byte, string, []any,
// map[any]any with cborx.ByteString for byte-string keys, and cborx.Tag.
// Anything else in a place they read is an error, so a value never passes
// with a form the ledger would read differently.

func unsigned(x any) (uint64, error) {
	n, ok := x.(uint64)
	if !ok {
		return 0, errors.New("not an unsigned integer")
	}
	return n, nil
}

func slot(x any) (*uint64, error) {
	n, err := unsigned(x)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func hash(x any, size int) ([]byte, error) {
	b, ok := x.([]byte)
	if !ok || len(b) != size {
		return nil, fmt.Errorf("not a hash of %d bytes", size)
	}
	return b, nil
}

func networkID(x any) (*uint8, error) {
	n, ok := x.(uint64)
	if !ok || n > 1 {
		return nil, errors.New("not 0 or 1")
	}
	id := uint8(n)
	return &id, nil
}

// set returns the elements of a Conway set: an array, with or without tag
// 258.
func set(x any) ([]any, error) {
	if t, ok := x.(cborx.Tag); ok {
		if t.Number != setTag {
			return nil, fmt.Errorf("tag %d instead of a set", t.Number)
		}
		x = t.Content
	}
	a, ok := x.([]any)
	if !ok {
		return nil, errors.New("not a set")
	}
	return a, nil
}

// sortedKeys returns the keys of a map whose keys are all byte strings, in
// canonical order, so that the first error is always the same one.
func sortedKeys(m map[any]any) ([]cborx.ByteString, error) {
	keys := make([]cborx.ByteString, 0, len(m))
	for k := range m {
		b, ok := k.(cborx.ByteString)
		if !ok {
			return nil, errors.New("a key is not a byte string")
		}
		keys = append(keys, b)
	}
	slices.SortFunc(keys, func(a, b cborx.ByteString) int {
		if len(a) != len(b) {
			return len(a) - len(b)
		}
		return bytes.Compare([]byte(a), []byte(b))
	})
	return keys, nil
}

// inputs reads the non-empty set of inputs, [transaction_id, index] each.
func inputs(x any) ([]Input, error) {
	items, err := set(x)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, errors.New("no inputs")
	}
	out := make([]Input, len(items))
	seen := make(map[Input]bool, len(items))
	for i, item := range items {
		pair, ok := item.([]any)
		if !ok || len(pair) != 2 {
			return nil, fmt.Errorf("input %d is not [transaction_id, index]", i)
		}
		id, err := hash(pair[0], 32)
		if err != nil {
			return nil, fmt.Errorf("input %d: %v", i, err)
		}
		ix, ok := pair[1].(uint64)
		if !ok || ix > math.MaxUint16 {
			return nil, fmt.Errorf("input %d: the index is not an integer of 2 bytes", i)
		}
		in := Input{TxID: [32]byte(id), Index: uint16(ix)}
		if seen[in] {
			return nil, fmt.Errorf("input %d appears twice", i)
		}
		seen[in] = true
		out[i] = in
	}
	return out, nil
}

// outputs reads the outputs, in the legacy form [address, value] or in the
// form {0: address, 1: value}. An output with a datum or a reference script
// is rejected (decision 35).
func outputs(x any) ([]model.Output, error) {
	items, ok := x.([]any)
	if !ok {
		return nil, errors.New("not an array")
	}
	out := make([]model.Output, len(items))
	for i, item := range items {
		o, err := output(item)
		if err != nil {
			return nil, fmt.Errorf("output %d: %v", i, err)
		}
		out[i] = o
	}
	return out, nil
}

func output(x any) (model.Output, error) {
	var addr, val any
	switch o := x.(type) {
	case []any:
		switch len(o) {
		case 2:
			addr, val = o[0], o[1]
		case 3:
			return model.Output{}, errors.New("a datum hash is not supported")
		default:
			return model.Output{}, errors.New("not [address, value]")
		}
	case map[any]any:
		for k := range o {
			switch k {
			case uint64(0), uint64(1):
			case uint64(2):
				return model.Output{}, errors.New("a datum is not supported")
			case uint64(3):
				return model.Output{}, errors.New("a reference script is not supported")
			default:
				return model.Output{}, errors.New("unknown output field")
			}
		}
		var ok0, ok1 bool
		addr, ok0 = o[uint64(0)]
		val, ok1 = o[uint64(1)]
		if !ok0 || !ok1 {
			return model.Output{}, errors.New("no address or no value")
		}
	default:
		return model.Output{}, errors.New("not an output")
	}
	a, err := address(addr)
	if err != nil {
		return model.Output{}, err
	}
	v, err := value(val)
	if err != nil {
		return model.Output{}, err
	}
	return model.Output{Address: a, Value: v}, nil
}

// address reads a Shelley payment address (CIP-19): a base address, with a
// stake credential, or an enterprise address, without one. Byron and pointer
// addresses are not accepted (decision 105).
func address(x any) (model.Address, error) {
	raw, ok := x.([]byte)
	if !ok || len(raw) == 0 {
		return model.Address{}, errors.New("the address is not a byte string")
	}
	typ, network := raw[0]>>4, raw[0]&0x0f
	var size int
	switch typ {
	case 0, 1, 2, 3:
		size = 1 + 28 + 28
	case 6, 7:
		size = 1 + 28
	default:
		return model.Address{}, fmt.Errorf("address type %d is not supported", typ)
	}
	if len(raw) != size {
		return model.Address{}, fmt.Errorf("an address of type %d has %d bytes, not %d", typ, len(raw), size)
	}
	if network > 1 {
		return model.Address{}, fmt.Errorf("network %d of an address is not 0 or 1", network)
	}
	// Bit 0 of the type says whether the payment credential is a script,
	// bit 1 whether the stake credential is.
	a := model.Address{Raw: raw, Type: typ, NetworkID: network, Payment: credential(typ&1 != 0, raw[1:29])}
	if typ <= 3 {
		stake := credential(typ&2 != 0, raw[29:57])
		a.Stake = &stake
	}
	return a, nil
}

func credential(script bool, h []byte) model.Credential {
	c := model.Credential{Kind: model.KeyHash, Hash: [28]byte(h)}
	if script {
		c.Kind = model.ScriptHash
	}
	return c
}

// value reads a coin or [coin, multiasset] with positive quantities.
func value(x any) (model.Value, error) {
	switch v := x.(type) {
	case uint64:
		return model.Value{Lovelace: v}, nil
	case []any:
		if len(v) != 2 {
			return model.Value{}, errors.New("the value is not [coin, multiasset]")
		}
		l, ok := v[0].(uint64)
		if !ok {
			return model.Value{}, errors.New("the coin is not an unsigned integer")
		}
		assets, err := multiasset(v[1], positive)
		if err != nil {
			return model.Value{}, err
		}
		return model.Value{Lovelace: l, Assets: assets}, nil
	default:
		return model.Value{}, errors.New("not a value")
	}
}

func positive(x any) (uint64, error) {
	n, ok := x.(uint64)
	if !ok || n == 0 {
		return 0, errors.New("not a positive quantity")
	}
	return n, nil
}

// nonZero reads a mint quantity: positive mints, negative burns.
func nonZero(x any) (int64, error) {
	switch n := x.(type) {
	case uint64:
		if n > 0 && n <= math.MaxInt64 {
			return int64(n), nil
		}
	case int64:
		if n < 0 {
			return n, nil
		}
	}
	return 0, errors.New("not a non-zero quantity of 8 bytes")
}

// multiasset reads {+ policy_id => {+ asset_name => quantity}}, the form of
// the tokens of a value and of the mint.
func multiasset[Q uint64 | int64](x any, quantity func(any) (Q, error)) (map[model.AssetID]Q, error) {
	policies, ok := x.(map[any]any)
	if !ok || len(policies) == 0 {
		return nil, errors.New("not a non-empty map of policies")
	}
	pkeys, err := sortedKeys(policies)
	if err != nil {
		return nil, err
	}
	out := make(map[model.AssetID]Q)
	for _, p := range pkeys {
		names, ok := policies[p].(map[any]any)
		if !ok || len(names) == 0 {
			return nil, errors.New("a policy without tokens")
		}
		nkeys, err := sortedKeys(names)
		if err != nil {
			return nil, err
		}
		for _, n := range nkeys {
			id, err := model.NewAssetID([]byte(p), []byte(n))
			if err != nil {
				return nil, err
			}
			q, err := quantity(names[n])
			if err != nil {
				return nil, fmt.Errorf("token %s: %v", id, err)
			}
			out[id] = q
		}
	}
	return out, nil
}

// withdrawals reads {+ reward_account => coin}, ordered by account.
func withdrawals(x any) ([]model.Withdrawal, error) {
	m, ok := x.(map[any]any)
	if !ok || len(m) == 0 {
		return nil, errors.New("not a non-empty map")
	}
	keys, err := sortedKeys(m)
	if err != nil {
		return nil, err
	}
	out := make([]model.Withdrawal, len(keys))
	for i, k := range keys {
		// A reward account is a header of type 14 (key) or 15 (script) and
		// network 0 or 1, and a stake credential.
		if len(k) != 1+28 || k[0]>>4 < 14 || k[0]&0x0f > 1 {
			return nil, fmt.Errorf("withdrawal %d: not a reward account", i)
		}
		amount, ok := m[k].(uint64)
		if !ok {
			return nil, fmt.Errorf("withdrawal %d: the amount is not an unsigned integer", i)
		}
		out[i] = model.Withdrawal{Account: []byte(k), Amount: amount}
	}
	return out, nil
}

// signers reads the non-empty set of required key hashes.
func signers(x any) ([][28]byte, error) {
	items, err := set(x)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, errors.New("an empty set")
	}
	out := make([][28]byte, len(items))
	for i, item := range items {
		h, err := hash(item, 28)
		if err != nil {
			return nil, fmt.Errorf("signer %d: %v", i, err)
		}
		out[i] = [28]byte(h)
		if slices.Contains(out[:i], out[i]) {
			return nil, fmt.Errorf("signer %d appears twice", i)
		}
	}
	return out, nil
}
