// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package model

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	// ErrOverflow reports an addition or subtraction outside uint64.
	ErrOverflow = errors.New("model: amount overflow")
	// ErrInvalidAmount reports an amount string that is not a plain decimal.
	ErrInvalidAmount = errors.New("model: invalid amount")
	// ErrInvalidAsset reports a malformed asset id.
	ErrInvalidAsset = errors.New("model: invalid asset id")
)

// Add returns a + b, or ErrOverflow.
func Add(a, b uint64) (uint64, error) {
	s := a + b
	if s < a {
		return 0, ErrOverflow
	}
	return s, nil
}

// Sub returns a - b, or ErrOverflow if b > a.
func Sub(a, b uint64) (uint64, error) {
	if b > a {
		return 0, ErrOverflow
	}
	return a - b, nil
}

// FormatAmount writes an amount as the decimal string the agent sees
// (section 4.1).
func FormatAmount(n uint64) string { return strconv.FormatUint(n, 10) }

// ParseAmount reads a decimal amount: digits only, no sign, no leading zeros
// except "0" itself.
func ParseAmount(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, ErrInvalidAmount
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, ErrInvalidAmount
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, ErrOverflow
	}
	return n, nil
}

// PolicyIDSize is the length of a minting policy hash.
const PolicyIDSize = 28

// MaxAssetNameSize is the longest asset name the ledger accepts.
const MaxAssetNameSize = 32

// PolicyID is a minting policy hash.
type PolicyID [PolicyIDSize]byte

// AssetID identifies a native token. Name holds the raw name bytes, so the
// type is comparable and works as a map key.
type AssetID struct {
	Policy PolicyID
	Name   string
}

// NewAssetID builds an asset id from raw bytes.
func NewAssetID(policy, name []byte) (AssetID, error) {
	if len(policy) != PolicyIDSize || len(name) > MaxAssetNameSize {
		return AssetID{}, ErrInvalidAsset
	}
	var a AssetID
	copy(a.Policy[:], policy)
	a.Name = string(name)
	return a, nil
}

// ParseAssetID reads the text form <policy_hex>.<name_hex>, in lowercase.
func ParseAssetID(s string) (AssetID, error) {
	p, n, ok := strings.Cut(s, ".")
	if !ok || strings.ToLower(s) != s {
		return AssetID{}, ErrInvalidAsset
	}
	policy, err := hex.DecodeString(p)
	if err != nil {
		return AssetID{}, ErrInvalidAsset
	}
	name, err := hex.DecodeString(n)
	if err != nil {
		return AssetID{}, ErrInvalidAsset
	}
	return NewAssetID(policy, name)
}

// String returns the text form <policy_hex>.<name_hex>.
func (a AssetID) String() string {
	return hex.EncodeToString(a.Policy[:]) + "." + hex.EncodeToString([]byte(a.Name))
}

// Compare orders assets by policy and then by name, the fixed order used by
// input selection (section 8.2).
func (a AssetID) Compare(b AssetID) int {
	if c := bytes.Compare(a.Policy[:], b.Policy[:]); c != 0 {
		return c
	}
	return strings.Compare(a.Name, b.Name)
}

// Value is an amount of lovelace and native tokens. A nil Assets map is the
// same as an empty one.
type Value struct {
	Lovelace uint64
	Assets   map[AssetID]uint64
}

// Add returns v + w without modifying either, or ErrOverflow.
func (v Value) Add(w Value) (Value, error) {
	l, err := Add(v.Lovelace, w.Lovelace)
	if err != nil {
		return Value{}, err
	}
	out := Value{Lovelace: l}
	if len(v.Assets)+len(w.Assets) == 0 {
		return out, nil
	}
	out.Assets = make(map[AssetID]uint64, len(v.Assets)+len(w.Assets))
	for a, q := range v.Assets {
		out.Assets[a] = q
	}
	for a, q := range w.Assets {
		s, err := Add(out.Assets[a], q)
		if err != nil {
			return Value{}, fmt.Errorf("asset %s: %w", a, err)
		}
		out.Assets[a] = s
	}
	return out, nil
}

// HasAssets reports whether v carries any token with a non-zero quantity.
func (v Value) HasAssets() bool {
	for _, q := range v.Assets {
		if q != 0 {
			return true
		}
	}
	return false
}
