// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package chain

import (
	"errors"
	"fmt"
	"strings"

	"github.com/blinklabs-io/gouroboros/ledger/common"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

var (
	// ErrInvalidAddress reports text or bytes that are not a payment address
	// the project accepts.
	ErrInvalidAddress = errors.New("chain: invalid address")
	// ErrNetworkMismatch reports an address of another network.
	ErrNetworkMismatch = errors.New("chain: address of another network")
)

// ParseAddress reads a payment address in bech32 (section 4.1): lowercase,
// with the prefix of the wallet's network. Byron (base58), stake and other
// non-payment addresses are rejected.
func ParseAddress(n model.Network, s string) (model.Address, error) {
	if !n.Valid() {
		return model.Address{}, fmt.Errorf("chain: unknown network %q", n)
	}
	if s != strings.ToLower(s) {
		return model.Address{}, fmt.Errorf("%w: must be lowercase bech32", ErrInvalidAddress)
	}
	want, other := "addr_test1", "addr1"
	if n == model.Mainnet {
		want, other = other, want
	}
	switch {
	case strings.HasPrefix(s, want):
	case strings.HasPrefix(s, other):
		return model.Address{}, fmt.Errorf("%w: %s is not a %s address", ErrNetworkMismatch, s, n)
	default:
		return model.Address{}, fmt.Errorf("%w: must start with %q", ErrInvalidAddress, want)
	}
	a, err := common.NewAddress(s)
	if err != nil {
		return model.Address{}, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	m, err := fromLedger(a)
	if err != nil {
		return model.Address{}, err
	}
	if m.NetworkID != n.AddressID() {
		return model.Address{}, fmt.Errorf("%w: network id %d", ErrNetworkMismatch, m.NetworkID)
	}
	return m, nil
}

// AddressFromBytes reads a payment address in its binary form, as found in a
// transaction output.
func AddressFromBytes(raw []byte) (model.Address, error) {
	a, err := common.NewAddressFromBytes(raw)
	if err != nil {
		return model.Address{}, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	return fromLedger(a)
}

// FormatAddress returns the bech32 form of a Shelley payment address.
func FormatAddress(m model.Address) (string, error) {
	a, err := common.NewAddressFromBytes(m.Raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	if a.Type() > common.AddressTypeScriptNone {
		return "", fmt.Errorf("%w: not a Shelley payment address", ErrInvalidAddress)
	}
	return a.String(), nil
}

// fromLedger converts a payment address. Header types 0 to 7 are the Shelley
// payment addresses of CIP-19; Byron and reward addresses are not accepted.
func fromLedger(a common.Address) (model.Address, error) {
	if a.Type() > common.AddressTypeScriptNone {
		return model.Address{}, fmt.Errorf("%w: header type %d is not a payment address", ErrInvalidAddress, a.Type())
	}
	raw, err := a.Bytes()
	if err != nil {
		return model.Address{}, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	pay, ok := credential(a.PayloadPayload())
	if !ok {
		return model.Address{}, fmt.Errorf("%w: no payment credential", ErrInvalidAddress)
	}
	m := model.Address{Raw: raw, Type: a.Type(), NetworkID: uint8(a.NetworkId()), Payment: pay}
	if stake, ok := credential(a.StakingPayload()); ok {
		m.Stake = &stake
	}
	return m, nil
}

// credential reads a key or script hash payload. Pointers and absent
// payloads have no credential.
func credential(p common.AddressPayload) (model.Credential, bool) {
	switch p := p.(type) {
	case common.AddressPayloadKeyHash:
		return model.Credential{Kind: model.KeyHash, Hash: p.Hash}, true
	case common.AddressPayloadScriptHash:
		return model.Credential{Kind: model.ScriptHash, Hash: p.Hash}, true
	default:
		return model.Credential{}, false
	}
}
