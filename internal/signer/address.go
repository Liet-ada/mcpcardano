// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package signer

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The derivation paths of the wallet's single address (section 3.2): account
// 0, external chain, index 0, and the account's stake key (CIP-1852).
const (
	PaymentPath = "1852H/1815H/0H/0/0"
	StakePath   = "1852H/1815H/0H/2/0"
)

// BaseAddress returns the bech32 base address of a payment and a stake
// verification key (CIP-19, header type 0: key and key).
func BaseAddress(n model.Network, payment, stake []byte) (string, error) {
	if len(payment) != 32 || len(stake) != 32 {
		return "", errors.New("signer: verification keys must be 32 bytes")
	}
	if !n.Valid() {
		return "", fmt.Errorf("signer: unknown network %q", n)
	}
	raw := []byte{0x00 | n.AddressID()}
	raw = append(raw, keyHash(payment)...)
	raw = append(raw, keyHash(stake)...)
	hrp := "addr_test"
	if n == model.Mainnet {
		hrp = "addr"
	}
	return model.Bech32(hrp, raw), nil
}

func keyHash(vkey []byte) []byte {
	h, _ := blake2b.New(28, nil)
	h.Write(vkey)
	return h.Sum(nil)
}
