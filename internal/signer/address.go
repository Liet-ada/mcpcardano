// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package signer

import (
	"errors"
	"fmt"
	"strings"

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
	return bech32(hrp, raw), nil
}

func keyHash(vkey []byte) []byte {
	h, _ := blake2b.New(28, nil)
	h.Write(vkey)
	return h.Sum(nil)
}

// bech32 encodes data as BIP-173 bech32, without the 90-character limit,
// which Cardano addresses exceed.
func bech32(hrp string, data []byte) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	five := convertBits(data)
	values := append(hrpExpand(hrp), five...)
	mod := polymod(append(values, 0, 0, 0, 0, 0, 0)) ^ 1
	var b strings.Builder
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, v := range five {
		b.WriteByte(charset[v])
	}
	for i := range 6 {
		b.WriteByte(charset[(mod>>(5*(5-i)))&31])
	}
	return b.String()
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, 2*len(hrp)+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func polymod(values []byte) uint32 {
	gen := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range 5 {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// convertBits regroups bytes into 5-bit values, padding the last one.
func convertBits(data []byte) []byte {
	var out []byte
	acc, bits := uint32(0), uint(0)
	for _, b := range data {
		acc = acc<<8 | uint32(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, byte(acc>>bits)&31)
		}
	}
	if bits > 0 {
		out = append(out, byte(acc<<(5-bits))&31)
	}
	return out
}
