// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package model

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidAddress reports text that is not a payment address of the
// expected network.
var ErrInvalidAddress = errors.New("model: invalid address")

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// Bech32 returns the text form of a Shelley address (CIP-19): addr or stake,
// with _test on the test networks. Other addresses, such as Byron ones, come
// out in hex: no transaction the wallet signs pays them.
func (a Address) Bech32() string {
	if len(a.Raw) == 0 {
		return ""
	}
	typ := a.Raw[0] >> 4
	hrp := "addr"
	switch {
	case typ == 14 || typ == 15:
		hrp = "stake"
	case typ > 7:
		return hex.EncodeToString(a.Raw)
	}
	if a.Raw[0]&0x0f == 0 {
		hrp += "_test"
	}
	return Bech32(hrp, a.Raw)
}

// Bech32 encodes data as BIP-173 bech32, without the 90-character limit,
// which Cardano addresses exceed.
func Bech32(hrp string, data []byte) string {
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

// ParseAddress reads the bech32 text of a Shelley payment address of
// network n (CIP-19): base, pointer or enterprise, with the prefix addr on
// mainnet and addr_test on the test networks. Reward accounts and Byron
// addresses are not destinations of a payment here.
func ParseAddress(n Network, s string) (Address, error) {
	hrp, data, err := parseBech32(s)
	if err != nil {
		return Address{}, err
	}
	want := "addr"
	if n != Mainnet {
		want = "addr_test"
	}
	if hrp != want || len(data) == 0 || data[0]&0x0f != n.AddressID() {
		return Address{}, fmt.Errorf("%w: not an address of %s", ErrInvalidAddress, n)
	}
	switch typ, size := data[0]>>4, len(data); {
	case typ <= 3 && size == 57, typ >= 6 && typ <= 7 && size == 29, typ >= 4 && typ <= 5 && size > 29 && size <= 64:
		return Address{Raw: data}, nil
	}
	return Address{}, fmt.Errorf("%w: not a Shelley payment address", ErrInvalidAddress)
}

// parseBech32 decodes BIP-173 bech32 in lowercase, the only case of the
// charset, without the 90-character limit.
func parseBech32(s string) (string, []byte, error) {
	i := strings.LastIndexByte(s, '1')
	if i < 1 || len(s)-i-1 < 6 {
		return "", nil, fmt.Errorf("%w: not bech32", ErrInvalidAddress)
	}
	hrp, rest := s[:i], s[i+1:]
	values := make([]byte, len(rest))
	for j := range len(rest) {
		k := strings.IndexByte(charset, rest[j])
		if k < 0 {
			return "", nil, fmt.Errorf("%w: not bech32", ErrInvalidAddress)
		}
		values[j] = byte(k)
	}
	if polymod(append(hrpExpand(hrp), values...)) != 1 {
		return "", nil, fmt.Errorf("%w: wrong checksum", ErrInvalidAddress)
	}
	data, ok := fromFive(values[:len(values)-6])
	if !ok {
		return "", nil, fmt.Errorf("%w: not bech32", ErrInvalidAddress)
	}
	return hrp, data, nil
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

// fromFive regroups 5-bit values into bytes; the padding left over must be
// shorter than 5 bits and zero.
func fromFive(values []byte) ([]byte, bool) {
	var out []byte
	acc, bits := uint32(0), uint(0)
	for _, v := range values {
		acc = acc<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	return out, bits < 5 && acc&(1<<bits-1) == 0
}
