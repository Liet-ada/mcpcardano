// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package hdkey holds the wallet's keys (section 8.7 of the specification):
// the BIP-39 recovery phrase, the Icarus root key of CIP-3, BIP32-Ed25519
// derivation along the paths of CIP-1852, and Ed25519 signatures with
// extended keys. It is the project's only own cryptographic code, so it stays
// small; its tests hold it to published vectors and to crypto/ed25519.
//
// The wallet builds it with the purego tag, so that edwards25519 and
// golang.org/x/crypto use no assembly and nothing outside the standard
// library imports unsafe (section 2.4).
package hdkey

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Hardened marks a hardened derivation index.
const Hardened uint32 = 1 << 31

// The derivation paths of CIP-1852: m/1852'/1815'/account'/role/index.
const (
	purpose    = 1852 | Hardened
	coinType   = 1815 | Hardened
	rolePay    = 0
	roleStake  = 2
	icarusIter = 4096
)

// ErrEntropy reports entropy of a length BIP-39 does not allow.
var ErrEntropy = errors.New("hdkey: entropy must be 16 to 32 bytes, in steps of 4")

// XPrv is an extended private key of BIP32-Ed25519: the scalar kL, the key kR
// that makes the signature nonces, and the chain code. However it is printed
// or logged, it shows [REDACTED].
type XPrv struct {
	kl, kr, cc [32]byte
}

// Root derives the root key of a wallet from the entropy of its recovery
// phrase, with the Icarus method of CIP-3 and no passphrase.
func Root(entropy []byte) (*XPrv, error) {
	return icarus(entropy, nil)
}

// icarus is CIP-3's generateMasterKey: PBKDF2-HMAC-SHA512 of the passphrase
// with the entropy as salt, 4096 rounds, 96 bytes, and then the bits that
// Ed25519 and BIP32-Ed25519 require on kL.
func icarus(entropy, passphrase []byte) (*XPrv, error) {
	if n := len(entropy); n < 16 || n > 32 || n%4 != 0 {
		return nil, ErrEntropy
	}
	k, err := pbkdf2.Key(sha512.New, string(passphrase), entropy, icarusIter, 96)
	if err != nil {
		return nil, fmt.Errorf("hdkey: %w", err)
	}
	x := new(XPrv)
	copy(x.kl[:], k[:32])
	copy(x.kr[:], k[32:64])
	copy(x.cc[:], k[64:])
	clear(k)
	x.kl[0] &= 0b1111_1000
	x.kl[31] &= 0b0001_1111
	x.kl[31] |= 0b0100_0000
	return x, nil
}

// Child derives child i, hardened if i has the Hardened bit, with the
// derivation scheme V2 of BIP32-Ed25519 that Cardano uses:
//
//	Z  = HMAC-SHA512(cc, 0x00 || kL || kR || le32(i))   hardened
//	Z  = HMAC-SHA512(cc, 0x02 || A || le32(i))          soft, A = kL*B
//	kL' = kL + 8*Z[0:28],  kR' = kR + Z[32:64] mod 2^256
//	cc' = HMAC-SHA512(cc, 0x01 or 0x03 || ...)[32:64]
//
// The integers are little-endian. x is left unchanged.
func (x *XPrv) Child(i uint32) *XPrv {
	var idx [4]byte
	binary.LittleEndian.PutUint32(idx[:], i)
	z := hmac.New(sha512.New, x.cc[:])
	c := hmac.New(sha512.New, x.cc[:])
	if i >= Hardened {
		z.Write([]byte{0x00})
		z.Write(x.kl[:])
		z.Write(x.kr[:])
		c.Write([]byte{0x01})
		c.Write(x.kl[:])
		c.Write(x.kr[:])
	} else {
		a := x.PublicKey()
		z.Write([]byte{0x02})
		z.Write(a)
		c.Write([]byte{0x03})
		c.Write(a)
	}
	z.Write(idx[:])
	c.Write(idx[:])
	zs, cs := z.Sum(nil), c.Sum(nil)

	child := new(XPrv)
	var carry uint
	for n := range 32 {
		s := uint(x.kl[n]) + carry
		if n < 28 {
			s += uint(zs[n]) << 3
		}
		child.kl[n], carry = byte(s), s>>8
	}
	carry = 0
	for n := range 32 {
		s := uint(x.kr[n]) + uint(zs[32+n]) + carry
		child.kr[n], carry = byte(s), s>>8
	}
	copy(child.cc[:], cs[32:])
	clear(zs)
	clear(cs)
	return child
}

// Derive follows a path from x. x is left unchanged, and the keys in between
// are wiped.
func (x *XPrv) Derive(path ...uint32) *XPrv {
	k := &XPrv{kl: x.kl, kr: x.kr, cc: x.cc}
	for _, i := range path {
		next := k.Child(i)
		k.Wipe()
		k = next
	}
	return k
}

// scalar returns kL reduced modulo the group order. kL*B is the same point
// whether kL is reduced or not, because B has that order.
func scalar(kl *[32]byte) *edwards25519.Scalar {
	var wide [64]byte
	copy(wide[:], kl[:])
	s, err := edwards25519.NewScalar().SetUniformBytes(wide[:])
	clear(wide[:])
	if err != nil {
		panic(err) // the input is always 64 bytes
	}
	return s
}

// PublicKey returns the verification key A = kL*B.
func (x *XPrv) PublicKey() []byte {
	return new(edwards25519.Point).ScalarBaseMult(scalar(&x.kl)).Bytes()
}

// Sign signs msg with the extended key. It is RFC 8032 Ed25519 with kL as the
// secret scalar and kR as the prefix that makes the nonce:
//
//	r = SHA-512(kR || msg),  R = r*B,  S = r + SHA-512(R || A || msg)*kL
//
// so crypto/ed25519 verifies its signatures, and for a key expanded from an
// Ed25519 seed it gives the same signature as crypto/ed25519.
func (x *XPrv) Sign(msg []byte) []byte {
	a := x.PublicKey()
	var d [64]byte
	h := sha512.New()
	h.Write(x.kr[:])
	h.Write(msg)
	h.Sum(d[:0])
	r, err := edwards25519.NewScalar().SetUniformBytes(d[:])
	if err != nil {
		panic(err) // the input is always 64 bytes
	}
	rb := new(edwards25519.Point).ScalarBaseMult(r).Bytes()
	h.Reset()
	h.Write(rb)
	h.Write(a)
	h.Write(msg)
	h.Sum(d[:0])
	k, err := edwards25519.NewScalar().SetUniformBytes(d[:])
	if err != nil {
		panic(err)
	}
	clear(d[:])
	s := edwards25519.NewScalar().MultiplyAdd(k, scalar(&x.kl), r)
	return append(rb, s.Bytes()...)
}

// Wipe overwrites the key with zeros.
func (x *XPrv) Wipe() {
	clear(x.kl[:])
	clear(x.kr[:])
	clear(x.cc[:])
}

const redacted = "[REDACTED]"

// String implements fmt.Stringer.
func (XPrv) String() string { return redacted }

// GoString implements fmt.GoStringer.
func (XPrv) GoString() string { return redacted }

// Format implements fmt.Formatter, so that no verb prints the key.
func (XPrv) Format(f fmt.State, _ rune) { io.WriteString(f, redacted) }

// LogValue implements slog.LogValuer.
func (XPrv) LogValue() slog.Value { return slog.StringValue(redacted) }

// Keys are the keys of a wallet: account 0, address index 0 (section 3.2).
type Keys struct {
	Payment *XPrv // m/1852'/1815'/0'/0/0
	Stake   *XPrv // m/1852'/1815'/0'/2/0
}

// WalletKeys derives a wallet's keys from the entropy of its recovery phrase.
func WalletKeys(entropy []byte) (Keys, error) {
	root, err := Root(entropy)
	if err != nil {
		return Keys{}, err
	}
	account := root.Derive(purpose, coinType, 0|Hardened)
	root.Wipe()
	k := Keys{Payment: account.Derive(rolePay, 0), Stake: account.Derive(roleStake, 0)}
	account.Wipe()
	return k, nil
}

// Wipe overwrites both keys with zeros.
func (k Keys) Wipe() {
	k.Payment.Wipe()
	k.Stake.Wipe()
}

// KeyHashSize is the size of a key hash: BLAKE2b-224 of the verification key.
const KeyHashSize = 28

// KeyHash returns the hash of a verification key, which addresses and
// required signers carry.
func KeyHash(vkey []byte) [KeyHashSize]byte {
	h, err := blake2b.New(KeyHashSize, nil)
	if err != nil {
		panic(err) // a constant size
	}
	h.Write(vkey)
	var out [KeyHashSize]byte
	h.Sum(out[:0])
	return out
}

// BaseAddress returns the base address (CIP-19 type 0) of a payment and a
// stake verification key on network n.
func BaseAddress(n model.Network, payment, stake []byte) model.Address {
	pay, stk := KeyHash(payment), KeyHash(stake)
	raw := make([]byte, 0, 1+2*KeyHashSize)
	raw = append(raw, n.AddressID())
	raw = append(raw, pay[:]...)
	raw = append(raw, stk[:]...)
	return model.Address{
		Raw:       raw,
		Type:      0,
		NetworkID: n.AddressID(),
		Payment:   model.Credential{Kind: model.KeyHash, Hash: pay},
		Stake:     &model.Credential{Kind: model.KeyHash, Hash: stk},
	}
}
