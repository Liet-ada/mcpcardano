// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package fidokit is a FIDO2 key in software, for tests only (decision 116):
// it creates a credential and signs assertions as a CTAP key does, with
// ES256 or EdDSA and its own counter, so that the wallet and the CLI are
// tested end to end without USB. Options make it misbehave on purpose.
package fidokit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
)

// The COSE algorithms and the relying party of the wallet's keys.
const (
	ES256 = -7
	EdDSA = -8
	RPID  = "mcpcardano"
)

// Flags of the authenticator data.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagAT = 0x40
	flagED = 0x80
)

// Key is one credential on a software key.
type Key struct {
	Alg int
	// Counter is the last counter given. Each assertion raises it first,
	// unless the key keeps none.
	Counter   uint32
	NoCounter bool

	id []byte
	ec *ecdsa.PrivateKey
	ed ed25519.PrivateKey
}

// New returns a key with a fresh credential of alg, ES256 or EdDSA.
func New(alg int) *Key {
	k := &Key{Alg: alg, id: make([]byte, 64)}
	rand.Read(k.id)
	switch alg {
	case ES256:
		k.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EdDSA:
		_, k.ed, _ = ed25519.GenerateKey(rand.Reader)
	default:
		panic("fidokit: unknown algorithm")
	}
	return k
}

// CredentialID returns the id of the credential.
func (k *Key) CredentialID() []byte { return bytes.Clone(k.id) }

// Options make the key misbehave: no touch, a PIN entered, a credential that
// may be synced, another relying party, or extensions after the data.
type Options struct {
	NoTouch    bool
	PIN        bool
	Synced     bool
	RPID       string // RPID if empty
	Extensions bool
}

// MakeCredential returns the authenticator data of a new credential, with
// its attested credential data, as makeCredential does. The attestation
// statement is left out: the wallet does not check it.
func (k *Key) MakeCredential(o Options) []byte {
	cose := map[int]any{3: k.Alg}
	switch k.Alg {
	case ES256:
		raw, _ := k.ec.PublicKey.Bytes()
		cose[1], cose[-1], cose[-2], cose[-3] = 2, 1, raw[1:33], raw[33:]
	case EdDSA:
		cose[1], cose[-1], cose[-2] = 1, 6, []byte(k.ed.Public().(ed25519.PublicKey))
	}
	c, _ := cborx.New(cborx.RecordLimits())
	pub, err := c.Marshal(cose)
	if err != nil {
		panic(err)
	}
	att := make([]byte, 16, 18+len(k.id)+len(pub)) // an AAGUID of zeros
	att = binary.BigEndian.AppendUint16(att, uint16(len(k.id)))
	att = append(append(att, k.id...), pub...)
	return k.authData(o, flagAT, att)
}

// Assertion is what a key returns for a challenge.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
}

// GetAssertion signs clientDataHash as getAssertion does: over the
// authenticator data followed by clientDataHash.
func (k *Key) GetAssertion(clientDataHash []byte, o Options) Assertion {
	if !k.NoCounter {
		k.Counter++
	}
	ad := k.authData(o, 0, nil)
	return Assertion{CredentialID: k.CredentialID(), AuthenticatorData: ad, Signature: k.Sign(append(bytes.Clone(ad), clientDataHash...))}
}

// Sign signs data with the credential's private key, for tests that build
// their own authenticator data.
func (k *Key) Sign(data []byte) []byte {
	if k.Alg == EdDSA {
		return ed25519.Sign(k.ed, data)
	}
	h := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, k.ec, h[:])
	if err != nil {
		panic(err)
	}
	return sig
}

func (k *Key) authData(o Options, flags byte, att []byte) []byte {
	rp := o.RPID
	if rp == "" {
		rp = RPID
	}
	h := sha256.Sum256([]byte(rp))
	flags |= flagUP
	if o.NoTouch {
		flags &^= flagUP
	}
	if o.PIN {
		flags |= flagUV
	}
	if o.Synced {
		flags |= flagBE
	}
	if o.Extensions {
		flags |= flagED
	}
	out := append(h[:], flags)
	out = binary.BigEndian.AppendUint32(out, k.Counter)
	out = append(out, att...)
	if o.Extensions {
		out = append(out, 0xa0) // an empty map of extensions
	}
	return out
}
