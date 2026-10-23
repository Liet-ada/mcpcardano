// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package authz

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// The FIDO2 key (section 6.3 and paper, section 6.6). The CLI talks CTAP to
// the key; the wallet only reads what the key returns and checks it with the
// standard library. The key signs its authenticator data followed by the
// clientDataHash, which is the SHA-256 of the canonical message, so a
// signature covers exactly the message the wallet built and keeps.

// RPID is the relying party of every credential: a CTAP identifier that is
// not a domain, as OpenSSH uses "ssh:".
const RPID = "mcpcardano"

// The algorithms of a key, by their COSE numbers: EdDSA if the key has it,
// ES256 otherwise.
const (
	AlgES256 = -7
	AlgEdDSA = -8
)

// Limits of what a key returns. A credential id has at most 1023 bytes
// (WebAuthn, section 5.8.3); an ES256 signature in DER has at most 72.
const (
	MaxCredentialID = 1023
	MaxAuthData     = 2048
	MaxSignature    = 128
)

// The authenticator data (WebAuthn, section 6.1): the SHA-256 of the RP id,
// the flags and the counter, then the attested credential data when a
// credential is created.
const (
	authDataSize = 32 + 1 + 4
	flagUP       = 0x01 // user present: the touch
	flagUV       = 0x04 // user verified: the PIN
	flagBE       = 0x08 // backup eligible: the credential may be synced
	flagAT       = 0x40 // attested credential data follows
	flagED       = 0x80 // extensions follow
)

// The reasons an assertion or a new credential is refused. IsKeyError tells
// them from other errors.
var (
	ErrKeyUnknown   error = keyError("the key is not registered")
	ErrKeyData      error = keyError("malformed authenticator data")
	ErrKeyRPID      error = keyError("the key signed for another relying party")
	ErrKeyPresence  error = keyError("the key was not touched")
	ErrKeyPIN       error = keyError("the action needs the key's PIN")
	ErrKeySynced    error = keyError("the credential may be synced to a cloud")
	ErrKeySignature error = keyError("the key's signature does not verify")
	ErrKeyCounter   error = keyError("the key's counter did not grow")
)

type keyError string

func (e keyError) Error() string { return "authz: " + string(e) }

// IsKeyError reports whether err is a refused assertion or credential.
func IsKeyError(err error) bool {
	var k keyError
	return errors.As(err, &k)
}

// Key is a registered key, as the wallet keeps it: all of it public.
type Key struct {
	CredentialID []byte
	Alg          int
	// PublicKey is the uncompressed point for ES256, 65 bytes, and the
	// Ed25519 key for EdDSA, 32 bytes.
	PublicKey []byte
	// Counter is the last counter the key gave; 0 if it keeps none.
	Counter uint32
}

// Assertion is what the key returns for a challenge.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
}

// Rules are what a verification demands besides the touch.
type Rules struct {
	PIN         bool // the action needs the key's PIN (user verification)
	AllowSynced bool // the person allowed credentials that may be synced
}

// KeyID names a key briefly: the first 8 bytes of the SHA-256 of its
// credential id, in hex. The person uses it to tell keys apart.
func KeyID(credentialID []byte) string {
	h := sha256.Sum256(credentialID)
	return hex.EncodeToString(h[:8])
}

// authData is the fixed part of the authenticator data, already checked
// against the rules.
type authData struct {
	flags   byte
	counter uint32
	rest    []byte // the attested credential data, if any
}

// readAuthData reads the authenticator data and applies the rules that need
// no signature: the RP id, no extensions, the touch, the PIN if the action
// needs it, and a credential that cannot be synced unless the person allowed
// it (paper, section 6.6).
func readAuthData(b []byte, r Rules) (authData, error) {
	if len(b) < authDataSize || len(b) > MaxAuthData {
		return authData{}, ErrKeyData
	}
	rp := sha256.Sum256([]byte(RPID))
	if !bytes.Equal(b[:32], rp[:]) {
		return authData{}, ErrKeyRPID
	}
	a := authData{flags: b[32], counter: binary.BigEndian.Uint32(b[33:37]), rest: b[authDataSize:]}
	switch {
	case a.flags&flagED != 0: // the CLI asks for no extension
		return authData{}, ErrKeyData
	case a.flags&flagUP == 0:
		return authData{}, ErrKeyPresence
	case r.PIN && a.flags&flagUV == 0:
		return authData{}, ErrKeyPIN
	case !r.AllowSynced && a.flags&flagBE != 0:
		return authData{}, ErrKeySynced
	}
	return a, nil
}

// Verify checks an assertion of k over the canonical message msg (section
// 6.2, step 5) and returns the key's new counter. The rules without a
// signature come first, then the signature over the authenticator data and
// the SHA-256 of msg, and the counter last, so that only a signed counter
// counts. A key that keeps no counter gives 0 every time; one that keeps it
// must give more than last time, or it may be a clone.
func Verify(k Key, msg []byte, a Assertion, r Rules) (uint32, error) {
	if !bytes.Equal(a.CredentialID, k.CredentialID) {
		return 0, ErrKeyUnknown
	}
	ad, err := readAuthData(a.AuthenticatorData, r)
	if err != nil {
		return 0, err
	}
	if len(ad.rest) != 0 {
		return 0, ErrKeyData
	}
	h := sha256.Sum256(msg)
	signed := append(bytes.Clone(a.AuthenticatorData), h[:]...)
	if !verifySignature(k, signed, a.Signature) {
		return 0, ErrKeySignature
	}
	if (ad.counter != 0 || k.Counter != 0) && ad.counter <= k.Counter {
		return 0, fmt.Errorf("%w: %d after %d", ErrKeyCounter, ad.counter, k.Counter)
	}
	return ad.counter, nil
}

func verifySignature(k Key, signed, sig []byte) bool {
	switch k.Alg {
	case AlgEdDSA:
		return len(k.PublicKey) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(k.PublicKey), signed, sig)
	case AlgES256:
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), k.PublicKey)
		if err != nil {
			return false
		}
		h := sha256.Sum256(signed)
		return ecdsa.VerifyASN1(pub, h[:], sig)
	}
	return false
}

// coseKey is a public key in COSE (RFC 9053): an OKP Ed25519 key or an EC2
// P-256 key, with no other parameter.
type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint,omitempty"`
}

// The COSE values of the two keys.
const (
	ktyOKP     = 1
	ktyEC2     = 2
	crvP256    = 1
	crvEd25519 = 6
)

// Credential reads a new credential from the authenticator data the key
// returns when it creates one (makeCredential), under the same rules as an
// assertion: the RP id, the touch, and a credential that cannot be synced
// unless the person allowed it. The attestation is not checked (decision
// 123): any brand of key will do, and the authorization of add_key covers
// exactly the credential read here.
func (a *Authorizer) Credential(authenticatorData []byte, r Rules) (Key, error) {
	r.PIN = false // the PIN is for the key that authorizes, not the new one
	ad, err := readAuthData(authenticatorData, r)
	if err != nil {
		return Key{}, err
	}
	// AAGUID (16 bytes), the length of the credential id (2), the id, and
	// the public key, which ends the data since there are no extensions.
	rest := ad.rest
	if ad.flags&flagAT == 0 || len(rest) < 18 {
		return Key{}, ErrKeyData
	}
	n := int(binary.BigEndian.Uint16(rest[16:18]))
	if n == 0 || n > MaxCredentialID || len(rest) < 18+n {
		return Key{}, ErrKeyData
	}
	id, raw := rest[18:18+n], rest[18+n:]
	var c coseKey
	if err := a.codec.Unmarshal(raw, &c); err != nil {
		return Key{}, fmt.Errorf("%w: public key: %v", ErrKeyData, err)
	}
	k := Key{CredentialID: bytes.Clone(id), Alg: c.Alg, Counter: ad.counter}
	switch {
	case c.Kty == ktyOKP && c.Alg == AlgEdDSA && c.Crv == crvEd25519 && len(c.X) == ed25519.PublicKeySize && c.Y == nil:
		k.PublicKey = bytes.Clone(c.X)
	case c.Kty == ktyEC2 && c.Alg == AlgES256 && c.Crv == crvP256 && len(c.X) == 32 && len(c.Y) == 32:
		k.PublicKey = append(append([]byte{0x04}, c.X...), c.Y...)
		if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), k.PublicKey); err != nil {
			return Key{}, fmt.Errorf("%w: public key: %v", ErrKeyData, err)
		}
	default:
		return Key{}, fmt.Errorf("%w: a public key that is neither EdDSA nor ES256", ErrKeyData)
	}
	return k, nil
}
