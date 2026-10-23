// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package authz

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/test/fidokit"
)

// register creates a credential on a software key and reads it as the
// wallet does.
func register(t testing.TB, a *Authorizer, alg int) (*fidokit.Key, Key) {
	t.Helper()
	sk := fidokit.New(alg)
	k, err := a.Credential(sk.MakeCredential(fidokit.Options{}), Rules{})
	if err != nil {
		t.Fatal(err)
	}
	return sk, k
}

func assertion(f fidokit.Assertion) Assertion {
	return Assertion{CredentialID: f.CredentialID, AuthenticatorData: f.AuthenticatorData, Signature: f.Signature}
}

func hash(msg []byte) []byte {
	h := sha256.Sum256(msg)
	return h[:]
}

// TestVerify has one case per rule of an assertion (section 6.2, step 5):
// the credential, the RP id, the touch, the PIN, a credential that may be
// synced, the signature over this message, and the counter.
func TestVerify(t *testing.T) {
	a, _ := newAuthorizer()
	msg := []byte("the canonical message")
	for _, alg := range []int{AlgES256, AlgEdDSA} {
		sk, k := register(t, a, alg)
		other, _ := register(t, a, alg)
		sign := func(o fidokit.Options) Assertion { return assertion(sk.GetAssertion(hash(msg), o)) }
		for _, tc := range []struct {
			name  string
			a     func() Assertion
			rules Rules
			want  error
		}{
			{"a touch", func() Assertion { return sign(fidokit.Options{}) }, Rules{}, nil},
			{"a touch and the PIN", func() Assertion { return sign(fidokit.Options{PIN: true}) }, Rules{PIN: true}, nil},
			{"another credential", func() Assertion { return assertion(other.GetAssertion(hash(msg), fidokit.Options{})) }, Rules{}, ErrKeyUnknown},
			{"another relying party", func() Assertion { return sign(fidokit.Options{RPID: "example.com"}) }, Rules{}, ErrKeyRPID},
			{"no touch", func() Assertion { return sign(fidokit.Options{NoTouch: true}) }, Rules{}, ErrKeyPresence},
			{"no PIN where the action needs it", func() Assertion { return sign(fidokit.Options{}) }, Rules{PIN: true}, ErrKeyPIN},
			{"a credential that may be synced", func() Assertion { return sign(fidokit.Options{Synced: true}) }, Rules{}, ErrKeySynced},
			{"a synced credential the person allowed", func() Assertion { return sign(fidokit.Options{Synced: true}) }, Rules{AllowSynced: true}, nil},
			{"extensions", func() Assertion { return sign(fidokit.Options{Extensions: true}) }, Rules{}, ErrKeyData},
			{"the flag of a new credential, signed", func() Assertion {
				s := sign(fidokit.Options{})
				s.AuthenticatorData[32] |= flagAT
				s.Signature = sk.Sign(append(bytes.Clone(s.AuthenticatorData), hash(msg)...))
				return s
			}, Rules{}, ErrKeyData},
			{"short authenticator data", func() Assertion {
				s := sign(fidokit.Options{})
				s.AuthenticatorData = s.AuthenticatorData[:36]
				return s
			}, Rules{}, ErrKeyData},
			{"a signature over another message", func() Assertion {
				return assertion(sk.GetAssertion(hash([]byte("another message")), fidokit.Options{}))
			}, Rules{}, ErrKeySignature},
			{"the PIN flag set after signing", func() Assertion {
				s := sign(fidokit.Options{})
				s.AuthenticatorData[32] |= flagUV
				return s
			}, Rules{PIN: true}, ErrKeySignature},
			{"no signature", func() Assertion { s := sign(fidokit.Options{}); s.Signature = nil; return s }, Rules{}, ErrKeySignature},
		} {
			_, err := Verify(k, msg, tc.a(), tc.rules)
			if !errors.Is(err, tc.want) {
				t.Errorf("alg %d, %s: %v, want %v", alg, tc.name, err, tc.want)
			}
		}
	}
}

// TestCounter: a key that keeps a counter must give more each time, or it
// may be a clone; one that keeps none gives 0 every time.
func TestCounter(t *testing.T) {
	a, _ := newAuthorizer()
	msg := []byte("m")
	sk, k := register(t, a, AlgES256)
	first := assertion(sk.GetAssertion(hash(msg), fidokit.Options{}))
	n, err := Verify(k, msg, first, Rules{})
	if err != nil || n != 1 {
		t.Fatalf("first: %d, %v", n, err)
	}
	k.Counter = n
	if _, err := Verify(k, msg, first, Rules{}); !errors.Is(err, ErrKeyCounter) {
		t.Errorf("the same counter again: %v", err)
	}
	sk.Counter = 0 // a clone that starts over gives 1 again
	if _, err := Verify(k, msg, assertion(sk.GetAssertion(hash(msg), fidokit.Options{})), Rules{}); !errors.Is(err, ErrKeyCounter) {
		t.Errorf("a clone: %v", err)
	}
	sk.NoCounter, sk.Counter = true, 0
	if _, err := Verify(k, msg, assertion(sk.GetAssertion(hash(msg), fidokit.Options{})), Rules{}); !errors.Is(err, ErrKeyCounter) {
		t.Errorf("a counter of 0 after 1: %v", err)
	}

	// A key with one counter for all its credentials gives it already when
	// it creates one; the first assertion gives more.
	global := fidokit.New(AlgEdDSA)
	global.Counter = 41
	kg, _ := a.Credential(global.MakeCredential(fidokit.Options{}), Rules{})
	if n, err := Verify(kg, msg, assertion(global.GetAssertion(hash(msg), fidokit.Options{})), Rules{}); kg.Counter != 41 || err != nil || n != 42 {
		t.Errorf("a counter at registration: %d, then %d, %v", kg.Counter, n, err)
	}

	none := fidokit.New(AlgEdDSA)
	none.NoCounter = true
	kn, _ := a.Credential(none.MakeCredential(fidokit.Options{}), Rules{})
	for range 2 {
		if n, err := Verify(kn, msg, assertion(none.GetAssertion(hash(msg), fidokit.Options{})), Rules{}); err != nil || n != 0 {
			t.Errorf("a key without a counter: %d, %v", n, err)
		}
	}
}

// TestKeyChallengeOnce: an assertion completes its challenge once; replayed,
// or after the challenge expired, it gives ErrExpired.
func TestKeyChallengeOnce(t *testing.T) {
	a, c := newAuthorizer()
	sk, k := register(t, a, AlgEdDSA)
	byKey := func(as Assertion) func(*Authorization) error {
		return func(au *Authorization) error {
			n, err := Verify(k, au.Message, as, Rules{})
			k.Counter = max(k.Counter, n)
			return err
		}
	}
	au, _ := a.Begin("unfreeze", wallet, nil, nil)
	as := assertion(sk.GetAssertion(hash(au.Message), fidokit.Options{}))
	if _, err := a.Complete(au.ID, byKey(as)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Complete(au.ID, byKey(as)); !errors.Is(err, ErrExpired) {
		t.Errorf("replayed: %v", err)
	}
	// An assertion for one challenge does not complete another.
	other, _ := a.Begin("unfreeze", wallet, nil, nil)
	if _, err := a.Complete(other.ID, byKey(assertion(sk.GetAssertion(hash(au.Message), fidokit.Options{})))); !errors.Is(err, ErrKeySignature) {
		t.Errorf("another challenge's message: %v", err)
	}
	c.advance(DefaultTTL)
	if _, err := a.Complete(other.ID, byKey(assertion(sk.GetAssertion(hash(other.Message), fidokit.Options{})))); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: %v", err)
	}
}

// TestCredential reads new credentials: both algorithms, and the rules and
// the shapes it refuses.
func TestCredential(t *testing.T) {
	a, _ := newAuthorizer()
	for _, alg := range []int{AlgES256, AlgEdDSA} {
		sk := fidokit.New(alg)
		k, err := a.Credential(sk.MakeCredential(fidokit.Options{}), Rules{})
		if err != nil || k.Alg != alg || !bytes.Equal(k.CredentialID, sk.CredentialID()) {
			t.Fatalf("alg %d: %+v, %v", alg, k, err)
		}
		if _, err := Verify(k, []byte("m"), assertion(sk.GetAssertion(hash([]byte("m")), fidokit.Options{})), Rules{}); err != nil {
			t.Errorf("alg %d: the registered key does not verify: %v", alg, err)
		}
	}

	sk := fidokit.New(AlgES256)
	good := sk.MakeCredential(fidokit.Options{})
	cose, _ := cborx.New(cborx.RecordLimits())
	withKey := func(m map[int]any) []byte {
		pub, _ := cose.Marshal(m)
		n := binary.BigEndian.Uint16(good[authDataSize+16:])
		return append(bytes.Clone(good[:authDataSize+18+int(n)]), pub...)
	}
	x := bytes.Repeat([]byte{1}, 32)
	ed := func(h string) []byte {
		x, _ := hex.DecodeString(h)
		return withKey(map[int]any{1: 1, 3: -8, -1: 6, -2: x})
	}
	for _, tc := range []struct {
		name string
		data []byte
		r    Rules
		want error
	}{
		{"no attested credential", good[:authDataSize], Rules{}, ErrKeyData},
		{"another relying party", sk.MakeCredential(fidokit.Options{RPID: "example.com"}), Rules{}, ErrKeyRPID},
		{"no touch", sk.MakeCredential(fidokit.Options{NoTouch: true}), Rules{}, ErrKeyPresence},
		{"a credential that may be synced", sk.MakeCredential(fidokit.Options{Synced: true}), Rules{}, ErrKeySynced},
		{"extensions", sk.MakeCredential(fidokit.Options{Extensions: true}), Rules{}, ErrKeyData},
		{"bytes after the public key", append(bytes.Clone(good), 0x00), Rules{}, ErrKeyData},
		{"a credential id longer than the data", func() []byte {
			d := bytes.Clone(good)
			binary.BigEndian.PutUint16(d[authDataSize+16:], 0xffff)
			return d
		}(), Rules{}, ErrKeyData},
		{"an empty credential id", func() []byte {
			d := bytes.Clone(good[:authDataSize+16])
			return append(d, 0, 0)
		}(), Rules{}, ErrKeyData},
		{"a point off the curve", withKey(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: x}), Rules{}, ErrKeyData},
		{"RS256", withKey(map[int]any{1: 3, 3: -257, -1: []byte{1}, -2: []byte{1}}), Rules{}, ErrKeyData},
		{"EdDSA on another curve", withKey(map[int]any{1: 1, 3: -8, -1: 7, -2: x}), Rules{}, ErrKeyData},
		{"an unknown parameter", withKey(map[int]any{1: 1, 3: -8, -1: 6, -2: x, -4: x}), Rules{}, ErrKeyData},
		// Ed25519 keys of small order verify the identity with S = 0 for
		// any message; an encoding of y at or above p is not canonical.
		{"EdDSA, the identity", ed("0100000000000000000000000000000000000000000000000000000000000000"), Rules{}, ErrKeyData},
		{"EdDSA, a point of order 2", ed("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), Rules{}, ErrKeyData},
		{"EdDSA, a point of order 4", ed("0000000000000000000000000000000000000000000000000000000000000000"), Rules{}, ErrKeyData},
		{"EdDSA, a point of order 8", ed("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), Rules{}, ErrKeyData},
		{"EdDSA, the identity with y = 1 + p", ed("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), Rules{}, ErrKeyData},
		{"EdDSA, a point of large order with y = 3 + p", ed("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), Rules{}, ErrKeyData},
		{"EdDSA, off the curve", ed("0200000000000000000000000000000000000000000000000000000000000000"), Rules{}, ErrKeyData},
		{"EdDSA, 31 bytes", ed("01000000000000000000000000000000000000000000000000000000000000"), Rules{}, ErrKeyData},
	} {
		if _, err := a.Credential(tc.data, tc.r); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// The PIN is not asked of the new key.
	if _, err := a.Credential(good, Rules{PIN: true}); err != nil {
		t.Errorf("the rule of the PIN applied to the new key: %v", err)
	}
	if _, err := a.Credential(sk.MakeCredential(fidokit.Options{Synced: true}), Rules{AllowSynced: true}); err != nil {
		t.Errorf("a synced credential the person allowed: %v", err)
	}
}

// FuzzAssertion feeds Verify arbitrary authenticator data and signatures.
// Nothing may panic, and nothing but the key's own signature may pass.
func FuzzAssertion(f *testing.F) {
	a := New("preprod")
	sk, k := register(f, a, AlgES256)
	msg := []byte("m")
	good := sk.GetAssertion(hash(msg), fidokit.Options{PIN: true})
	f.Add(good.AuthenticatorData, good.Signature)
	f.Add(good.AuthenticatorData[:authDataSize-1], []byte{})
	f.Fuzz(func(t *testing.T, data, sig []byte) {
		_, err := Verify(k, msg, Assertion{CredentialID: k.CredentialID, AuthenticatorData: data, Signature: sig}, Rules{PIN: true})
		if err == nil && !(bytes.Equal(data, good.AuthenticatorData) && bytes.Equal(sig, good.Signature)) {
			t.Fatalf("a forged assertion passed: %x %x", data, sig)
		}
	})
}

// FuzzCredential feeds Credential arbitrary authenticator data. Nothing may
// panic, and what it accepts is a key it can verify with.
func FuzzCredential(f *testing.F) {
	a := New("preprod")
	for _, alg := range []int{AlgES256, AlgEdDSA} {
		f.Add(fidokit.New(alg).MakeCredential(fidokit.Options{}))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := a.Credential(data, Rules{})
		if err != nil {
			return
		}
		switch {
		case len(k.CredentialID) == 0 || len(k.CredentialID) > MaxCredentialID:
			t.Fatalf("credential id of %d bytes", len(k.CredentialID))
		case k.Alg == AlgEdDSA && len(k.PublicKey) != 32, k.Alg == AlgES256 && len(k.PublicKey) != 65,
			k.Alg != AlgEdDSA && k.Alg != AlgES256:
			t.Fatalf("key %d of %d bytes", k.Alg, len(k.PublicKey))
		}
	})
}
