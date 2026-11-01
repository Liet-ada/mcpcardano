// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package fido talks to a FIDO2 security key for the CLI (decision 124): it
// creates a credential for the wallet and signs the clientDataHash the wallet
// gives, with the key's PIN when the action needs it. It is the only package
// that imports the FIDO2 libraries, behind Key, so the tests drive a key in
// software and a library can be replaced alone. The wallet checks everything
// a key returns (decision 123): nothing here is trusted, and a fault here can
// stop an authorization but not forge one.
package fido

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	authn "github.com/go-authn/fido"
)

// Key is an attached security key.
type Key interface {
	// Name is what the key calls itself.
	Name() string
	// Info says whether the key has a PIN, how many tries it has left, and
	// whether creating a credential needs the PIN.
	Info(ctx context.Context) (Info, error)
	// Register creates a credential for rpID, not discoverable, EdDSA if the
	// key has it and ES256 otherwise, after a touch, and returns the
	// authenticator data. pin is empty unless Info says registering needs it.
	Register(ctx context.Context, rpID, pin string) ([]byte, error)
	// Assert signs clientDataHash with one of the credentials in allow, after
	// a touch; with a pin, the key also checks it.
	Assert(ctx context.Context, rpID string, clientDataHash []byte, allow [][]byte, pin string) (Assertion, error)
	Close() error
}

// Info is what a key says about its PIN.
type Info struct {
	PIN           bool // a PIN is set
	Retries       int  // PIN tries left before the key locks
	PINToRegister bool // creating a credential needs the PIN
}

// Assertion is what a key returns for a challenge.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
}

// An Opener opens the attached key; Open is the real one.
type Opener func(ctx context.Context) (Key, error)

// ErrNoKey reports that no security key is attached.
var ErrNoKey = errors.New("fido: no security key is attached")

// ErrNotRegistered reports a key that holds none of the registered
// credentials: any FIDO2 device may be the first attached, a Trezor too.
var ErrNotRegistered = errors.New("not a registered key: connect the one you registered")

// The COSE algorithms a credential may use, the preferred first.
var algorithms = []int64{-8, -7} // EdDSA, ES256

// Open opens the first security key attached, through this system's
// transport, and asks it what it can do.
func Open(ctx context.Context) (Key, error) {
	t, err := transport()
	if err != nil {
		return nil, err
	}
	k, err := authn.Open(ctx, t)
	if err != nil {
		return nil, err
	}
	info, err := k.GetInfo(ctx)
	if err != nil {
		k.Close()
		return nil, err
	}
	return &key{k: k, info: info}, nil
}

// key is a security key behind go-authn/fido.
type key struct {
	k    *authn.Key
	info authn.Info
}

// Name is what the key calls itself, with only its visible characters: the
// device chooses it, and it reaches the person's terminal.
func (k *key) Name() string { return visible(k.k.Name()) }

// visible keeps the letters, marks, numbers, punctuation, symbols and spaces
// of s, at most 64 bytes, and puts "?" for anything else, such as the escape
// sequences a hostile device could put in its name.
func visible(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != ' ' && (!unicode.IsGraphic(r) || unicode.IsSpace(r)) {
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > 64 {
			break
		}
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return "the security key"
	}
	return b.String()
}

func (k *key) Close() error { return k.k.Close() }

func (k *key) Info(ctx context.Context) (Info, error) {
	i := Info{PIN: k.info.Has("clientPin")}
	if !i.PIN {
		return i, nil
	}
	// CTAP 2.1: with a PIN set, makeCredential needs it unless the key says
	// a credential that is not discoverable does not.
	i.PINToRegister = !k.info.Has("makeCredUvNotRqd")
	r, err := k.k.PINRetries(ctx)
	if err != nil {
		return Info{}, err
	}
	i.Retries = r.PIN
	return i, nil
}

func (k *key) Register(ctx context.Context, rpID, pin string) ([]byte, error) {
	// The wallet does not check the attestation (decision 123), so what the
	// key signs at registration does not matter; the user handle only has to
	// be unique.
	cdh, user := make([]byte, 32), make([]byte, 16)
	rand.Read(cdh)
	rand.Read(user)
	r := authn.MakeCredentialRequest{
		ClientDataHash: cdh,
		RP:             authn.RelyingParty{ID: rpID, Name: rpID},
		User:           authn.User{ID: user, Name: rpID, DisplayName: rpID},
		Algorithms:     algorithms,
		Options:        map[string]bool{"rk": false},
	}
	if pin != "" {
		t, err := k.token(ctx, pin)
		if err != nil {
			return nil, err
		}
		r.Token = t
	}
	att, err := k.k.MakeCredential(ctx, r)
	if err != nil {
		return nil, err
	}
	return att.AuthData, nil
}

func (k *key) Assert(ctx context.Context, rpID string, clientDataHash []byte, allow [][]byte, pin string) (Assertion, error) {
	r := authn.GetAssertionRequest{RPID: rpID, ClientDataHash: clientDataHash}
	for _, id := range allow {
		r.Allow = append(r.Allow, authn.Credential{Type: "public-key", ID: id})
	}
	if err := k.holds(ctx, r); err != nil {
		return Assertion{}, err
	}
	if pin != "" {
		t, err := k.token(ctx, pin)
		if err != nil {
			return Assertion{}, err
		}
		r.Token = t
	}
	a, err := k.k.GetAssertion(ctx, r)
	if err != nil {
		return Assertion{}, err
	}
	// A key asked for exactly one credential may leave out which answered.
	id := a.Credential.ID
	if id == nil && len(allow) == 1 {
		id = allow[0]
	}
	if id == nil {
		return Assertion{}, fmt.Errorf("fido: %s did not say which credential answered", k.Name())
	}
	return Assertion{CredentialID: id, AuthenticatorData: a.AuthData, Signature: a.Signature}, nil
}

// holds asks the key whether it has one of the credentials of r, with no
// touch and no PIN, before the PIN goes to it. Only a plain no counts: a key
// that cannot say goes on, and answers the assertion itself. This spares a
// mistake, not an attack: a hostile device could say yes.
func (k *key) holds(ctx context.Context, r authn.GetAssertionRequest) error {
	r.Options = map[string]bool{"up": false}
	_, err := k.k.GetAssertion(ctx, r)
	if err != nil && strings.Contains(err.Error(), noCredentials) {
		return fmt.Errorf("%s is %w", k.Name(), ErrNotRegistered)
	}
	return nil
}

// noCredentials is how go-authn/fido writes CTAP2_ERR_NO_CREDENTIALS: it has
// no error to compare with.
var noCredentials = authn.Status(0x2e).String()

// token turns the PIN into a token, with the newest PIN protocol the key
// has. It asks with getPinToken, the exchange of CTAP 2.0, which a key of
// CTAP 2.1 still answers with a token for creating credentials and signing
// assertions. go-authn/fido v0.6.2 sends the permissions and the RP id of
// the CTAP 2.1 exchange under the keys 0x07 and 0x08, where the
// specification and libfido2 have 0x09 and 0x0A, and a YubiKey refuses it
// with CTAP2_ERR_MISSING_PARAMETER (found in E5).
func (k *key) token(ctx context.Context, pin string) (authn.Token, error) {
	if k.info.Has("noMcGaPermissionsWithClientPin") {
		return authn.Token{}, fmt.Errorf("fido: %s takes the PIN only with permissions, which this version cannot ask for", k.Name())
	}
	proto := authn.PINProtocolOne
	if slices.Contains(k.info.PINProtocols, uint(authn.PINProtocolTwo)) {
		proto = authn.PINProtocolTwo
	}
	return k.k.PINToken(ctx, pin, proto, 0, "")
}
