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

func (k *key) Name() string { return k.k.Name() }

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
		t, err := k.token(ctx, pin, authn.PermMakeCredential, rpID)
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
	if pin != "" {
		t, err := k.token(ctx, pin, authn.PermGetAssertion, rpID)
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

// token turns the PIN into a token for one command on rpID, with the newest
// PIN protocol the key has.
func (k *key) token(ctx context.Context, pin string, perms authn.Permissions, rpID string) (authn.Token, error) {
	proto := authn.PINProtocolOne
	if slices.Contains(k.info.PINProtocols, uint(authn.PINProtocolTwo)) {
		proto = authn.PINProtocolTwo
	}
	return k.k.PINToken(ctx, pin, proto, perms, rpID)
}
