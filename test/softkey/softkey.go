// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package softkey is a security key in software behind fido.Key, for the
// tests of the CLI (decision 116): a fidokit credential with a PIN, which it
// checks as a key does, and a Slot to insert keys into. It is apart from
// fidokit so that the wallet's tests never import the CLI's fido.
package softkey

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/Liet-ada/mcpcardano/internal/fido"
	"github.com/Liet-ada/mcpcardano/test/fidokit"
)

// Key is a security key in software.
type Key struct {
	Credential    *fidokit.Key
	name          string
	PIN           string // empty if none is set
	Retries       int
	PINToRegister bool // registering takes the PIN
}

// New returns a key with an EdDSA credential and the PIN pin, if not empty.
func New(name, pin string) *Key {
	return &Key{Credential: fidokit.New(fidokit.EdDSA), name: name, PIN: pin, Retries: 8}
}

func (k *Key) Name() string { return k.name }
func (k *Key) Close() error { return nil }

func (k *Key) Info(context.Context) (fido.Info, error) {
	return fido.Info{PIN: k.PIN != "", Retries: k.Retries, PINToRegister: k.PINToRegister}, nil
}

func (k *Key) checkPIN(pin string) error {
	if pin != "" && pin != k.PIN {
		k.Retries--
		return errors.New("fido: soft key: the PIN was wrong")
	}
	return nil
}

func (k *Key) Register(_ context.Context, rpID, pin string) ([]byte, error) {
	if k.PINToRegister && pin == "" {
		return nil, errors.New("fido: soft key: a PIN is required and none was given")
	}
	if err := k.checkPIN(pin); err != nil {
		return nil, err
	}
	return k.Credential.MakeCredential(fidokit.Options{RPID: rpID}), nil
}

func (k *Key) Assert(_ context.Context, rpID string, cdh []byte, allow [][]byte, pin string) (fido.Assertion, error) {
	if !slices.ContainsFunc(allow, func(id []byte) bool { return bytes.Equal(id, k.Credential.CredentialID()) }) {
		return fido.Assertion{}, errors.New("fido: soft key: no credential the authenticator holds matches")
	}
	if err := k.checkPIN(pin); err != nil {
		return fido.Assertion{}, err
	}
	a := k.Credential.GetAssertion(cdh, fidokit.Options{RPID: rpID, PIN: pin != ""})
	return fido.Assertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, Signature: a.Signature}, nil
}

// Slot is the USB port: the keys inserted, opened one after another; the
// last stays. An empty slot has no key.
type Slot struct {
	mu       sync.Mutex
	inserted []*Key
}

// Insert puts keys in the slot, replacing what was there.
func (s *Slot) Insert(keys ...*Key) {
	s.mu.Lock()
	s.inserted = keys
	s.mu.Unlock()
}

// Open is a fido.Opener.
func (s *Slot) Open(context.Context) (fido.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inserted) == 0 {
		return nil, fido.ErrNoKey
	}
	k := s.inserted[0]
	if len(s.inserted) > 1 {
		s.inserted = s.inserted[1:]
	}
	return k, nil
}
