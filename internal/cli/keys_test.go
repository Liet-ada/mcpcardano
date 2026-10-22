// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/fido"
	"github.com/Liet-ada/mcpcardano/test/fidokit"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

// softKey is a security key in software behind fido.Key (decision 116): a
// fidokit credential with a PIN, which it checks as a key does.
type softKey struct {
	k          *fidokit.Key
	name       string
	pin        string // empty if none is set
	retries    int
	toRegister bool // registering takes the PIN
}

func newSoftKey(name, pin string) *softKey {
	return &softKey{k: fidokit.New(fidokit.EdDSA), name: name, pin: pin, retries: 8}
}

func (s *softKey) Name() string { return s.name }
func (s *softKey) Close() error { return nil }

func (s *softKey) Info(context.Context) (fido.Info, error) {
	return fido.Info{PIN: s.pin != "", Retries: s.retries, PINToRegister: s.toRegister}, nil
}

func (s *softKey) checkPIN(pin string) error {
	if pin != "" && pin != s.pin {
		s.retries--
		return errors.New("fido: soft key: the PIN was wrong")
	}
	return nil
}

func (s *softKey) Register(_ context.Context, rpID, pin string) ([]byte, error) {
	if s.toRegister && pin == "" {
		return nil, errors.New("fido: soft key: a PIN is required and none was given")
	}
	if err := s.checkPIN(pin); err != nil {
		return nil, err
	}
	return s.k.MakeCredential(fidokit.Options{RPID: rpID}), nil
}

func (s *softKey) Assert(_ context.Context, rpID string, cdh []byte, allow [][]byte, pin string) (fido.Assertion, error) {
	if !slices.ContainsFunc(allow, func(id []byte) bool { return bytes.Equal(id, s.k.CredentialID()) }) {
		return fido.Assertion{}, errors.New("fido: soft key: no credential the authenticator holds matches")
	}
	if err := s.checkPIN(pin); err != nil {
		return fido.Assertion{}, err
	}
	a := s.k.GetAssertion(cdh, fidokit.Options{RPID: rpID, PIN: pin != ""})
	return fido.Assertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, Signature: a.Signature}, nil
}

// slot is the USB port: the keys inserted for one command, one after
// another; the last stays. An empty slot has no key.
type slot struct {
	inserted []*softKey
}

func (s *slot) insert(keys ...*softKey) { s.inserted = keys }

func (s *slot) open(context.Context) (fido.Key, error) {
	if len(s.inserted) == 0 {
		return nil, fido.ErrNoKey
	}
	k := s.inserted[0]
	if len(s.inserted) > 1 {
		s.inserted = s.inserted[1:]
	}
	return k, nil
}

// keys never waits for a key, and never opens a real one.
func (s *slot) keys() keys {
	if s == nil {
		s = &slot{}
	}
	return keys{open: s.open, wait: 0}
}

// TestKeyCommands runs the key's commands (section 6.1) against a real
// wallet with keys in software: registering the first key with the
// password, the touch and PIN in each authorization, a second key added and
// the first removed, and a recovery started, warned of and cancelled.
func TestKeyCommands(t *testing.T) {
	w := walletkit.Start(t)
	walletkit.Unlock(t, w.Admin(t))
	p := person{t: t, w: w, slot: &slot{}}
	if r := p.must(password, "wallet create", "-label", "saving"); !strings.Contains(r.errOut, "Consider a security key") {
		t.Errorf("no suggestion of a key:\n%s", r.errOut)
	}
	id := regexp.MustCompile(`w_[a-z2-7]+`).FindString(p.must("", "status").out)
	if r := p.must("", "key list"); !strings.Contains(r.out, "No security key is registered") {
		t.Errorf("key list with none:\n%s", r.out)
	}

	// The first key, with the password; one without a PIN is refused.
	yubikey := newSoftKey("YubiKey", "1234")
	p.slot.insert(newSoftKey("no PIN", ""))
	if r := p.run(password, "key add", "-name", "YubiKey"); r.code != ExitError || !strings.Contains(r.errOut, "has no PIN") {
		t.Errorf("a key without a PIN: %+v", r)
	}
	p.slot.insert(yubikey)
	r := p.must(password, "key add", "-name", "YubiKey")
	if !strings.Contains(r.errOut, `Register the security key "YubiKey" (EdDSA`) || !strings.Contains(r.out, "Register a second key") {
		t.Errorf("key add:\n%s%s", r.errOut, r.out)
	}
	if r := p.must("", "key list"); !strings.Contains(r.out, "YubiKey  EdDSA, added") {
		t.Errorf("key list:\n%s", r.out)
	}

	// Now the touch: no password is asked, and the PIN only where the
	// action takes it.
	p.must("", "freeze", "-wallet", id)
	if r := p.must("", "unfreeze", "-wallet", id); !strings.Contains(r.errOut, "Touch YubiKey before") || strings.Contains(r.errOut, "PIN") {
		t.Errorf("unfreeze with the key:\n%s", r.errOut)
	}
	if r := p.must("1234\n", "wallet backup", "-wallet", id); len(strings.Fields(r.out)) != 24 {
		t.Errorf("wallet backup with the key and its PIN:\n%s%s", r.errOut, r.out)
	}
	if r := p.must(password, "wallet create", "-label", "other"); strings.Contains(r.errOut, "Consider a security key") {
		t.Errorf("a key suggested with one registered:\n%s", r.errOut)
	}

	// A second key: created on the new key, authorized by the first, with
	// its PIN; then the first is removed with the second.
	backup := newSoftKey("backup", "5678")
	backup.toRegister = true
	p.slot.insert(backup, yubikey)
	if r := p.must("5678\n\n1234\n", "key add", "-name", "backup"); !strings.Contains(r.errOut, "insert a registered key") {
		t.Errorf("key add with a key registered:\n%s", r.errOut)
	}
	p.slot.insert(backup)
	p.must("5678\n", "key remove", "-name", "YubiKey")
	if r := p.must("", "key list"); strings.Contains(r.out, "YubiKey") || !strings.Contains(r.out, "backup") {
		t.Errorf("key list after removing:\n%s", r.out)
	}

	// A recovery with the password: every command warns of it, and the
	// key cancels it.
	p.slot.insert()
	if r := p.must(password, "recover start"); !strings.Contains(r.out, "every wallet is frozen") {
		t.Errorf("recover start:\n%s", r.out)
	}
	if r := p.must("", "recover status"); !strings.Contains(r.out, "the registered keys will be removed") || !strings.Contains(r.errOut, "mcpcardano recover cancel") {
		t.Errorf("recover status:\n%s%s", r.errOut, r.out)
	}
	p.slot.insert(backup)
	p.must("", "recover cancel")
	if r := p.must("", "recover status"); !strings.Contains(r.out, "No recovery is waiting") || r.errOut != "" {
		t.Errorf("after cancelling:\n%s%s", r.errOut, r.out)
	}
}

// TestKeyExitCodes: what the key refuses is an authorization refused, exit
// 3, as is an empty PIN; no key at all is an error, exit 1 (section 6.5).
func TestKeyExitCodes(t *testing.T) {
	w := walletkit.Start(t)
	walletkit.Unlock(t, w.Admin(t))
	p := person{t: t, w: w, slot: &slot{}}
	id := regexp.MustCompile(`w_[a-z2-7]+`).FindString(p.must(password, "wallet create", "-label", "saving").out)
	key := newSoftKey("YubiKey", "1234")
	p.slot.insert(key)
	p.must(password, "key add", "-name", "YubiKey")

	stranger := newSoftKey("stranger", "1234")
	for _, tc := range []struct {
		name, input string
		inserted    []*softKey
		args        []string
		code        int
		says        string
	}{
		{"a wrong PIN", "0000\n", []*softKey{key}, []string{"wallet backup", "-wallet", id}, ExitRejected, "PIN was wrong"},
		{"an empty PIN", "\n", []*softKey{key}, []string{"wallet backup", "-wallet", id}, ExitRejected, ""},
		{"a key that is not registered", "", []*softKey{stranger}, []string{"unfreeze", "-wallet", id}, ExitRejected, "no credential"},
		{"no key", "", nil, []string{"unfreeze", "-wallet", id}, ExitError, "no security key was inserted"},
		{"the password instead", password, nil, []string{"key remove", "-name", "nobody"}, ExitError, `no registered key is named "nobody"`},
		{"no name", "", nil, []string{"key add"}, ExitUsage, "-name must be"},
	} {
		p.slot.insert(tc.inserted...)
		r := p.run(tc.input, tc.args[0], tc.args[1:]...)
		if r.code != tc.code || !strings.Contains(r.errOut, tc.says) {
			t.Errorf("%s: exit %d, want %d\n%s", tc.name, r.code, tc.code, r.errOut)
		}
	}
	if key.retries != 7 {
		t.Errorf("%d PIN tries left after one wrong PIN", key.retries)
	}
}
