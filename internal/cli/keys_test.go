// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/test/softkey"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

// TestKeyCommands runs the key's commands (section 6.1) against a real
// wallet with keys in software: registering the first key with the
// password, the touch and PIN in each authorization, a second key added and
// the first removed, and a recovery started, warned of and cancelled.
func TestKeyCommands(t *testing.T) {
	w := walletkit.Start(t)
	walletkit.Unlock(t, w.Admin(t))
	p := person{t: t, w: w, slot: &softkey.Slot{}}
	if r := p.must(password, "wallet create", "-label", "saving"); !strings.Contains(r.errOut, "Consider a security key") {
		t.Errorf("no suggestion of a key:\n%s", r.errOut)
	}
	id := regexp.MustCompile(`w_[a-z2-7]+`).FindString(p.must("", "status").out)
	if r := p.must("", "key list"); !strings.Contains(r.out, "No security key is registered") {
		t.Errorf("key list with none:\n%s", r.out)
	}

	// The first key, with the password; one without a PIN is refused.
	yubikey := softkey.New("YubiKey", "1234")
	p.slot.Insert(softkey.New("no PIN", ""))
	if r := p.run(password, "key add", "-name", "YubiKey"); r.code != ExitError || !strings.Contains(r.errOut, "has no PIN") {
		t.Errorf("a key without a PIN: %+v", r)
	}
	p.slot.Insert(yubikey)
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
	backup := softkey.New("backup", "5678")
	backup.PINToRegister = true
	p.slot.Insert(backup, yubikey)
	if r := p.must("5678\n\n1234\n", "key add", "-name", "backup"); !strings.Contains(r.errOut, "insert a registered key") {
		t.Errorf("key add with a key registered:\n%s", r.errOut)
	}
	p.slot.Insert(backup)
	p.must("5678\n", "key remove", "-name", "YubiKey")
	if r := p.must("", "key list"); strings.Contains(r.out, "YubiKey") || !strings.Contains(r.out, "backup") {
		t.Errorf("key list after removing:\n%s", r.out)
	}

	// A recovery with the password: every command warns of it, and the
	// key cancels it.
	p.slot.Insert()
	if r := p.must(password, "recover start"); !strings.Contains(r.out, "every wallet is frozen") ||
		!strings.Contains(r.errOut, "after 72 hours the registered key is removed") {
		t.Errorf("recover start:\n%s%s", r.errOut, r.out)
	}
	if r := p.must("", "recover status"); !strings.Contains(r.out, "the registered keys will be removed") ||
		!strings.Contains(r.out, "mcpcardano recover cancel") || r.errOut != "" {
		t.Errorf("recover status, which says it once:\n%s%s", r.errOut, r.out)
	}
	if r := p.must("", "key list"); !strings.Contains(r.errOut, "If you did not start it, cancel it now") {
		t.Errorf("another command during the recovery:\n%s", r.errOut)
	}
	p.slot.Insert(backup)
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
	p := person{t: t, w: w, slot: &softkey.Slot{}}
	id := regexp.MustCompile(`w_[a-z2-7]+`).FindString(p.must(password, "wallet create", "-label", "saving").out)
	key := softkey.New("YubiKey", "1234")
	p.slot.Insert(key)
	p.must(password, "key add", "-name", "YubiKey")

	stranger := softkey.New("stranger", "1234")
	for _, tc := range []struct {
		name, input string
		inserted    []*softkey.Key
		args        []string
		code        int
		says        string
	}{
		{"a wrong PIN", "0000\n", []*softkey.Key{key}, []string{"wallet backup", "-wallet", id}, ExitRejected, "PIN was wrong"},
		{"an empty PIN", "\n", []*softkey.Key{key}, []string{"wallet backup", "-wallet", id}, ExitRejected, ""},
		{"a key that is not registered", "", []*softkey.Key{stranger}, []string{"unfreeze", "-wallet", id}, ExitRejected, "is not a registered key"},
		{"no key", "", nil, []string{"unfreeze", "-wallet", id}, ExitError, "no security key was inserted"},
		{"the password instead", password, nil, []string{"key remove", "-name", "nobody"}, ExitError, `no registered key is named "nobody"`},
		{"no name", "", nil, []string{"key add"}, ExitUsage, "-name must be"},
	} {
		p.slot.Insert(tc.inserted...)
		r := p.run(tc.input, tc.args[0], tc.args[1:]...)
		if r.code != tc.code || !strings.Contains(r.errOut, tc.says) {
			t.Errorf("%s: exit %d, want %d\n%s", tc.name, r.code, tc.code, r.errOut)
		}
	}
	if key.Retries != 7 {
		t.Errorf("%d PIN tries left after one wrong PIN", key.Retries)
	}
}
