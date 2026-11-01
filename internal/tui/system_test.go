// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/doctor"
	"github.com/Liet-ada/mcpcardano/internal/fido"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/test/softkey"
)

// addAudit gives the fake wallet n entries, the first of them seq 1.
func addAudit(t *testing.T, f *fakeWallet, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		kind, body := "unlock", map[string]any{"ok": true}
		if i%2 == 0 {
			kind, body = "frozen", map[string]any{"wallet_id": walletA, "cancelled": uint64(1)}
		}
		encoded, err := recordCodec.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := recordCodec.Marshal(audit.Entry{Seq: uint64(i), Time: at.Unix(), Prev: []byte{}, Type: kind, Body: encoded})
		if err != nil {
			t.Fatal(err)
		}
		f.audit = append(f.audit, raw)
	}
}

// TestAddFirstKey: the name, the touch on the new key, and the password,
// since no key is registered yet.
func TestAddFirstKey(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.st.Keys = nil
	key := softkey.New("YubiKey", "1234")
	slot := &softkey.Slot{}
	slot.Insert(key)
	m := press(t, start(t, f, slot), "4", "a", "enter")
	if len(f.begun) != 0 || !strings.Contains(plain(m), "A key's name is 1 to 64 bytes") {
		t.Fatalf("no name: began %v\n%s", f.begun, plain(m))
	}
	m = press(t, m, "m", "i", "a", "enter")
	p, ok := f.params.(*ipc.AddKey)
	if !ok || p.Name != "mia" || len(p.AuthenticatorData) == 0 {
		t.Fatalf("began with %+v\n%s", f.params, plain(m))
	}
	m = press(t, m, "a", "p", "w", "enter")
	if !strings.Contains(plain(m), "The security key mia is registered.") || !strings.Contains(plain(m), "second one") {
		t.Errorf("after registering:\n%s", plain(m))
	}
	if m.adding != nil || m.overlay != noOverlay {
		t.Errorf("the screen stayed: %d", m.overlay)
	}
}

// TestAddSecondKey: the new key's PIN when it asks for one, never drawn; then
// the swap, because a registered key authorizes.
func TestAddSecondKey(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	key := softkey.New("YubiKey", "1234")
	key.PINToRegister = true
	key.Retries = 2
	slot := &softkey.Slot{}
	slot.Insert(key)
	m := press(t, start(t, f, slot), "4", "a", "n", "enter")
	if !strings.Contains(plain(m), "PIN OF THE NEW KEY") || !strings.Contains(plain(m), "locks after 2 more wrong PINs") {
		t.Fatalf("the PIN:\n%s", plain(m))
	}
	m = press(t, m, "1", "2", "3", "x", "backspace", "4")
	if v := plain(m); strings.Contains(v, "1234") || !strings.Contains(v, "••••▌") {
		t.Fatalf("typing the PIN:\n%s", v)
	}
	m = press(t, m, "enter")
	if !strings.Contains(plain(m), "insert a registered key in its place") || len(f.begun) != 0 {
		t.Fatalf("the swap: began %v\n%s", f.begun, plain(m))
	}
	m = press(t, m, "x") // only enter goes on
	if len(f.begun) != 0 {
		t.Fatalf("x went on: %v", f.begun)
	}
	m = press(t, m, "enter")
	if p, ok := f.params.(*ipc.AddKey); !ok || p.Name != "n" || m.auth == nil {
		t.Errorf("began with %+v", f.params)
	}
}

// TestAddKeyStops: esc lets go of a key waiting for its PIN, a key with no PIN
// is told to set one, and a wrong PIN says so.
func TestAddKeyStops(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	key := softkey.New("YubiKey", "1234")
	key.PINToRegister = true
	slot := &softkey.Slot{}
	slot.Insert(key)
	held := &closing{Key: key}
	m := press(t, start(t, f, slot), "4")
	m.keys = func(context.Context) (fido.Key, error) { return held, nil }
	m = press(t, m, "a", "n", "enter", "1")
	buf := m.adding.pin
	if m = press(t, m, "esc"); m.adding != nil || m.overlay != noOverlay {
		t.Fatalf("esc stayed: %d", m.overlay)
	}
	if held.closed != 1 || !wiped(buf) {
		t.Errorf("esc: closed %d, PIN wiped %v", held.closed, wiped(buf))
	}
	m = press(t, m, "a", "n", "enter", "9")
	buf = m.adding.pin
	m = press(t, m, "enter")
	if !strings.Contains(plain(m), "PIN") || m.adding != nil || len(f.begun) != 0 {
		t.Errorf("a wrong PIN: began %v\n%s", f.begun, plain(m))
	}
	if !wiped(buf) {
		t.Error("the PIN stayed once sent")
	}
	nopin := softkey.New("Blank", "")
	blank := &softkey.Slot{}
	blank.Insert(nopin)
	m = press(t, start(t, newFake(ipc.MethodPassword), blank), "4", "a", "n", "enter")
	if !strings.Contains(plain(m), "Blank has no PIN") || m.adding != nil {
		t.Errorf("a key with no PIN:\n%s", plain(m))
	}
}

// TestKeyStaleAnswer: an answer for a registration the person left goes
// nowhere, and its key is let go.
func TestKeyStaleAnswer(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := start(t, f, &softkey.Slot{})
	gone := &keyAdding{}
	k := &closing{}
	m = drive(t, m, keyOpened{adding: gone, key: k})
	if k.closed != 1 || m.adding != nil {
		t.Fatalf("with no registration: closed %d", k.closed)
	}
	m.adding, m.overlay = &keyAdding{cancel: func() {}}, keyOverlay
	m = drive(t, m, keyOpened{adding: gone, key: k})
	if k.closed != 2 || m.adding.key != nil {
		t.Fatalf("with a newer one: closed %d", k.closed)
	}
	m = drive(t, m, keyRegistered{adding: gone, data: []byte{1}})
	if m.adding.data != nil || len(f.begun) != 0 {
		t.Errorf("a stale credential: %v, began %v", m.adding.data, f.begun)
	}
}

// closing is a key that counts its closes.
type closing struct {
	fido.Key
	closed int
}

func (c *closing) Close() error { c.closed++; return nil }

// TestSpinnerChain: one chain of the spinner runs while a key is awaited,
// through the wait for the key and for its touch.
func TestSpinnerChain(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.st.Keys = nil
	key := softkey.New("YubiKey", "1234")
	slot := &softkey.Slot{}
	slot.Insert(key)
	m := press(t, start(t, f, slot), "4", "a", "n")
	next, cmd := m.Update(pressKey("enter"))
	m = next.(Model)
	batch := cmd().(tea.BatchMsg)
	if len(batch) != 2 {
		t.Fatalf("%d commands", len(batch))
	}
	opened := batch[0]().(keyOpened)
	next, cmd = m.Update(opened)
	if _, isBatch := cmd().(tea.BatchMsg); isBatch {
		t.Error("a second chain of the spinner")
	}
}

// TestNotRegisteredKey: a device that is not a registered key is named, and
// the authorization stays open for the right one, with no PIN gone.
func TestNotRegisteredKey(t *testing.T) {
	f := newFake(ipc.MethodKey)
	registered, other := softkey.New("YubiKey", "1234"), softkey.New("Trezor Safe 7", "")
	f.ch.Credentials = [][]byte{registered.Credential.CredentialID()}
	f.ch.PIN = true
	slot := &softkey.Slot{}
	slot.Insert(other)
	m := press(t, start(t, f, slot), "3", "enter", "a", "1", "2", "3", "4", "enter")
	if v := plain(m); !strings.Contains(v, "Trezor Safe 7 is not a registered key") || strings.Contains(v, "refused") || m.auth == nil || m.auth.stage != reading {
		t.Fatalf("another device:\n%s", v)
	}
	if len(f.completed) != 0 || registered.Retries != 8 {
		t.Errorf("%d completions, %d tries", len(f.completed), registered.Retries)
	}
	slot.Insert(registered)
	if m = press(t, m, "a", "1", "2", "3", "4", "enter"); len(f.completed) != 1 {
		t.Errorf("the right key after it: %d completions\n%s", len(f.completed), plain(m))
	}
}

// TestNewKeyNamed: registering says which device it is, before its touch.
func TestNewKeyNamed(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	k := softkey.New("Trezor Safe 7", "1234")
	k.PINToRegister = true
	slot := &softkey.Slot{}
	slot.Insert(k)
	m := press(t, start(t, f, slot), "4", "a", "n", "enter")
	if !strings.Contains(plain(m), "NEW KEY  Trezor Safe 7") {
		t.Errorf("the device:\n%s", plain(m))
	}
}

// TestRemoveKey: d goes through the dialog, with the chosen key.
func TestRemoveKey(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.st.Keys[0].CredentialID = []byte{7}
	m := press(t, start(t, f, &softkey.Slot{}), "4", "d")
	if p, ok := f.params.(*ipc.KeyRef); !ok || p.CredentialID[0] != 7 || m.auth == nil {
		t.Fatalf("began with %+v", f.params)
	}
	if m = press(t, m, "a", "p", "w", "enter"); !strings.Contains(plain(m), "The security key YubiKey 5C is removed.") {
		t.Errorf("the note:\n%s", plain(m))
	}
	f.st.Keys = nil
	m = drive(t, m, m.fetch())
	began := len(f.begun)
	if m = press(t, m, "d"); len(f.begun) != began {
		t.Errorf("d with no keys: %v", f.begun)
	}
}

// TestUnlockScreen: a locked wallet opens with the password; a wrong one
// stays, esc shows it locked and it does not ask again, and it asks when it
// locks again.
func TestUnlockScreen(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.st.Unlocked = false
	f.refuseUnlock = &ipc.Error{Code: ipc.AuthFailed, Detail: "wrong password"}
	m := start(t, f, &softkey.Slot{})
	if v := plain(m); m.overlay != unlockOverlay || !strings.Contains(v, "PASSWORD") {
		t.Fatalf("locked:\n%s", v)
	}
	m = press(t, m, "s", "e", "c", "r", "x", "backspace")
	if v := plain(m); strings.Contains(v, "secr") || !strings.Contains(v, "••••▌") {
		t.Fatalf("typing:\n%s", v)
	}
	buf := m.unlock.secret
	m = press(t, m, "enter")
	if f.password != "secr" || !wiped(buf[:4]) || !wiped(f.sentPassword) {
		t.Fatalf("sent %q, wiped %v and %v", f.password, wiped(buf[:4]), wiped(f.sentPassword))
	}
	if m.overlay != unlockOverlay || !strings.Contains(plain(m), "wrong password") {
		t.Fatalf("a wrong password:\n%s", plain(m))
	}
	m = press(t, m, "n", "o")
	buf = m.unlock.secret
	m = press(t, m, "esc")
	if !wiped(buf) {
		t.Fatal("esc left what was typed")
	}
	if m.overlay != noOverlay || !strings.Contains(plain(m), "● LOCKED") {
		t.Fatalf("esc:\n%s", plain(m))
	}
	m = drive(t, m, m.fetch())
	if m.overlay != noOverlay {
		t.Fatal("it asked again after esc")
	}
	m = press(t, m, "6", "u")
	if m.overlay != unlockOverlay {
		t.Fatalf("u in the system tab:\n%s", plain(m))
	}
	f.refuseUnlock = nil
	m = press(t, m, "p", "w", "enter")
	if m.overlay != noOverlay || !strings.Contains(plain(m), "The wallet is unlocked.") || m.status.Unlocked != true {
		t.Fatalf("unlocked:\n%s", plain(m))
	}
	f.st.Unlocked = false // the wallet restarted
	m = drive(t, m, m.fetch())
	if m.overlay != unlockOverlay {
		t.Errorf("locked again: overlay %d", m.overlay)
	}
}

// TestUnlockWaits: nothing typed while the wallet checks the password goes
// anywhere.
func TestUnlockWaits(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.st.Unlocked = false
	m := start(t, f, &softkey.Slot{})
	m.unlock.busy = true
	if next, cmd := m.key(pressKey("x")); cmd != nil || len(next.(Model).unlock.secret) != 0 {
		t.Error("a key got through")
	}
	if !strings.Contains(plain(m), "CHECKING") {
		t.Errorf("waiting:\n%s", plain(m))
	}
}

// TestRecovery: r starts it through the dialog, the bar counts down, and x
// cancels it; each says so if there is nothing to do.
func TestRecovery(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	ends := at.Add(72 * time.Hour).Unix()
	f.result = encoded(t, &ipc.Recovery{StartedAt: at.Unix(), EndsAt: ends})
	m := press(t, start(t, f, &softkey.Slot{}), "6", "x")
	if len(f.begun) != 0 || !strings.Contains(plain(m), "No recovery is waiting.") {
		t.Fatalf("x with none: began %v\n%s", f.begun, plain(m))
	}
	f.st.Keys, m.status.Keys = nil, nil
	if m = press(t, m, "r"); len(f.begun) != 0 || !strings.Contains(plain(m), "password already authorizes") {
		t.Fatalf("r with no keys: began %v\n%s", f.begun, plain(m))
	}
	f.st.Keys = []ipc.KeyInfo{{Name: "k", Alg: -8}}
	m = drive(t, m, m.fetch())
	m = press(t, m, "r")
	if len(f.begun) != 1 || f.begun[0] != ipc.ActStartRecovery {
		t.Fatalf("began %v", f.begun)
	}
	m = press(t, m, "a", "p", "w", "enter")
	if !strings.Contains(plain(m), "every wallet is frozen") || !strings.Contains(plain(m), "2026-10-31") {
		t.Fatalf("started:\n%s", plain(m))
	}
	f.st.Recovery = &ipc.Recovery{StartedAt: at.Unix(), EndsAt: ends}
	m = drive(t, m, m.fetch())
	if v := plain(press(t, m, "esc")); !strings.Contains(v, "RECOVERY IN 72:00:00") || !strings.Contains(v, "2026-10-31 14:32:08") {
		t.Fatalf("waiting:\n%s", v)
	}
	if m = press(t, m, "r"); len(f.begun) != 1 || !strings.Contains(plain(m), "already waiting") {
		t.Fatalf("r with one waiting: %v", f.begun)
	}
	m = press(t, m, "x")
	if f.begun[1] != ipc.ActCancelRecovery {
		t.Fatalf("began %v", f.begun)
	}
	if m = press(t, m, "a", "p", "w", "enter"); !strings.Contains(plain(m), "The wallets stay frozen") {
		t.Errorf("cancelled:\n%s", plain(m))
	}
}

// TestAudit: opening the tab checks the chains once and asks only for the
// last page, whatever the size of the log; older pages come on request.
func TestAudit(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	addAudit(t, f, 250)
	m := press(t, start(t, f, &softkey.Slot{}), "5")
	if f.verified != 1 || len(f.pages) != 1 || f.pages[0] != 151 {
		t.Fatalf("verified %d, pages %v", f.verified, f.pages)
	}
	v := plain(m)
	if !strings.Contains(v, "chain ✓ verified 14:32:08 (250 entries)") || !strings.Contains(v, "100 of the 100 loaded, from entry 151") {
		t.Fatalf("the audit:\n%s", v)
	}
	if strings.Index(v, "250 ") > strings.Index(v, "249 ") {
		t.Errorf("the newest goes first:\n%s", v)
	}
	if !strings.Contains(v, "AGENTE") {
		t.Errorf("the wallet by its name:\n%s", v)
	}
	m = press(t, m, "m", "m")
	if len(f.pages) != 3 || f.pages[1] != 51 || f.pages[2] != 1 || len(m.audit.lines) != 250 {
		t.Fatalf("pages %v, %d lines", f.pages, len(m.audit.lines))
	}
	if m.audit.lines[0].Seq != 1 || m.audit.lines[249].Seq != 250 {
		t.Fatalf("the order: %d to %d", m.audit.lines[0].Seq, m.audit.lines[249].Seq)
	}
	if m = press(t, m, "m"); len(f.pages) != 3 || !strings.Contains(plain(m), "first entry of the log") {
		t.Errorf("m at the start: %v", f.pages)
	}
	if m = press(t, m, "v"); f.verified != 2 {
		t.Errorf("v verified %d", f.verified)
	}
	if m = press(t, m, "1", "5"); f.verified != 3 {
		t.Errorf("coming back verified %d", f.verified)
	}
}

// TestAuditFilter: the filter is text, q and f included, by event or by the
// wallet's name, and esc clears it.
func TestAuditFilter(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	addAudit(t, f, 6)
	m := press(t, start(t, f, &softkey.Slot{}), "5", "/", "f", "r", "o", "z")
	if len(f.frozen) != 0 || !strings.Contains(plain(m), "3 of the 6 loaded") {
		t.Fatalf("filtering: frozen %v\n%s", f.frozen, plain(m))
	}
	m = press(t, m, "enter", "down", "enter")
	if v := plain(m); m.overlay != detailOverlay || !strings.Contains(v, "ENTRY 4") || !strings.Contains(v, `"cancelled": 1`) {
		t.Fatalf("the detail:\n%s", v)
	}
	m = press(t, m, "x")
	if m.overlay != noOverlay || m.audit.detail != nil {
		t.Fatal("the detail stayed")
	}
	m = press(t, m, "/", "esc")
	if !strings.Contains(plain(m), "6 of the 6 loaded") {
		t.Errorf("esc did not clear the filter:\n%s", plain(m))
	}
	m = press(t, m, "/", "a", "g", "e", "n", "t", "e", "enter")
	if !strings.Contains(plain(m), "3 of the 6 loaded") {
		t.Errorf("by the wallet's name:\n%s", plain(m))
	}
}

// TestAuditBroken: a chain that does not hold is said in red, and never as
// verified.
func TestAuditBroken(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	addAudit(t, f, 2)
	m := press(t, start(t, f, &softkey.Slot{}), "5")
	f.brokenChain = errors.New("audit: entry 2 does not follow entry 1")
	m = press(t, m, "v")
	v := plain(m)
	if strings.Contains(v, "chain ✓") || !strings.Contains(v, "chain not verified") || !strings.Contains(v, "does not follow") {
		t.Errorf("a broken chain:\n%s", v)
	}
}

// TestDoctor: d runs the checks and shows them by level; what a check says
// passes through visible.
func TestDoctor(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := press(t, start(t, f, &softkey.Slot{}), "6", "d")
	if !strings.Contains(plain(m), "This view cannot run doctor") {
		t.Fatalf("with no doctor:\n%s", plain(m))
	}
	m = press(t, m, "esc")
	m.doctor = func(context.Context) (doctor.Report, error) {
		return doctor.Report{{Level: doctor.OK, Detail: "the users"}, {Level: doctor.Warn, Detail: "no key\x1b[31m"}, {Level: doctor.Fail, Detail: "the wallet"}}, nil
	}
	m = press(t, m, "d")
	v := plain(m)
	if !strings.Contains(v, "ok    the users") || !strings.Contains(v, "warn  no key?[31m") || !strings.Contains(v, "FAIL  the wallet") {
		t.Fatalf("the report:\n%s", v)
	}
	m.doctor = func(context.Context) (doctor.Report, error) { return nil, errors.New("no env") }
	if m = press(t, m, "d"); !strings.Contains(plain(m), "no env") {
		t.Errorf("doctor failing:\n%s", plain(m))
	}
}

// TestSystemTab: what needs sudo is only named, and the template opens.
func TestSystemTab(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := press(t, start(t, f, &softkey.Slot{}), "6")
	for _, s := range []string{"sudo mcpcardano install", "sudo mcpcardano uninstall", "sudo mcpcardano apikey set <name>"} {
		if !strings.Contains(plain(m), s) {
			t.Errorf("no %q:\n%s", s, plain(m))
		}
	}
	if m = press(t, m, "t"); m.editor == nil || !strings.Contains(plain(m), "TEMPLATE OF THE AGENT'S WALLETS") {
		t.Errorf("t:\n%s", plain(m))
	}
}

func TestCountdown(t *testing.T) {
	for d, want := range map[time.Duration]string{0: "0:00:00", -time.Hour: "0:00:00", time.Minute + time.Second: "0:01:01", 72 * time.Hour: "72:00:00"} {
		if got := countdown(at.Add(d).Unix(), at); got != want {
			t.Errorf("%v: %s", d, got)
		}
	}
	if got := when(at.Unix(), at); got != at.Format(time.TimeOnly) {
		t.Errorf("today: %s", got)
	}
	if got := when(at.Add(48*time.Hour).Unix(), at); got != fmt.Sprintf("2026-10-30 %s", at.Format(time.TimeOnly)) {
		t.Errorf("another day: %s", got)
	}
}
