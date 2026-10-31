// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/test/softkey"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

const testPhrase = "void come effort suffer camp survey warrior heavy shoot primary clutch crush " +
	"open amazing screen patrol group space point ten exist slush involve unfold"

var testExpired = []ipc.Expired{
	{WalletID: walletA, BodyHash: bytes.Repeat([]byte{0xbb}, 32), Spend: ipc.Spend{Lovelace: 5_170_000}, TTL: 900, Time: at.Add(-time.Hour).Unix()},
	{WalletID: walletA, BodyHash: bytes.Repeat([]byte{0xaa}, 32), Spend: ipc.Spend{Lovelace: 2_170_000}, TTL: 800, Time: at.Add(-2 * time.Hour).Unix()},
}

func encoded(t *testing.T, b ipc.Body) []byte {
	t.Helper()
	raw, err := ipc.NewCodec().Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// walletResult is the result of an action that makes a wallet: the fake's
// ids are not valid ones, which the codec checks.
func walletResult(t *testing.T, label string) []byte {
	t.Helper()
	id, err := model.NewWalletID(nil)
	if err != nil {
		t.Fatal(err)
	}
	return encoded(t, &ipc.Wallet{ID: string(id), Label: label, Network: "preprod", Mode: "C", CreatedBy: "person", Address: walletkit.Address(6, 7, 0)})
}

// write presses the letters of s.
func write(t *testing.T, m Model, s string) Model {
	t.Helper()
	return press(t, m, strings.Split(s, "")...)
}

// TestOpenSession: the form takes a duration and ADA, and refuses what is
// wrong without asking the wallet; the action goes through the dialog.
func TestOpenSession(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := press(t, start(t, f, &softkey.Slot{}), "2", "down", "s")
	if v := plain(m); !strings.Contains(v, "OPEN A SESSION ON NUEVA2") || !strings.Contains(v, "[ 1h▌ ]") {
		t.Fatalf("the form:\n%s", v)
	}
	m = press(t, m, "enter", "enter")
	if len(f.begun) != 0 || !strings.Contains(plain(m), "The maximum is an amount of ADA") || m.overlay != formOverlay {
		t.Fatalf("no amount: began %v\n%s", f.begun, plain(m))
	}
	m = press(t, m, "0", "enter")
	if len(f.begun) != 0 || !strings.Contains(plain(m), "A session's maximum must be above zero.") {
		t.Fatalf("zero: began %v\n%s", f.begun, plain(m))
	}
	m = press(t, m, "tab", "x", "enter", "enter")
	if len(f.begun) != 0 || !strings.Contains(plain(m), "A session lasts a duration") {
		t.Fatalf("a bad duration: began %v\n%s", f.begun, plain(m))
	}
	m = press(t, m, "tab", "backspace", "backspace", "backspace", "2", "h", "tab", "backspace", "1", "2", ".", "5", "enter")
	p, ok := f.params.(*ipc.OpenSession)
	if !ok || p.WalletID != walletB || p.Seconds != 7200 || p.MaxLovelace != 12_500_000 {
		t.Fatalf("began %v with %+v", f.begun, f.params)
	}
	if m.overlay != noOverlay || m.auth == nil {
		t.Fatalf("the dialog did not open:\n%s", plain(m))
	}
	m = press(t, m, "a", "p", "w", "enter")
	if len(f.completed) != 1 || !strings.Contains(plain(m), "Session open on wallet nueva2.") {
		t.Errorf("completed %d\n%s", len(f.completed), plain(m))
	}
}

// TestAskRefused: what the wallet refuses at the start leaves the form, for
// the person to mend it.
func TestAskRefused(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.refuseAsk = &ipc.Error{Code: ipc.Locked, Detail: "the wallet is locked"}
	m := press(t, start(t, f, &softkey.Slot{}), "2", "c", "x", "enter")
	if m.overlay != formOverlay || m.auth != nil || !strings.Contains(plain(m), "the wallet is locked") {
		t.Fatalf("refused:\n%s", plain(m))
	}
	if m = press(t, m, "y"); strings.Contains(plain(m), "ERROR") || !strings.Contains(plain(m), "[ xy▌ ]") {
		t.Errorf("typing again:\n%s", plain(m))
	}
}

// TestCloseSession: s on a wallet with a session closes it at once, with no
// authorization. The palette never closes what it says it opens.
func TestCloseSession(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := press(t, start(t, f, &softkey.Slot{}), "2", "s")
	if len(f.closed) != 1 || f.closed[0] != walletA || len(f.begun) != 0 || !strings.Contains(plain(m), "Session closed on wallet agente.") {
		t.Fatalf("closed %v, began %v\n%s", f.closed, f.begun, plain(m))
	}
	m = write(t, press(t, m, ":"), "open a session")
	if m = press(t, m, "enter"); len(f.closed) != 1 || m.overlay != noOverlay || !strings.Contains(plain(m), "already has a session") {
		t.Errorf("open with a session on: closed %v\n%s", f.closed, plain(m))
	}
	m = write(t, press(t, m, "down", ":"), "close the")
	if m = press(t, m, "enter"); len(f.closed) != 1 || !strings.Contains(plain(m), "has no session") {
		t.Errorf("close with no session: closed %v\n%s", f.closed, plain(m))
	}
}

// TestBudget: the entries are marked one by one or all at once, and only
// those marked go to the wallet, in the order it takes them.
func TestBudget(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := press(t, start(t, f, &softkey.Slot{}), "2", "b")
	if m.overlay != noOverlay || !strings.Contains(plain(m), "Wallet agente has nothing to release.") {
		t.Fatalf("with nothing to release:\n%s", plain(m))
	}
	f.expired = testExpired
	f.result = encoded(t, &ipc.Released{Lovelace: 7_340_000})
	m = press(t, m, "b")
	if v := plain(m); !strings.Contains(v, "5.170000 ADA") || !strings.Contains(v, "First check on the chain") {
		t.Fatalf("the list:\n%s", v)
	}
	m = press(t, m, "enter")
	if len(f.begun) != 0 || !strings.Contains(plain(m), "Mark what to release") {
		t.Fatalf("nothing marked: began %v\n%s", f.begun, plain(m))
	}
	m = press(t, m, "down", "space", "enter")
	if p := f.params.(*ipc.ReleaseBudget); len(p.Entries) != 1 || p.Entries[0][0] != 0xaa {
		t.Fatalf("one marked: %x", p.Entries)
	}
	m = press(t, m, "esc", "b", "a", "enter")
	if p := f.params.(*ipc.ReleaseBudget); len(p.Entries) != 2 || p.Entries[0][0] != 0xaa || p.Entries[1][0] != 0xbb {
		t.Fatalf("all marked: %x", p.Entries)
	}
	m = press(t, m, "a", "p", "w", "enter")
	if !strings.Contains(plain(m), "Released 7.340000 ADA of the budget of wallet agente.") {
		t.Errorf("the result:\n%s", plain(m))
	}
	m = press(t, m, "b", "a", "a")
	if slices.Contains(m.budget.marked, true) {
		t.Errorf("a twice leaves %v", m.budget.marked)
	}
	if m = press(t, m, "f"); m.overlay != noOverlay || len(f.frozen) != 1 {
		t.Errorf("f in the budget: overlay %d, frozen %v", m.overlay, f.frozen)
	}
}

// TestCreate: with no wallets the tab still creates one.
func TestCreate(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.st.Wallets = nil
	f.result = walletResult(t, "mi cartera")
	m := press(t, start(t, f, &softkey.Slot{}), "2", "c", "enter")
	if len(f.begun) != 0 || !strings.Contains(plain(m), "A label is 1 to 64 bytes") {
		t.Fatalf("no label: began %v\n%s", f.begun, plain(m))
	}
	m = write(t, m, "mi")
	m = write(t, press(t, m, "space"), "cartera")
	m = press(t, m, "f", "backspace", "enter") // f is text in a form
	if p, ok := f.params.(*ipc.CreateWallet); !ok || p.Label != "mi cartera" || len(f.frozen) != 0 {
		t.Fatalf("began with %+v, frozen %v", f.params, f.frozen)
	}
	m = press(t, m, "a", "p", "w", "enter")
	if !strings.Contains(plain(m), "Wallet mi cartera created: write down its phrase with p.") {
		t.Errorf("the result:\n%s", plain(m))
	}
}

func takeWords(t *testing.T, m Model, words []string) Model {
	t.Helper()
	for _, w := range words {
		m = press(t, write(t, m, w), "enter")
	}
	return m
}

// TestRestore: the words stay hidden unless asked, are completed from the
// list, and go to the wallet once; the wallet's refusal leaves them to mend,
// and every way out wipes them.
func TestRestore(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.result = walletResult(t, "old")
	m := write(t, press(t, start(t, f, &softkey.Slot{}), "2", "R"), "old")
	m = write(t, press(t, m, "enter"), "voi")
	r := m.restore
	if v := plain(m); m.overlay != restoreOverlay || strings.Contains(v, "voi") || !strings.Contains(v, "•••▌") || !strings.Contains(v, "TAKEN  0") {
		t.Fatalf("hidden:\n%s", v)
	}
	if v := plain(press(t, m, "ctrl+r")); !strings.Contains(v, "voi▌") || !strings.Contains(v, "void") || !strings.Contains(v, "voice") {
		t.Fatalf("shown:\n%s", v)
	}
	m = press(t, m, "ctrl+r", "enter")
	if !strings.Contains(plain(m), "not the start of one word") || r.words() != 0 {
		t.Fatalf("void and voice both start so:\n%s", plain(m))
	}
	m = press(t, m, "d", "tab")
	if string(r.typed) != "void " || !strings.Contains(plain(m), "TAKEN  1") {
		t.Fatalf("a word taken: %q", string(r.typed))
	}
	m = press(t, m, "enter")
	if !strings.Contains(plain(m), "A recovery phrase has 12, 15") {
		t.Fatalf("too few words:\n%s", plain(m))
	}
	m = press(t, m, "backspace", "backspace")
	if string(r.typed) != "voi" {
		t.Fatalf("going back: %q", string(r.typed))
	}
	m = press(t, m, "d", "space")
	// Each word by the letters that make it the only one; the last sends it.
	f.refuseAsk = &ipc.Error{Code: ipc.Malformed, Detail: "the recovery phrase is not valid"}
	var four []string
	for _, w := range strings.Fields(testPhrase)[1:] {
		four = append(four, w[:min(len(w), 4)])
	}
	m = takeWords(t, m, four)
	if p := f.params.(*ipc.RestoreWallet); string(p.Phrase) != testPhrase || p.Label != "old" {
		t.Fatalf("sent %q", string(p.Phrase))
	}
	if m.restore == nil || !strings.Contains(plain(m), "not valid") {
		t.Fatalf("the wallet's refusal:\n%s", plain(m))
	}
	f.refuseAsk = nil
	buf := r.typed[:cap(r.typed)]
	m = press(t, m, "enter")
	if m.auth == nil || m.restore != nil || m.overlay != noOverlay || len(f.begun) != 2 {
		t.Fatalf("sent again: began %v\n%s", f.begun, plain(m))
	}
	if !wiped(buf) || !wiped(f.sent) {
		t.Error("the words were not wiped once the wallet took them")
	}
	m = press(t, m, "a", "p", "w", "enter")
	if !strings.Contains(plain(m), "Wallet old restored.") {
		t.Errorf("the result:\n%s", plain(m))
	}

	// A phrase of 12 words ends with an empty word; esc wipes one half typed.
	m = write(t, press(t, m, "R"), "new")
	m = press(t, m, "enter")
	m = takeWords(t, m, strings.Fields(testPhrase)[:12])
	m = press(t, m, "enter")
	if p := f.params.(*ipc.RestoreWallet); string(p.Phrase) != strings.Join(strings.Fields(testPhrase)[:12], " ") {
		t.Errorf("12 words: %q", string(p.Phrase))
	}
	m = write(t, press(t, m, "esc", "R"), "new")
	m = write(t, press(t, m, "enter"), "void")
	buf = m.restore.typed[:cap(m.restore.typed)]
	if m = press(t, m, "backspace", "esc"); m.restore != nil || !wiped(buf) {
		t.Error("esc did not wipe the words")
	}
}

// TestRestoreLocked: a locked wallet says so before the person types a word.
func TestRestoreLocked(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.st.Unlocked = false
	m := press(t, start(t, f, &softkey.Slot{}), "2", "R")
	if m.overlay != noOverlay || !strings.Contains(plain(m), "The wallet is locked") {
		t.Errorf("locked:\n%s", plain(m))
	}
}

func wiped(b []byte) bool { return !slices.ContainsFunc(b, func(c byte) bool { return c != 0 }) }

// openPhrase opens the phrase of the chosen wallet with the password.
func openPhrase(t *testing.T, f *fakeWallet, m Model) Model {
	t.Helper()
	f.result = encoded(t, &ipc.RecoveryPhrase{Phrase: []byte(testPhrase)})
	return press(t, m, "p", "a", "p", "w", "enter")
}

// TestPhrase: the words appear only when asked, numbered in four columns;
// esc wipes them.
func TestPhrase(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := press(t, start(t, f, &softkey.Slot{}), "2")
	m = press(t, m, "p")
	if !strings.Contains(plain(m), "RECOVERY PHRASE OF AGENTE") {
		t.Fatalf("the dialog:\n%s", plain(m))
	}
	m = openPhrase(t, f, press(t, m, "esc"))
	v := plain(m)
	if m.overlay != phraseOverlay || !strings.Contains(v, "owns the funds") || !strings.Contains(v, "24 ·······") || !strings.Contains(v, "hides in 2:00") {
		t.Fatalf("hidden:\n%s", v)
	}
	body := ansi.Strip(strings.Join(m.phraseView(110), "\n"))
	for _, w := range strings.Fields(testPhrase) {
		if strings.Contains(body, " "+w+" ") {
			t.Fatalf("the word %q shows before it is asked:\n%s", w, body)
		}
	}
	m = press(t, m, "space")
	v = plain(m)
	if !strings.Contains(v, "1 void") || !strings.Contains(v, "7 warrior") || !strings.Contains(v, "24 unfold") {
		t.Fatalf("shown:\n%s", v)
	}
	if v = plain(press(t, m, "space")); strings.Contains(v, "void") {
		t.Fatalf("hidden again:\n%s", v)
	}
	if !wiped(f.returned) {
		t.Error("the wallet's result stayed in memory")
	}
	words := m.phrase.words
	m = press(t, m, "esc")
	if m.phrase != nil || m.overlay != noOverlay || !wiped(words) {
		t.Errorf("esc: words %v", m.phrase)
	}
	if v = plain(m); strings.Contains(v, "void") {
		t.Errorf("after esc:\n%s", v)
	}
}

// TestPhraseIdle: two minutes with no key hide and wipe the phrase, and a
// key starts the two minutes again.
func TestPhraseIdle(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	now := at
	m := start(t, f, &softkey.Slot{})
	m.now = func() time.Time { return now }
	m = openPhrase(t, f, press(t, m, "2"))
	words := m.phrase.words

	now = at.Add(time.Minute)
	m = press(t, m, "space")
	now = at.Add(2 * time.Minute)
	m = drive(t, m, phraseTick{})
	if m.phrase == nil {
		t.Fatal("a key did not start the two minutes again")
	}
	now = at.Add(3 * time.Minute)
	m = drive(t, m, phraseTick{})
	if m.phrase != nil || m.overlay != noOverlay || !wiped(words) || !strings.Contains(plain(m), "hid itself") {
		t.Errorf("after the two minutes:\n%s", plain(m))
	}
	if strings.Contains(plain(m), "void") {
		t.Errorf("the words stayed:\n%s", plain(m))
	}
}

// TestPhraseLeaves: q, ctrl+c and f wipe the phrase too; f still freezes.
func TestPhraseLeaves(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := start(t, f, &softkey.Slot{})
	m = openPhrase(t, f, press(t, m, "2"))
	words := m.phrase.words
	if m = press(t, m, "f"); m.phrase != nil || !wiped(words) || len(f.frozen) != 1 {
		t.Errorf("f: frozen %v", f.frozen)
	}
	for _, k := range []string{"q", "ctrl+c"} {
		m = openPhrase(t, f, m)
		words = m.phrase.words
		next, _ := m.key(pressKey(k))
		m = next.(Model)
		if m.phrase != nil || !wiped(words) {
			t.Errorf("%s did not wipe the words", k)
		}
	}
	f.refuse = errors.New("broken")
	if m = openPhrase(t, f, m); m.phrase != nil || m.overlay != noOverlay {
		t.Errorf("a refused phrase:\n%s", plain(m))
	}
}

// TestWordList: the copy is the published list, as hdkey's, and completes
// only what one word can complete.
func TestWordList(t *testing.T) {
	const want = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	if got := sha256.Sum256([]byte(english)); hex.EncodeToString(got[:]) != want {
		t.Fatalf("english.txt has SHA-256 %x", got)
	}
	for typed, want := range map[string]string{"aban": "abandon", "abandon": "abandon", "zoo": "zoo", "act": "act", "acti": "action", "ab": "", "zzz": "", "": ""} {
		got, ok := complete([]byte(typed))
		if !ok {
			got = ""
		}
		if got != want {
			t.Errorf("%q completes to %q", typed, got)
		}
	}
	// BIP-39 promises that four letters are enough.
	for _, w := range wordlist() {
		if got, ok := complete([]byte(w[:min(len(w), 4)])); !ok || got != w {
			t.Errorf("%s: %q, %v", w[:min(len(w), 4)], got, ok)
		}
	}
}
