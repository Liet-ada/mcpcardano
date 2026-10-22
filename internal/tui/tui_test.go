// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/test/softkey"
)

// fakeWallet answers as the wallet would, and keeps what it was asked.
type fakeWallet struct {
	mu        sync.Mutex
	st        *ipc.StatusReport
	ch        *ipc.Challenge
	completed []*ipc.CompleteAuthorization
	rejected  []string
	frozen    int
	refuse    error // what Complete answers
}

func (f *fakeWallet) Status(context.Context) (*ipc.StatusReport, error) { return f.st, nil }
func (f *fakeWallet) Begin(context.Context, string, ipc.Body) (*ipc.Challenge, error) {
	return f.ch, nil
}
func (f *fakeWallet) Complete(_ context.Context, c *ipc.CompleteAuthorization) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *c
	cp.Password = append([]byte(nil), c.Password...)
	f.completed = append(f.completed, &cp)
	return f.refuse
}
func (f *fakeWallet) Reject(_ context.Context, id string) error {
	f.rejected = append(f.rejected, id)
	return nil
}
func (f *fakeWallet) FreezeAll(context.Context) error { f.frozen++; return nil }

const approvalID = "ap_aaaaaaaaaaaaaaaaaaaaaaaaaa"

func newFake(method string) *fakeWallet {
	exp := time.Now().Add(5 * time.Minute).Unix()
	return &fakeWallet{
		st: &ipc.StatusReport{Unlocked: true,
			Wallets:   []ipc.WalletStatus{{Wallet: ipc.Wallet{ID: "w_aaaaaaaaaaaaaaaaaaaaaaaaaa", Label: "agent", Mode: "B"}}},
			Approvals: []ipc.Approval{{ID: approvalID, WalletID: "w_aaaaaaaaaaaaaaaaaaaaaaaaaa", Spend: ipc.Spend{Lovelace: 4_000_000}, ExpiresAt: exp}}},
		ch: &ipc.Challenge{AuthID: make([]byte, 16), Summary: []string{"Pay 4.000000 ADA to addr_test1qz..."}, Methods: []string{method},
			ExpiresAt: exp, RPID: "mcpcardano", ClientDataHash: make([]byte, 32)},
	}
}

// drive feeds a message to the view and runs what it asks for, except the
// tick that waits for the next refresh.
func drive(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	for msg != nil {
		next, cmd := m.Update(msg)
		m, msg = next.(Model), nil
		if cmd == nil {
			break
		}
		out := make(chan tea.Msg, 1)
		go func() { out <- cmd() }()
		select {
		case msg = <-out:
		case <-time.After(300 * time.Millisecond): // the refresh tick
		}
		if _, quit := msg.(tea.QuitMsg); quit {
			break
		}
	}
	return m
}

func press(t *testing.T, m Model, keys ...string) Model {
	t.Helper()
	for _, k := range keys {
		var msg tea.KeyPressMsg
		switch k {
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		case "backspace":
			msg = tea.KeyPressMsg{Code: tea.KeyBackspace}
		case "down":
			msg = tea.KeyPressMsg{Code: tea.KeyDown}
		default:
			msg = tea.KeyPressMsg{Code: []rune(k)[0], Text: k}
		}
		m = drive(t, m, msg)
	}
	return m
}

func start(t *testing.T, f *fakeWallet, slot *softkey.Slot) Model {
	m := New(context.Background(), f, slot.Open, "preprod")
	return drive(t, m, m.Init()())
}

// TestApproveWithPassword: the summary is the wallet's, the password is
// never drawn, it goes to the wallet once and is wiped.
func TestApproveWithPassword(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := start(t, f, &softkey.Slot{})
	if v := m.content(); !strings.Contains(v, approvalID) || !strings.Contains(v, "spends 4.000000 ADA") {
		t.Fatalf("the approvals:\n%s", v)
	}
	m = press(t, m, "enter")
	if v := m.content(); !strings.Contains(v, "Pay 4.000000 ADA to addr_test1qz...") || !strings.Contains(v, "[a] approve (password)") {
		t.Fatalf("the summary:\n%s", v)
	}
	m = press(t, m, "a", "s", "e", "c", "r", "x", "backspace", "e", "t")
	if v := m.content(); strings.Contains(v, "secret") || !strings.Contains(v, "••••••") {
		t.Fatalf("while typing:\n%s", v)
	}
	m = press(t, m, "enter")
	if len(f.completed) != 1 || string(f.completed[0].Password) != "secret" || f.completed[0].Assertion != nil {
		t.Fatalf("completed %+v", f.completed)
	}
	if m.secret != nil || !strings.Contains(m.content(), "Approved") {
		t.Errorf("after approving: %q\n%s", m.secret, m.content())
	}
}

// TestWrongPassword: the authorization stays open, and Esc and an empty
// answer decline without asking the wallet.
func TestWrongPassword(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.refuse = &ipc.Error{Code: ipc.AuthFailed, Detail: "wrong password"}
	m := start(t, f, &softkey.Slot{})
	m = press(t, m, "enter", "a", "x", "enter")
	if m.stage != reading || !strings.Contains(m.content(), "! ipc: AUTH_FAILED: wrong password") {
		t.Errorf("after a wrong password, stage %d:\n%s", m.stage, m.content())
	}
	m = press(t, m, "a", "y", "esc", "a", "enter")
	if len(f.completed) != 1 || m.stage != reading {
		t.Errorf("declined: %d completions, stage %d", len(f.completed), m.stage)
	}
	m = press(t, m, "esc")
	if m.stage != browsing {
		t.Errorf("back: stage %d", m.stage)
	}
}

// TestApproveWithKey: with a key registered, the view waits for one and
// sends its assertion; with the PIN when the action takes it.
func TestApproveWithKey(t *testing.T) {
	f := newFake(ipc.MethodKey)
	key := softkey.New("YubiKey", "1234")
	f.ch.Credentials = [][]byte{key.Credential.CredentialID()}
	slot := &softkey.Slot{}
	slot.Insert(key)
	m := start(t, f, slot)
	m = press(t, m, "enter")
	if !strings.Contains(m.content(), "[a] approve (touch of a registered key)") {
		t.Fatalf("the summary:\n%s", m.content())
	}
	m = press(t, m, "a")
	if len(f.completed) != 1 || f.completed[0].Password != nil || f.completed[0].Assertion == nil {
		t.Fatalf("completed %+v", f.completed)
	}

	f.ch.PIN = true
	m = press(t, m, "enter", "a", "1", "2", "3", "4", "enter")
	if len(f.completed) != 2 || key.Retries != 8 {
		t.Errorf("with the PIN: %d completions, %d tries left", len(f.completed), key.Retries)
	}
	m = press(t, m, "enter", "a", "0", "0", "0", "0", "enter")
	if len(f.completed) != 2 || m.stage != reading || !strings.Contains(m.content(), "PIN was wrong") {
		t.Errorf("a wrong PIN: %d completions, stage %d\n%s", len(f.completed), m.stage, m.content())
	}
}

// TestNoKey: with no key inserted, the view says so once the authorization
// expires.
func TestNoKey(t *testing.T) {
	f := newFake(ipc.MethodKey)
	f.ch.ExpiresAt = time.Now().Add(time.Second).Unix()
	f.ch.Credentials = [][]byte{{1}}
	m := start(t, f, &softkey.Slot{})
	m = press(t, m, "enter")
	next, cmd := m.Update(tea.KeyPressMsg{Code: 'a', Text: "a"})
	if !strings.Contains(next.(Model).content(), "Insert and touch a registered security key") {
		t.Errorf("while waiting:\n%s", next.(Model).content())
	}
	m = drive(t, next.(Model), cmd())
	if !strings.Contains(m.content(), "no security key was inserted") || len(f.completed) != 0 {
		t.Errorf("after the wait:\n%s", m.content())
	}
}

// TestRejectAndFreeze: rejecting and freezing take no authorization.
func TestRejectAndFreeze(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := start(t, f, &softkey.Slot{})
	m = press(t, m, "r")
	m = press(t, m, "f")
	if len(f.rejected) != 1 || f.rejected[0] != approvalID || f.frozen != 1 || !strings.Contains(m.content(), "Every wallet is frozen") {
		t.Errorf("rejected %v, frozen %d\n%s", f.rejected, f.frozen, m.content())
	}
	if _, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"}); cmd == nil || cmd() != tea.Quit() {
		t.Error("q does not quit")
	}
}

// TestVisible: what the view draws has no control sequence, whatever the
// wallet or a key sent.
func TestVisible(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.st.Wallets[0].Wallet.Label = "evil\x1b[2J\x1b]0;owned\x07"
	f.ch.Summary = []string{"bidi \u202egnp.exe", "bell\x07"}
	m := start(t, f, &softkey.Slot{})
	views := m.content()
	m = press(t, m, "enter")
	views += m.content()
	for _, bad := range []string{"\x1b", "\x07", "\u202e"} {
		if strings.Contains(views, bad) {
			t.Errorf("the view draws %q", bad)
		}
	}
	if !strings.Contains(views, "evil?[2J?]0;owned?") || !strings.Contains(views, "bidi ?gnp.exe") {
		t.Errorf("views:\n%s", views)
	}
}
