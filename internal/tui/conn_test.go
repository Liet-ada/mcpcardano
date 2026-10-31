// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/test/softkey"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

// TestViewApproves drives the view over a real admin connection: a payment
// of mode B waiting for the person is read with the summary the wallet
// computed and approved with a registered key's touch, and the wallet then
// has the witnesses for the server. After the wallet restarts, the view
// connects again on its own.
func TestViewApproves(t *testing.T) {
	ctx := context.Background()
	w := walletkit.Start(t)
	admin, service := w.Admin(t), w.Service(t)
	walletkit.Unlock(t, admin)
	wallet := walletkit.CreateWallet(t, service, "agent")
	var pol ipc.WalletPolicy
	if err := admin.Call(ctx, ipc.MsgShowPolicy, &ipc.WalletRef{WalletID: wallet.ID}, &pol); err != nil {
		t.Fatal(err)
	}
	pol.Mode, pol.Policy.Limits.ApprovalThreshold = "B", 1_000_000
	if _, err := walletkit.Authorize(admin, ipc.ActChangePolicy, &pol, &ipc.PolicyHash{}); err != nil {
		t.Fatal(err)
	}
	key := softkey.New("YubiKey", "1234")
	if err := walletkit.AddKey(admin, key.Credential, "YubiKey", walletkit.WithPassword); err != nil {
		t.Fatal(err)
	}
	body := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 7, 0), 5_000_000, w.Clock))
	res, err := walletkit.Sign(service, wallet.ID, body, nil)
	if err != nil || res.Status != ipc.PendingApproval {
		t.Fatalf("the payment: %+v, %v", res, err)
	}

	slot := &softkey.Slot{}
	slot.Insert(key)
	conn := &Conn{Socket: w.Config.AdminSocket, Hello: walletkit.Hello()}
	defer conn.Close()
	m := New(ctx, conn, slot.Open, "preprod")
	m = drive(t, m, m.Init()())
	// The admin socket gives each wallet's policy with what it spent.
	if s := plain(press(t, m, "2")); !strings.Contains(s, "APPROVE ABOVE") || !strings.Contains(s, "1.00") {
		t.Fatalf("the wallet's limits:\n%s", s)
	}
	m = press(t, m, "3")
	if !strings.Contains(plain(m), res.ApprovalID) {
		t.Fatalf("the view:\n%s", plain(m))
	}
	m = press(t, m, "enter")
	if s := plain(m); !strings.Contains(s, "5.170000 ADA") || !strings.Contains(s, "TOUCH OF A REGISTERED KEY") {
		t.Fatalf("the summary:\n%s", s)
	}
	m = press(t, m, "a")
	if !strings.Contains(plain(m), "Approved") {
		t.Fatalf("after the touch:\n%s", plain(m))
	}
	var st ipc.ApprovalStatus
	if err := service.Call(ctx, ipc.MsgGetApprovalStatus, &ipc.GetApprovalStatus{ApprovalID: res.ApprovalID}, &st); err != nil || st.Status != ipc.ApprovalApproved {
		t.Errorf("the approval: %+v, %v", st, err)
	}

	// Every wallet frozen with f, and the agent's unfrozen again from its
	// tab with a touch.
	m = press(t, m, "f")
	if st, _ := conn.Status(ctx); !st.Wallets[0].Wallet.Frozen {
		t.Fatal("f did not freeze the wallet")
	}
	m = press(t, m, "2", "u", "a")
	if st, _ := conn.Status(ctx); st.Wallets[0].Wallet.Frozen || !strings.Contains(plain(m), "is unfrozen") {
		t.Fatalf("u did not unfreeze the wallet:\n%s", plain(m))
	}

	w.Restart(t)
	if _, err := conn.Status(ctx); err == nil {
		t.Fatal("the connection outlived the wallet")
	}
	m = drive(t, m, tea.Msg(tick{}))
	if v := plain(press(t, m, "esc")); !strings.Contains(v, "● LOCKED") || strings.Contains(v, "ERROR") {
		t.Errorf("after the restart, the view did not connect again:\n%s", v)
	}
}

// authorized answers the dialog with the key's touch, and its PIN if the
// action takes it.
func authorized(t *testing.T, m Model) Model {
	t.Helper()
	if m.auth == nil {
		t.Fatalf("no authorization:\n%s", plain(m))
	}
	if m.auth.ch.PIN {
		return press(t, m, "a", "1", "2", "3", "4", "enter")
	}
	return press(t, m, "a")
}

// TestViewWalletActions drives every action of a wallet over a real admin
// connection, each authorized with a software key: the wallet is the one that
// says they happened.
func TestViewWalletActions(t *testing.T) {
	ctx := context.Background()
	w := walletkit.Start(t)
	admin, service := w.Admin(t), w.Service(t)
	walletkit.Unlock(t, admin)
	agent := walletkit.CreateWallet(t, service, "agent")
	key := softkey.New("YubiKey", "1234")
	if err := walletkit.AddKey(admin, key.Credential, "YubiKey", walletkit.WithPassword); err != nil {
		t.Fatal(err)
	}
	slot := &softkey.Slot{}
	slot.Insert(key)
	conn := &Conn{Socket: w.Config.AdminSocket, Hello: walletkit.Hello()}
	defer conn.Close()
	m := New(ctx, conn, slot.Open, "preprod")
	m = drive(t, m, m.Init()())
	find := func(label string) *ipc.WalletStatus {
		st, err := conn.Status(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for i := range st.Wallets {
			if st.Wallets[i].Wallet.Label == label {
				return &st.Wallets[i]
			}
		}
		return nil
	}

	// A session of 30 minutes up to 12.5 ADA, and closing it.
	m = press(t, m, "2", "s", "backspace", "backspace", "3", "0", "m", "enter", "1", "2", ".", "5", "enter")
	if s := plain(m); !strings.Contains(s, "for 30m0s, up to 12.500000 ADA") {
		t.Fatalf("the summary of the session:\n%s", s)
	}
	m = authorized(t, m)
	ws := find("agent")
	if ws.Session == nil || ws.Session.Remaining != 12_500_000 || !strings.Contains(plain(m), "close session") {
		t.Fatalf("the session %+v:\n%s", ws.Session, plain(m))
	}
	m = press(t, m, "s")
	if find("agent").Session != nil || !strings.Contains(plain(m), "Session closed") {
		t.Fatalf("the session was not closed:\n%s", plain(m))
	}

	// What the wallet signed and did not see on the chain, released.
	body := walletkit.Encode(t, walletkit.Payment(agent.Address, walletkit.Address(6, 7, 0), 5_000_000, w.Clock))
	res, err := walletkit.Sign(service, agent.ID, body, nil)
	if err != nil || res.Status != ipc.Signed {
		t.Fatalf("the payment: %+v, %v", res, err)
	}
	w.Clock.Advance(11 * time.Minute)
	m = press(t, m, "b", "space", "enter")
	if s := plain(m); !strings.Contains(s, "Release 5.170000 ADA") {
		t.Fatalf("the summary of the release:\n%s", s)
	}
	if m = authorized(t, m); !strings.Contains(plain(m), "Released 5.170000 ADA") {
		t.Fatalf("after the release:\n%s", plain(m))
	}
	if left, err := conn.Expired(ctx, agent.ID); err != nil || len(left) != 0 {
		t.Fatalf("still to release: %v, %v", left, err)
	}

	// A wallet created, and one restored from a phrase.
	m = press(t, m, "c", "m", "i", "a", "enter")
	m = authorized(t, m)
	if find("mia") == nil || !strings.Contains(plain(m), "Wallet mia created") {
		t.Fatalf("no wallet was created:\n%s", plain(m))
	}
	m = press(t, m, "R", "o", "l", "d", "enter")
	for range 23 {
		m = press(t, m, "a", "b", "a", "n", "enter")
	}
	m = press(t, m, "a", "r", "t", "enter")
	m = authorized(t, m)
	restored := find("old")
	if restored == nil || !strings.Contains(plain(m), "Wallet old restored") {
		t.Fatalf("no wallet was restored:\n%s", plain(m))
	}
	if m.restore != nil {
		t.Error("the phrase stayed on its screen")
	}

	// Its phrase, back from the wallet with the PIN and the touch.
	st, _ := conn.Status(ctx)
	for i := range st.Wallets {
		if st.Wallets[i].Wallet.ID == restored.Wallet.ID {
			m.wallets.at = i
		}
	}
	m = authorized(t, press(t, m, "p"))
	if m.phrase == nil || string(m.phrase.words) != strings.Repeat("abandon ", 23)+"art" {
		t.Fatalf("the phrase:\n%s", plain(m))
	}
	if s := plain(press(t, m, "esc")); strings.Contains(s, "abandon") {
		t.Errorf("the phrase stayed on show:\n%s", s)
	}
}
