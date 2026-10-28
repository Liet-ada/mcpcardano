// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"context"
	"strings"
	"testing"

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

	w.Restart(t)
	if _, err := conn.Status(ctx); err == nil {
		t.Fatal("the connection outlived the wallet")
	}
	m = drive(t, m, tea.Msg(tick{}))
	if v := plain(press(t, m, "esc")); !strings.Contains(v, "● LOCKED") || strings.Contains(v, "ERROR") {
		t.Errorf("after the restart, the view did not connect again:\n%s", v)
	}
}
