// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package e2e

import (
	"context"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/tui"
)

// TestViewReadsTheServer: what the view expects of each tool is what a real
// server answers, a draft under way included.
func TestViewReadsTheServer(t *testing.T) {
	ctx := context.Background()
	st := newStack(t)
	defer st.stopServer()
	var created struct {
		WalletID string `json:"wallet_id"`
		Address  string `json:"address"`
	}
	if err := st.call("create_wallet", map[string]any{"label": "agent"}, &created); err != nil {
		t.Fatal(err)
	}
	st.fund(created.Address, 3, 40_000_000)
	c := &tui.ServerConn{Socket: st.settings.Socket, Version: "e2e"}
	defer c.Close()

	wallets, err := c.Wallets(ctx)
	if err != nil || len(wallets) != 1 || wallets[0].ID != created.WalletID || wallets[0].Mode != "C" {
		t.Fatalf("wallets: %+v, %v", wallets, err)
	}
	o, err := c.Overview(ctx, created.WalletID)
	if err != nil || o.WalletID != created.WalletID || o.Address != created.Address || o.Balance.Lovelace != "120000000" || o.UTxOs != 3 {
		t.Fatalf("overview: %+v, %v", o, err)
	}
	net, err := c.Network(ctx)
	if err != nil || net.Network != "preprod" || net.Tip == nil || net.Tip.Slot == "" || len(net.DataSources) == 0 || net.DataSources[0].Status != "ok" || net.DataSource.Name == "" {
		t.Fatalf("network: %+v, %v", net, err)
	}

	d := st.pay(created.WalletID, enterprise(9), "5000000")
	drafts, err := c.Drafts(ctx)
	if err != nil || len(drafts) != 1 || drafts[0].ID != d.DraftID || drafts[0].WalletID != created.WalletID || drafts[0].State == "" || drafts[0].Fee == "" || drafts[0].ExpiresAt == "" {
		t.Fatalf("drafts: %+v, %v", drafts, err)
	}
	if o, err = c.Overview(ctx, created.WalletID); err != nil || o.LiveDrafts != 1 {
		t.Errorf("overview with a draft: %+v, %v", o, err)
	}
}
