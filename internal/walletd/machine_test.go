// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

// TestUnlockByMachine follows the unlock bound to the machine of decision
// 132 through restarts: systemd hands over the key of the machine in the
// directory of credentials, and the wallet starts unlocked once a password
// unlock has bound the key store to it. The password always opens.
func TestUnlockByMachine(t *testing.T) {
	w := walletkit.Start(t)
	w.Credentials = t.TempDir()
	key := filepath.Join(w.Credentials, "mcpcardano-wallet.unlock")
	setKey := func(k []byte) {
		t.Helper()
		if k == nil {
			os.Remove(key)
		} else if err := os.WriteFile(key, k, 0o400); err != nil {
			os.Chmod(key, 0o600)
			if err := os.WriteFile(key, k, 0o400); err != nil {
				t.Fatal(err)
			}
		}
	}
	unlocked := func() bool {
		t.Helper()
		return status(t, w.Admin(t)).Unlocked
	}
	// last returns the body of the last unlock in the audit log.
	last := func() map[string]any {
		t.Helper()
		admin, records := w.Admin(t), func() *cborx.Codec { c, _ := cborx.New(cborx.RecordLimits()); return c }()
		var body map[string]any
		var page ipc.AuditPage
		for from := uint64(1); from != 0; from = page.Next {
			if err := admin.Call(ctx, ipc.MsgShowAudit, &ipc.ShowAudit{From: from, Limit: 100}, &page); err != nil {
				t.Fatal(err)
			}
			for _, raw := range page.Entries {
				var e audit.Entry
				records.Unmarshal(raw, &e)
				if e.Type == "unlock" {
					body = nil
					records.Unmarshal(e.Body, &body)
				}
			}
		}
		return body
	}
	machine, other := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)

	// The first start with a key waits for the password, which binds it.
	setKey(machine)
	w.Restart(t)
	if unlocked() || last()["error"] == nil {
		t.Fatalf("a start before binding: unlocked %v, %v", unlocked(), last())
	}
	walletkit.Unlock(t, w.Admin(t))
	if e := last(); e["by"] != "password" || e["machine"] != true {
		t.Fatalf("the unlock that binds: %v", e)
	}
	wallet := walletkit.CreateWallet(t, w.Service(t), "agent")

	// From then on the wallet starts unlocked, and signs.
	w.Restart(t)
	if !unlocked() || last()["by"] != "machine" || last()["ok"] != true {
		t.Fatalf("a start with the key: unlocked %v, %v", unlocked(), last())
	}
	body := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 7, 0), 2_000_000, w.Clock))
	if res, err := walletkit.Sign(w.Service(t), wallet.ID, body, nil); err != nil || res.Status != ipc.Signed {
		t.Fatalf("signing after a start with the key: %+v, %v", res, err)
	}

	// Another key, as a credential made again, does not open; the password
	// does, and binds the new key.
	setKey(other)
	w.Restart(t)
	if unlocked() {
		t.Fatal("another key opened the key store")
	}
	walletkit.Unlock(t, w.Admin(t))
	w.Restart(t)
	if !unlocked() {
		t.Fatal("the new key was not bound")
	}

	// A key that cannot be read, or none, leaves the wallet locked; the
	// password opens, and unbinds it.
	for _, k := range [][]byte{other[:31], nil} {
		setKey(other)
		w.Restart(t)
		setKey(k)
		w.Restart(t)
		if unlocked() {
			t.Fatalf("key %x: started unlocked", k)
		}
		walletkit.Unlock(t, w.Admin(t))
		if e := last(); e["ok"] != true || e["machine"] != false {
			t.Fatalf("key %x: the unlock with the password: %v", k, e)
		}
		setKey(other)
		w.Restart(t)
		if unlocked() {
			t.Fatalf("key %x: the key store stayed bound", k)
		}
		walletkit.Unlock(t, w.Admin(t))
	}

	// Outside systemd there is no directory of credentials: nothing changes.
	w.Credentials = ""
	w.Restart(t)
	if unlocked() {
		t.Fatal("started unlocked without credentials")
	}
}
