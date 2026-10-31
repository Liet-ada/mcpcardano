// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd_test

import (
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/test/fidokit"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

func showPolicy(t *testing.T, admin *ipc.Client, id string) ipc.WalletPolicy {
	t.Helper()
	var p ipc.WalletPolicy
	if err := admin.Call(ctx, ipc.MsgShowPolicy, &ipc.WalletRef{WalletID: id}, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func freeze(t *testing.T, admin *ipc.Client, id string) {
	t.Helper()
	if err := admin.Call(ctx, ipc.MsgFreeze, &ipc.Freeze{WalletID: id}, &ipc.Empty{}); err != nil {
		t.Fatal(err)
	}
}

func frozen(t *testing.T, admin *ipc.Client, id string) bool {
	t.Helper()
	return showPolicy(t, admin, id).Policy.Frozen
}

// cancelled completes an authorization that a freeze should have cancelled.
func cancelled(t *testing.T, admin *ipc.Client, ch *ipc.Challenge) {
	t.Helper()
	if err := walletkit.Complete(admin, walletkit.WithPassword(ch), nil); walletkit.Code(err) != ipc.AuthExpired {
		t.Errorf("after the freeze: %v", err)
	}
}

// TestFreezeCancels: what was under way on a wallet when it froze does not
// run, whichever way it froze; freezing every wallet cancels the same.
func TestFreezeCancels(t *testing.T) {
	for name, stop := range map[string]func(*testing.T, *ipc.Client, string){
		"freeze":     freeze,
		"freeze all": func(t *testing.T, admin *ipc.Client, _ string) { freeze(t, admin, "") },
	} {
		t.Run(name, func(t *testing.T) {
			_, admin, _, wallet := setup(t)

			pol := showPolicy(t, admin, wallet.ID)
			before := pol.Policy.Limits.PerTx
			pol.Policy.Limits.PerTx++
			change, err := walletkit.Begin(admin, ipc.ActChangePolicy, &pol)
			if err != nil {
				t.Fatal(err)
			}
			session, err := walletkit.Begin(admin, ipc.ActOpenSession, &ipc.OpenSession{WalletID: wallet.ID, Seconds: 3600, MaxLovelace: 5})
			if err != nil {
				t.Fatal(err)
			}
			phrase, err := walletkit.Begin(admin, ipc.ActShowRecoveryPhrase, &ipc.WalletRef{WalletID: wallet.ID})
			if err != nil {
				t.Fatal(err)
			}
			stop(t, admin, wallet.ID)
			cancelled(t, admin, change)
			cancelled(t, admin, session)
			cancelled(t, admin, phrase)
			got := showPolicy(t, admin, wallet.ID)
			if !got.Policy.Frozen || got.Policy.Limits.PerTx != before {
				t.Errorf("the policy after the freeze: %+v", got.Policy)
			}
			if st := status(t, admin); st.Wallets[0].Session != nil {
				t.Errorf("a session opened: %+v", st.Wallets[0].Session)
			}

			// An unfreeze opened on the frozen wallet, and a second freeze.
			undo, err := walletkit.Begin(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID})
			if err != nil {
				t.Fatal(err)
			}
			stop(t, admin, wallet.ID)
			cancelled(t, admin, undo)
			if !frozen(t, admin, wallet.ID) {
				t.Error("an unfreeze opened before the freeze ran")
			}
		})
	}
}

// TestFreezeLeavesTheRest: freezing a wallet leaves what is under way on
// another, and freezing every wallet leaves what is of no wallet.
func TestFreezeLeavesTheRest(t *testing.T) {
	_, admin, service, wallet := setup(t)
	other := walletkit.CreateWallet(t, service, "other")
	freeze(t, admin, other.ID)
	undo, err := walletkit.Begin(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: other.ID})
	if err != nil {
		t.Fatal(err)
	}
	freeze(t, admin, wallet.ID)
	if err := walletkit.Complete(admin, walletkit.WithPassword(undo), nil); err != nil {
		t.Fatalf("the unfreeze of another wallet: %v", err)
	}
	if frozen(t, admin, other.ID) || !frozen(t, admin, wallet.ID) {
		t.Errorf("frozen: %v and %v", frozen(t, admin, other.ID), frozen(t, admin, wallet.ID))
	}

	create, err := walletkit.Begin(admin, ipc.ActCreateWallet, &ipc.CreateWallet{Label: "new"})
	if err != nil {
		t.Fatal(err)
	}
	freeze(t, admin, "")
	if err := walletkit.Complete(admin, walletkit.WithPassword(create), &ipc.Wallet{}); err != nil {
		t.Errorf("creating a wallet, which is of none: %v", err)
	}
}

// TestRecoveryCancels: starting a recovery freezes every wallet, and stops
// what was under way on them as a freeze does.
func TestRecoveryCancels(t *testing.T) {
	_, admin, _, wallet := setup(t)
	key := fidokit.New(fidokit.ES256)
	if err := walletkit.AddKey(admin, key, "key", walletkit.WithPassword); err != nil {
		t.Fatal(err)
	}
	pol := showPolicy(t, admin, wallet.ID)
	before := pol.Policy.Limits.PerTx
	pol.Policy.Limits.PerTx++
	ch, err := walletkit.Begin(admin, ipc.ActChangePolicy, &pol)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActStartRecovery, &ipc.Empty{}, &ipc.Recovery{}); err != nil {
		t.Fatal(err)
	}
	if err := walletkit.Complete(admin, walletkit.Touch(key)(ch), &ipc.PolicyHash{}); walletkit.Code(err) != ipc.AuthExpired {
		t.Errorf("after the recovery started: %v", err)
	}
	if got := showPolicy(t, admin, wallet.ID); !got.Policy.Frozen || got.Policy.Limits.PerTx != before {
		t.Errorf("the policy during the recovery: %+v", got.Policy)
	}
}

// TestFreezeKeepsTheApproval: a freeze cancels the authorization of an
// approval, not the approval: it can be approved once unfrozen, and no
// witness leaves meanwhile.
func TestFreezeKeepsTheApproval(t *testing.T) {
	w, admin, service, wallet := setup(t)
	pol := showPolicy(t, admin, wallet.ID)
	pol.Mode, pol.Policy.Limits.ApprovalThreshold = "B", 1_000_000
	if _, err := walletkit.Authorize(admin, ipc.ActChangePolicy, &pol, &ipc.PolicyHash{}); err != nil {
		t.Fatal(err)
	}
	body := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 7, 0), 5_000_000, w.Clock))
	res, err := walletkit.Sign(service, wallet.ID, body, nil)
	if err != nil || res.Status != ipc.PendingApproval {
		t.Fatalf("the payment: %+v, %v", res, err)
	}
	approve := &ipc.ApproveDraft{ApprovalID: res.ApprovalID}
	ch, err := walletkit.Begin(admin, ipc.ActApproveDraft, approve)
	if err != nil {
		t.Fatal(err)
	}
	freeze(t, admin, wallet.ID)
	cancelled(t, admin, ch)
	var as ipc.ApprovalStatus
	service.Call(ctx, ipc.MsgGetApprovalStatus, &ipc.GetApprovalStatus{ApprovalID: res.ApprovalID}, &as)
	if as.Status != ipc.ApprovalPending || len(as.Witnesses) != 0 {
		t.Fatalf("the approval after the freeze: %+v", as)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActApproveDraft, approve, nil); err != nil {
		t.Errorf("approving once unfrozen: %v", err)
	}
}

// TestPolicyKeepsFrozen: a policy never changes whether its wallet is frozen:
// the wallet refuses one that says otherwise when it opens, and when it runs.
func TestPolicyKeepsFrozen(t *testing.T) {
	_, admin, _, wallet := setup(t)
	pol := showPolicy(t, admin, wallet.ID)
	before := pol.Policy.Limits.PerTx
	pol.Policy.Limits.PerTx++

	pol.Policy.Frozen = true
	if _, err := walletkit.Begin(admin, ipc.ActChangePolicy, &pol); walletkit.Code(err) != ipc.Frozen {
		t.Errorf("freezing with a policy: %v", err)
	}
	pol.Policy.Frozen = false
	freeze(t, admin, wallet.ID)
	if _, err := walletkit.Begin(admin, ipc.ActChangePolicy, &pol); walletkit.Code(err) != ipc.Frozen {
		t.Errorf("thawing with a policy: %v", err)
	}
	if !frozen(t, admin, wallet.ID) {
		t.Error("the wallet thawed")
	}

	// As it is now, it runs, and the wallet stays frozen.
	pol.Policy.Frozen = true
	if _, err := walletkit.Authorize(admin, ipc.ActChangePolicy, &pol, &ipc.PolicyHash{}); err != nil {
		t.Fatal(err)
	}
	got := showPolicy(t, admin, wallet.ID)
	if !got.Policy.Frozen || got.Policy.Limits.PerTx != before+1 {
		t.Fatalf("the policy: %+v", got.Policy)
	}

	// Opened while frozen, it does not freeze the wallet again after an
	// unfreeze.
	pol.Policy.Limits.PerTx++
	ch, err := walletkit.Begin(admin, ipc.ActChangePolicy, &pol)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if err := walletkit.Complete(admin, walletkit.WithPassword(ch), &ipc.PolicyHash{}); walletkit.Code(err) != ipc.Frozen {
		t.Errorf("after the unfreeze: %v", err)
	}
	got = showPolicy(t, admin, wallet.ID)
	if got.Policy.Frozen || got.Policy.Limits.PerTx != before+1 {
		t.Errorf("the policy after the unfreeze: %+v", got.Policy)
	}
}

// TestFreezeAudit: the audit says how many authorizations a freeze cancelled.
func TestFreezeAudit(t *testing.T) {
	_, admin, _, wallet := setup(t)
	for range 2 {
		if _, err := walletkit.Begin(admin, ipc.ActShowRecoveryPhrase, &ipc.WalletRef{WalletID: wallet.ID}); err != nil {
			t.Fatal(err)
		}
	}
	freeze(t, admin, wallet.ID)
	entries := auditLog(t, admin)
	last := entries[len(entries)-1]
	if last.Type != "frozen" || body(t, last)["cancelled"] != uint64(2) {
		t.Errorf("the entry: %s, %v", last.Type, body(t, last))
	}
}
