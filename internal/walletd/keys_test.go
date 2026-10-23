// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/authz"
	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/test/fidokit"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

// auditLog returns the type and body of every entry of the audit log.
func auditLog(t *testing.T, admin *ipc.Client) []audit.Entry {
	t.Helper()
	records, _ := cborx.New(cborx.RecordLimits())
	var out []audit.Entry
	for from := uint64(1); from != 0; {
		var page ipc.AuditPage
		if err := admin.Call(ctx, ipc.MsgShowAudit, &ipc.ShowAudit{From: from, Limit: 100}, &page); err != nil {
			t.Fatal(err)
		}
		for _, raw := range page.Entries {
			var e audit.Entry
			if err := records.Unmarshal(raw, &e); err != nil {
				t.Fatal(err)
			}
			out = append(out, e)
		}
		from = page.Next
	}
	return out
}

// body decodes an audit entry's body.
func body(t *testing.T, e audit.Entry) map[string]any {
	t.Helper()
	records, _ := cborx.New(cborx.RecordLimits())
	var m map[string]any
	if err := records.Unmarshal(e.Body, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func status(t *testing.T, admin *ipc.Client) ipc.StatusReport {
	t.Helper()
	var st ipc.StatusReport
	if err := admin.Call(ctx, ipc.MsgStatus, &ipc.Empty{}, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// withKey starts a wallet with one wallet and a registered key.
func withKey(t *testing.T, alg int) (*walletkit.Wallet, *ipc.Client, ipc.Wallet, *fidokit.Key) {
	t.Helper()
	w, admin, _, wallet := setup(t)
	key := fidokit.New(alg)
	if err := walletkit.AddKey(admin, key, "YubiKey", walletkit.WithPassword); err != nil {
		t.Fatal(err)
	}
	return w, admin, wallet, key
}

// TestKeyReplacesPassword: once a key is registered, its touch authorizes
// and the password no longer does (paper, section 6.6). The challenge
// carries what the key needs, and the audit log names the key.
func TestKeyReplacesPassword(t *testing.T) {
	_, admin, _, wallet := setup(t)
	key := fidokit.New(fidokit.EdDSA)
	add := &ipc.AddKey{Name: "YubiKey", AuthenticatorData: key.MakeCredential(fidokit.Options{})}
	summary, err := walletkit.Authorize(admin, ipc.ActAddKey, add, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.Join(summary, "\n"); !strings.Contains(s, authz.KeyID(key.CredentialID())) || !strings.Contains(s, "EdDSA") {
		t.Errorf("summary %q", s)
	}
	st := status(t, admin)
	if len(st.Keys) != 1 || st.Keys[0].Name != "YubiKey" || st.Keys[0].Alg != ipc.AlgEdDSA || !bytes.Equal(st.Keys[0].CredentialID, key.CredentialID()) {
		t.Fatalf("keys %+v", st.Keys)
	}

	ch, err := walletkit.Begin(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Methods[0] != ipc.MethodKey || ch.RPID != authz.RPID || ch.PIN || len(ch.Credentials) != 1 ||
		!bytes.Equal(ch.Credentials[0], key.CredentialID()) || len(ch.ClientDataHash) != 32 {
		t.Fatalf("challenge %+v", ch)
	}
	if err := walletkit.Complete(admin, walletkit.WithPassword(ch), nil); walletkit.Code(err) != ipc.AuthFailed {
		t.Errorf("the password with a key registered: %v", err)
	}
	if err := walletkit.Complete(admin, walletkit.Touch(key)(ch), nil); err != nil {
		t.Fatalf("the touch: %v", err)
	}

	var by []string
	for _, e := range auditLog(t, admin) {
		if e.Type == "authorization.completed" {
			b := body(t, e)
			by = append(by, b["method"].(string)+" "+b["action"].(string))
			if b["method"] == ipc.MethodKey && b["key"] != authz.KeyID(key.CredentialID()) {
				t.Errorf("the audit log names key %v", b["key"])
			}
		}
	}
	if strings.Join(by, ", ") != "password add_key, fido2 unfreeze" {
		t.Errorf("authorizations %q", by)
	}
}

// TestKeyPIN: the actions that change who controls the wallets, or show a
// seed, take the key's PIN besides the touch; the others only the touch
// (decision 123).
func TestKeyPIN(t *testing.T) {
	_, admin, wallet, key := withKey(t, fidokit.ES256)
	var template ipc.Template
	if err := admin.Call(ctx, ipc.MsgShowTemplate, &ipc.Empty{}, &template); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		action string
		params ipc.Body
		pin    bool
	}{
		{ipc.ActOpenSession, &ipc.OpenSession{WalletID: wallet.ID, Seconds: 60, MaxLovelace: 1_000_000}, false},
		{ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID}, false},
		{ipc.ActShowRecoveryPhrase, &ipc.WalletRef{WalletID: wallet.ID}, true},
		{ipc.ActSetTemplate, &template, true},
	} {
		ch, err := walletkit.Begin(admin, tc.action, tc.params)
		if err != nil || ch.PIN != tc.pin {
			t.Fatalf("%s: PIN %v, %v", tc.action, ch.PIN, err)
		}
		if tc.pin {
			err := walletkit.Complete(admin, walletkit.WithKey(key, fidokit.Options{})(ch), nil)
			if walletkit.Code(err) != ipc.AuthFailed || !strings.Contains(err.Error(), "PIN") {
				t.Errorf("%s without the PIN: %v", tc.action, err)
			}
		}
		if err := walletkit.Complete(admin, walletkit.Touch(key)(ch), ipc.NewResult(tc.action)); err != nil {
			t.Errorf("%s: %v", tc.action, err)
		}
	}
}

// TestKeyRefusals: an assertion is refused for each rule it breaks (section
// 6.2, step 5), the refusal goes to the audit log, and the challenge stays
// open for the right one.
func TestKeyRefusals(t *testing.T) {
	_, admin, wallet, key := withKey(t, fidokit.ES256)
	stranger := fidokit.New(fidokit.ES256)
	forged := func(ch *ipc.Challenge) *ipc.CompleteAuthorization {
		c := walletkit.Touch(stranger)(ch)
		c.Assertion.CredentialID = key.CredentialID() // a registered id, another key's signature
		return c
	}
	replayed := func(ch *ipc.Challenge) *ipc.CompleteAuthorization {
		key.Counter = 0 // the key gives 1 again, the counter of its first touch
		return walletkit.Touch(key)(ch)
	}
	ch, err := walletkit.Begin(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := walletkit.Complete(admin, walletkit.Touch(key)(ch), nil); err != nil { // the counter is now 1
		t.Fatal(err)
	}
	refusals := []struct {
		name   string
		answer walletkit.Answer
		why    string
	}{
		{"an unregistered key", walletkit.Touch(stranger), "not registered"},
		{"another key's signature", forged, "signature"},
		{"another relying party", walletkit.WithKey(key, fidokit.Options{RPID: "example.com"}), "relying party"},
		{"no touch", walletkit.WithKey(key, fidokit.Options{NoTouch: true}), "not touched"},
		{"a credential that may be synced", walletkit.WithKey(key, fidokit.Options{Synced: true}), "synced"},
		{"a repeated counter", replayed, "counter"},
	}
	ch, _ = walletkit.Begin(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID})
	for _, r := range refusals {
		err := walletkit.Complete(admin, r.answer(ch), nil)
		if walletkit.Code(err) != ipc.AuthFailed || !strings.Contains(err.Error(), r.why) {
			t.Errorf("%s: %v", r.name, err)
		}
	}
	if err := walletkit.Complete(admin, walletkit.Touch(key)(ch), nil); err != nil {
		t.Errorf("the right touch after the refusals: %v", err)
	}
	n := 0
	for _, e := range auditLog(t, admin) {
		if e.Type == "key.refused" {
			n++
		}
	}
	if n != len(refusals) {
		t.Errorf("%d refusals in the audit log, want %d", n, len(refusals))
	}
}

// TestSyncedKeys: a credential that may be synced to a cloud is refused,
// unless the person allows them in config.json (paper, section 6.6).
func TestSyncedKeys(t *testing.T) {
	w, admin, _, _ := setup(t)
	synced := fidokit.New(fidokit.EdDSA)
	add := &ipc.AddKey{Name: "passkey", AuthenticatorData: synced.MakeCredential(fidokit.Options{Synced: true})}
	if _, err := walletkit.Begin(admin, ipc.ActAddKey, add); walletkit.Code(err) != ipc.Malformed || !strings.Contains(err.Error(), "synced") {
		t.Fatalf("a synced credential: %v", err)
	}
	w.Config.AllowSyncedKeys = true
	w.Restart(t)
	admin = w.Admin(t)
	walletkit.Unlock(t, admin)
	if _, err := walletkit.Authorize(admin, ipc.ActAddKey, add, nil); err != nil {
		t.Fatalf("a synced credential the person allowed: %v", err)
	}
	if _, err := walletkit.AuthorizeWith(admin, ipc.ActCreateWallet, &ipc.CreateWallet{Label: "x"}, &ipc.Wallet{},
		walletkit.WithKey(synced, fidokit.Options{Synced: true})); err != nil {
		t.Errorf("its touch: %v", err)
	}
}

// TestSecondKey: with a key registered, another is added with its touch and
// PIN, and the message covers the new credential; a key is removed with the
// touch of any registered key, and with none left the password authorizes
// again.
func TestSecondKey(t *testing.T) {
	_, admin, wallet, first := withKey(t, fidokit.ES256)
	second := fidokit.New(fidokit.EdDSA)
	if err := walletkit.AddKey(admin, second, "backup", walletkit.WithPassword); walletkit.Code(err) != ipc.AuthFailed {
		t.Errorf("a second key with the password: %v", err)
	}
	if err := walletkit.AddKey(admin, second, "backup", walletkit.WithKey(first, fidokit.Options{})); walletkit.Code(err) != ipc.AuthFailed {
		t.Errorf("a second key without the PIN: %v", err)
	}
	if err := walletkit.AddKey(admin, second, "backup", walletkit.Touch(first)); err != nil {
		t.Fatalf("a second key: %v", err)
	}
	for name, add := range map[string]*ipc.AddKey{
		"the same credential": {Name: "again", AuthenticatorData: second.MakeCredential(fidokit.Options{})},
		"the same name":       {Name: "backup", AuthenticatorData: fidokit.New(fidokit.ES256).MakeCredential(fidokit.Options{})},
	} {
		if _, err := walletkit.Begin(admin, ipc.ActAddKey, add); walletkit.Code(err) != ipc.Malformed {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Either key authorizes; the first is removed with the second's touch,
	// as when it is lost.
	ch, _ := walletkit.Begin(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID})
	if len(ch.Credentials) != 2 {
		t.Errorf("%d credentials in the challenge", len(ch.Credentials))
	}
	if err := walletkit.Complete(admin, walletkit.Touch(second)(ch), nil); err != nil {
		t.Error(err)
	}
	if _, err := walletkit.AuthorizeWith(admin, ipc.ActRemoveKey, &ipc.KeyRef{CredentialID: first.CredentialID()}, nil, walletkit.Touch(second)); err != nil {
		t.Fatalf("remove the first: %v", err)
	}
	if _, err := walletkit.AuthorizeWith(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID}, nil, walletkit.Touch(first)); walletkit.Code(err) != ipc.AuthFailed {
		t.Errorf("the removed key: %v", err)
	}
	summary, err := walletkit.AuthorizeWith(admin, ipc.ActRemoveKey, &ipc.KeyRef{CredentialID: second.CredentialID()}, nil, walletkit.Touch(second))
	if err != nil || !strings.Contains(strings.Join(summary, " "), "password authorizes again") {
		t.Fatalf("remove the last: %q, %v", summary, err)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID}, nil); err != nil {
		t.Errorf("the password with no key left: %v", err)
	}
}

// TestRecovery: with every key lost, the password starts a recovery: the
// wallets freeze, the password still authorizes nothing else, and a touch of
// a registered key cancels it. Once the wait is over, the keys are removed
// and the password authorizes again (decision 123).
func TestRecovery(t *testing.T) {
	w, admin, _, _ := setup(t)
	if _, err := walletkit.Authorize(admin, ipc.ActStartRecovery, &ipc.Empty{}, nil); walletkit.Code(err) != ipc.NotFound {
		t.Errorf("a recovery with no key: %v", err)
	}
	key := fidokit.New(fidokit.ES256)
	walletkit.AddKey(admin, key, "YubiKey", walletkit.WithPassword)
	wallet := status(t, admin).Wallets[0].Wallet

	var r ipc.Recovery
	start := w.Clock.Now()
	if _, err := walletkit.Authorize(admin, ipc.ActStartRecovery, &ipc.Empty{}, &r); err != nil {
		t.Fatal(err)
	}
	if r.EndsAt != start.Add(72*time.Hour).Unix() {
		t.Errorf("recovery %+v", r)
	}
	st := status(t, admin)
	if st.Recovery == nil || st.Recovery.EndsAt != r.EndsAt || !st.Wallets[0].Wallet.Frozen {
		t.Fatalf("status during the recovery: %+v, frozen %v", st.Recovery, st.Wallets[0].Wallet.Frozen)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActStartRecovery, &ipc.Empty{}, nil); walletkit.Code(err) != ipc.Malformed {
		t.Errorf("a second recovery: %v", err)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActShowRecoveryPhrase, &ipc.WalletRef{WalletID: wallet.ID}, &ipc.RecoveryPhrase{}); walletkit.Code(err) != ipc.AuthFailed {
		t.Errorf("the password during the wait: %v", err)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActCancelRecovery, &ipc.Empty{}, nil); walletkit.Code(err) != ipc.AuthFailed {
		t.Errorf("cancelled with the password: %v", err)
	}
	if _, err := walletkit.AuthorizeWith(admin, ipc.ActCancelRecovery, &ipc.Empty{}, nil, walletkit.Touch(key)); err != nil {
		t.Fatalf("cancelled with the key: %v", err)
	}
	if st := status(t, admin); st.Recovery != nil || len(st.Keys) != 1 || !st.Wallets[0].Wallet.Frozen {
		t.Errorf("after cancelling: %+v, %d keys, frozen %v", st.Recovery, len(st.Keys), st.Wallets[0].Wallet.Frozen)
	}

	// Again, and this time the wait runs out.
	walletkit.Authorize(admin, ipc.ActStartRecovery, &ipc.Empty{}, nil)
	w.Clock.Advance(72*time.Hour - time.Second)
	if st := status(t, admin); st.Recovery == nil || len(st.Keys) != 1 {
		t.Fatal("the recovery ended early")
	}
	w.Clock.Advance(time.Second)
	if st := status(t, admin); st.Recovery != nil || len(st.Keys) != 0 || !st.Wallets[0].Wallet.Frozen {
		t.Errorf("after the wait: %+v, %d keys, frozen %v", st.Recovery, len(st.Keys), st.Wallets[0].Wallet.Frozen)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID}, nil); err != nil {
		t.Errorf("the password after the wait: %v", err)
	}
	var types []string
	for _, e := range auditLog(t, admin) {
		if strings.HasPrefix(e.Type, "recovery.") {
			types = append(types, e.Type)
		}
	}
	if strings.Join(types, " ") != "recovery.started recovery.cancelled recovery.started recovery.completed" {
		t.Errorf("audit %q", types)
	}
}

// TestKeyAcrossRestart: the keys and their counters are in state.cbor, so a
// restart keeps them, and an assertion that repeats a counter given before
// the restart is still refused. Unlock keeps taking the password.
func TestKeyAcrossRestart(t *testing.T) {
	w, admin, wallet, key := withKey(t, fidokit.EdDSA)
	unfreeze := &ipc.WalletRef{WalletID: wallet.ID}
	if _, err := walletkit.AuthorizeWith(admin, ipc.ActUnfreeze, unfreeze, nil, walletkit.Touch(key)); err != nil {
		t.Fatal(err)
	}
	w.Restart(t)
	admin = w.Admin(t)
	walletkit.Unlock(t, admin)
	key.Counter = 0 // the next assertion gives 1, as before the restart
	if _, err := walletkit.AuthorizeWith(admin, ipc.ActUnfreeze, unfreeze, nil, walletkit.Touch(key)); walletkit.Code(err) != ipc.AuthFailed {
		t.Errorf("a counter given before the restart: %v", err)
	}
	if _, err := walletkit.AuthorizeWith(admin, ipc.ActUnfreeze, unfreeze, nil, walletkit.Touch(key)); err != nil {
		t.Errorf("after the restart: %v", err)
	}
}
