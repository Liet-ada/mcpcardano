// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package wallet

import (
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/test/fidokit"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

// Rows M-16 to M-18 of the attack matrix come from another attacker: a
// malware that runs as the person. It reaches the admin socket and may have
// stolen the password, but it cannot touch the registered key (paper,
// section 6.6). Each test tries to unfreeze a frozen wallet, checks that it
// stayed frozen, and ends with the person's touch passing, so the refusals
// are not the wallet refusing everything.

// keyed is an attacker whose person registered a key and froze the wallet.
func keyed(t *testing.T) (*attacker, *fidokit.Key) {
	a := newAttacker(t)
	key := fidokit.New(fidokit.ES256)
	if err := walletkit.AddKey(a.admin, key, "YubiKey", walletkit.WithPassword); err != nil {
		t.Fatal(err)
	}
	if err := a.admin.Call(ctx, ipc.MsgFreeze, &ipc.Freeze{WalletID: a.wallet.ID}, &ipc.Empty{}); err != nil {
		t.Fatal(err)
	}
	return a, key
}

// try answers a new challenge to unfreeze the wallet with answer, wants code,
// and checks that the wallet stayed frozen.
func (a *attacker) try(name string, answer walletkit.Answer, code ipc.Code) {
	a.t.Helper()
	_, err := walletkit.AuthorizeWith(a.admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: a.wallet.ID}, nil, answer)
	if walletkit.Code(err) != code {
		a.t.Errorf("%s: %v, want %s", name, err, code)
	}
	a.frozen(name)
}

func (a *attacker) frozen(name string) {
	a.t.Helper()
	var st ipc.StatusReport
	if err := a.admin.Call(ctx, ipc.MsgStatus, &ipc.Empty{}, &st); err != nil {
		a.t.Fatal(err)
	}
	if !st.Wallets[0].Wallet.Frozen {
		a.t.Fatalf("%s unfroze the wallet", name)
	}
}

// person unfreezes the wallet with the key's touch, as the person would.
func (a *attacker) person(key *fidokit.Key) {
	a.t.Helper()
	if _, err := walletkit.AuthorizeWith(a.admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: a.wallet.ID}, nil, walletkit.Touch(key)); err != nil {
		a.t.Errorf("the person's touch: %v", err)
	}
}

// M-16: a forged assertion. The malware has the password and the registered
// credential id, which the challenge itself gives, but signs with a key of
// its own, or changes the authenticator data after the key signed it.
func TestM16_ForgedAssertion(t *testing.T) {
	a, key := keyed(t)
	own := fidokit.New(fidokit.ES256)
	a.try("the stolen password", walletkit.WithPassword, ipc.AuthFailed)
	a.try("its own key under the registered id", func(ch *ipc.Challenge) *ipc.CompleteAuthorization {
		c := walletkit.Touch(own)(ch)
		c.Assertion.CredentialID = key.CredentialID()
		return c
	}, ipc.AuthFailed)
	a.try("the touch flag set after signing", func(ch *ipc.Challenge) *ipc.CompleteAuthorization {
		c := walletkit.WithKey(key, fidokit.Options{NoTouch: true})(ch)
		c.Assertion.AuthenticatorData[32] |= 0x01
		return c
	}, ipc.AuthFailed)
	a.person(key)
}

// M-17: a repeated assertion. The malware captured an assertion of the
// person's touch, or cloned the key with its counter: the challenge serves
// once, an assertion covers only its own challenge, and the counter must
// grow.
func TestM17_RepeatedAssertion(t *testing.T) {
	a, key := keyed(t)
	ch, err := walletkit.Begin(a.admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: a.wallet.ID})
	if err != nil {
		t.Fatal(err)
	}
	captured := walletkit.Touch(key)(ch)
	if err := walletkit.Complete(a.admin, captured, nil); err != nil {
		t.Fatal(err)
	}
	a.admin.Call(ctx, ipc.MsgFreeze, &ipc.Freeze{WalletID: a.wallet.ID}, &ipc.Empty{})
	if err := walletkit.Complete(a.admin, captured, nil); walletkit.Code(err) != ipc.AuthExpired {
		t.Errorf("the same assertion on its used challenge: %v", err)
	}
	a.frozen("the used challenge")
	a.try("the captured assertion on a new challenge", func(ch *ipc.Challenge) *ipc.CompleteAuthorization {
		c := *captured
		c.AuthID = ch.AuthID
		return &c
	}, ipc.AuthFailed)
	clone := *key
	clone.Counter = 0 // the clone gives 1 again
	a.try("a clone of the key", walletkit.Touch(&clone), ipc.AuthFailed)
	a.person(key)
}

// M-18: an assertion of another key. A key the person never registered, the
// registered one used for another relying party, or a credential that may be
// synced to a cloud are all refused.
func TestM18_OtherKey(t *testing.T) {
	a, key := keyed(t)
	a.try("an unregistered key", walletkit.Touch(fidokit.New(fidokit.ES256)), ipc.AuthFailed)
	a.try("another relying party", walletkit.WithKey(key, fidokit.Options{RPID: "webauthn.example"}), ipc.AuthFailed)
	a.try("a synced credential", walletkit.WithKey(key, fidokit.Options{Synced: true}), ipc.AuthFailed)
	a.person(key)
}
