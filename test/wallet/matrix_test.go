// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package wallet tests the wallet process from outside, as a compromised
// server would attack it: one test per row of the attack matrix of section
// 11.6, named with its ID (criterion 2 of milestone H-2), and the crash tests
// of section 9.1, which kill the real binary between the steps of a
// signature (criterion 3). Rows M-16 to M-18 come from a malware that runs
// as the person and cannot touch the FIDO2 key (keys_test.go).
package wallet

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

var ctx = context.Background()

// attacker is a compromised server connected to a real wallet that holds one
// wallet with the default template: mode C, 100 tADA of budget, 20 per
// transaction, a fee of at most 2 tADA, 2 new destinations per hour.
type attacker struct {
	t       *testing.T
	w       *walletkit.Wallet
	admin   *ipc.Client
	service *ipc.Client
	wallet  ipc.Wallet
	n       byte // makes each body different
}

func newAttacker(t *testing.T) *attacker {
	w := walletkit.Start(t)
	a := &attacker{t: t, w: w, admin: w.Admin(t), service: w.Service(t)}
	walletkit.Unlock(t, a.admin)
	a.wallet = walletkit.CreateWallet(t, a.service, "agent")
	return a
}

// body is a payment of lovelace to a destination of its own, with change to
// the wallet; change may alter any field.
func (a *attacker) body(lovelace uint64, change func(map[uint64]any)) map[uint64]any {
	a.n++
	m := walletkit.Payment(a.wallet.Address, walletkit.Address(6, a.n, 0), lovelace, a.w.Clock)
	m[0] = walletkit.Set([]any{bytes.Repeat([]byte{a.n}, 32), uint64(0)})
	if change != nil {
		change(m)
	}
	return m
}

func (a *attacker) sign(body, aux []byte) *ipc.SignDraftResult {
	a.t.Helper()
	res, err := walletkit.Sign(a.service, a.wallet.ID, body, aux)
	if err != nil {
		a.t.Fatal(err)
	}
	return res
}

// rejected fails unless the wallet rejects the body with code and a detail
// that mentions what.
func (a *attacker) rejected(name string, m map[uint64]any, code ipc.Code, what string) *ipc.SignDraftResult {
	a.t.Helper()
	res := a.sign(walletkit.Encode(a.t, m), nil)
	if res.Status != ipc.Rejected || res.Rejection.Code != code || !strings.Contains(res.Rejection.Detail, what) {
		a.t.Errorf("%s: got %s %+v, want %s about %q", name, res.Status, res.Rejection, code, what)
	}
	return res
}

func (a *attacker) signed(name string, m map[uint64]any) *ipc.SignDraftResult {
	a.t.Helper()
	res := a.sign(walletkit.Encode(a.t, m), nil)
	if res.Status != ipc.Signed {
		a.t.Fatalf("%s: got %s %+v", name, res.Status, res.Rejection)
	}
	return res
}

func (a *attacker) spentHour() uint64 {
	a.t.Helper()
	var ps ipc.PolicyStatus
	if err := a.service.Call(ctx, ipc.MsgGetPolicyStatus, &ipc.GetPolicyStatus{WalletID: a.wallet.ID}, &ps); err != nil {
		a.t.Fatal(err)
	}
	return ps.SpentHour
}

// own returns the wallet's address with another stake credential.
func (a *attacker) ownPaymentOtherStake() []byte {
	addr := bytes.Clone(a.wallet.Address)
	copy(addr[29:], bytes.Repeat([]byte{0x99}, 28))
	return addr
}

func TestM01_UndeclaredInputs(t *testing.T) {
	a := newAttacker(t)
	// A consolidation with inputs that are not the wallet's: the spend is the
	// fee, whatever the inputs hold, and whatever the server says they hold.
	m := a.body(0, func(m map[uint64]any) {
		var ins []any
		for i := range 40 {
			ins = append(ins, []any{bytes.Repeat([]byte{byte(i)}, 32), uint64(i)})
		}
		m[0] = walletkit.Set(ins...)
		m[1] = []any{[]any{a.wallet.Address, uint64(90_000_000)}}
	})
	body := walletkit.Encode(t, m)
	draft := "d_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	var res ipc.SignDraftResult
	err := a.service.Call(ctx, ipc.MsgSignDraft, &ipc.SignDraft{WalletID: a.wallet.ID, DraftID: draft, Body: body,
		Inputs: []ipc.ResolvedInput{{TxID: bytes.Repeat([]byte{1}, 32), Index: 1, Output: []byte{0x82, 0x41, 0x60, 0x01}}}}, &res)
	if err != nil || res.Status != ipc.Signed || res.Spend.Lovelace != 170_000 {
		t.Fatalf("got %+v, %v", res, err)
	}
	if a.spentHour() != 170_000 {
		t.Errorf("spent %d", a.spentHour())
	}
}

func TestM02_OwnPaymentForeignStake(t *testing.T) {
	a := newAttacker(t)
	to := a.ownPaymentOtherStake()
	// The output is spend: above the limit per transaction it is refused,
	// below it the spend counts it.
	a.rejected("the whole budget", a.body(0, func(m map[uint64]any) {
		m[1] = []any{[]any{to, uint64(60_000_000)}, []any{a.wallet.Address, uint64(1_000_000)}}
	}), ipc.BudgetExceeded, "limits.per_tx")
	res := a.signed("within the limit", a.body(0, func(m map[uint64]any) {
		m[1] = []any{[]any{to, uint64(5_000_000)}, []any{a.wallet.Address, uint64(1_000_000)}}
	}))
	if res.Spend.Lovelace != 5_170_000 {
		t.Errorf("spend %d", res.Spend.Lovelace)
	}
}

func TestM03_MintOrBurn(t *testing.T) {
	a := newAttacker(t)
	policy := cborx.ByteString(bytes.Repeat([]byte{0xa1}, 28))
	for _, q := range []int64{1, -1} {
		a.rejected("mint", a.body(1_000_000, func(m map[uint64]any) {
			m[9] = map[cborx.ByteString]map[cborx.ByteString]int64{policy: {"T": q}}
		}), ipc.PolicyBlocked, "structure.mint")
	}
}

func TestM04_CertificatesWithdrawalsGovernance(t *testing.T) {
	a := newAttacker(t)
	pool := append([]byte{0}, bytes.Repeat([]byte{1}, 28)...)
	// A certificate is refused even if the policy allowed it, until its
	// deposit counts (decision 105).
	a.rejected("certificate", a.body(1_000_000, func(m map[uint64]any) {
		m[4] = walletkit.Set([]any{uint64(2), []any{uint64(0), a.wallet.Address[29:]}, pool[1:]})
	}), ipc.TxUnsupportedField, "certificates")
	reward := append([]byte{0xe0}, a.wallet.Address[29:]...)
	a.rejected("withdrawal", a.body(1_000_000, func(m map[uint64]any) {
		m[5] = map[cborx.ByteString]uint64{cborx.ByteString(reward): 1}
	}), ipc.PolicyBlocked, "structure.withdrawals")
	for key, name := range map[uint64]string{19: "voting_procedures", 20: "proposal_procedures", 21: "current_treasury_value", 22: "donation"} {
		a.rejected(name, a.body(1_000_000, func(m map[uint64]any) { m[key] = uint64(1) }), ipc.TxUnsupportedField, name)
	}
}

func TestM05_Collateral(t *testing.T) {
	a := newAttacker(t)
	in := walletkit.Set([]any{bytes.Repeat([]byte{9}, 32), uint64(0)})
	cases := map[uint64]any{13: in, 16: []any{a.wallet.Address, uint64(1)}, 17: uint64(5_000_000)}
	for key, v := range cases {
		a.rejected("collateral", a.body(1_000_000, func(m map[uint64]any) { m[key] = v }), ipc.TxUnsupportedField, "collateral")
	}
}

func TestM06_ForeignRequiredSigners(t *testing.T) {
	a := newAttacker(t)
	a.rejected("a signer of another", a.body(1_000_000, func(m map[uint64]any) {
		m[14] = walletkit.Set(bytes.Repeat([]byte{7}, 28))
	}), ipc.PolicyBlocked, "structure.required_signers")
	a.rejected("the wallet's stake key", a.body(1_000_000, func(m map[uint64]any) {
		m[14] = walletkit.Set(a.wallet.Address[29:57])
	}), ipc.PolicyBlocked, "structure.required_signers")
	a.signed("the wallet's own payment key", a.body(1_000_000, func(m map[uint64]any) {
		m[14] = walletkit.Set(a.wallet.Address[1:29])
	}))
}

func TestM07_UnknownField(t *testing.T) {
	a := newAttacker(t)
	for _, key := range []uint64{6, 10, 12, 23, 1 << 32} {
		a.rejected("unknown field", a.body(1_000_000, func(m map[uint64]any) { m[key] = uint64(0) }), ipc.TxUnsupportedField, "unknown body field")
	}
}

func TestM08_AmbiguousEncoding(t *testing.T) {
	a := newAttacker(t)
	good := walletkit.Encode(t, a.body(1_000_000, nil))
	// The fee as an 8-byte integer, the outputs as an indefinite array, and a
	// tag around the whole body.
	m := a.body(1_000_000, nil)
	in, outs := walletkit.Encode(t, m[0]), walletkit.Encode(t, m[1])
	ttl := walletkit.Encode(t, m[3])
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	variants := map[string][]byte{
		"long integer":     cat([]byte{0xa4, 0x00}, in, []byte{0x01}, outs, []byte{0x02, 0x1b, 0, 0, 0, 0, 0, 2, 0x98, 0x10, 0x03}, ttl),
		"indefinite array": cat([]byte{0xa4, 0x00}, in, []byte{0x01, 0x9f}, outs[1:], []byte{0xff, 0x02, 0x1a, 0, 2, 0x98, 0x10, 0x03}, ttl),
		"tagged body":      cat([]byte{0xd8, 0x18}, good),
	}
	for name, body := range variants {
		if res := a.sign(body, nil); res.Status != ipc.Rejected || res.Rejection.Code != ipc.TxNotCanonical {
			t.Errorf("%s: got %s %+v", name, res.Status, res.Rejection)
		}
	}
}

func TestM09_OtherNetwork(t *testing.T) {
	a := newAttacker(t)
	a.rejected("network id of mainnet", a.body(1_000_000, func(m map[uint64]any) { m[15] = uint64(1) }), ipc.PolicyBlocked, "network")
	mainnet := append([]byte{0x61}, bytes.Repeat([]byte{7}, 28)...)
	a.rejected("an address of mainnet", a.body(0, func(m map[uint64]any) {
		m[1] = []any{[]any{mainnet, uint64(1_000_000)}, []any{a.wallet.Address, uint64(1_000_000)}}
	}), ipc.PolicyBlocked, "network")
}

func TestM10_InflatedFee(t *testing.T) {
	a := newAttacker(t)
	a.rejected("a fee of 3 tADA", a.body(0, func(m map[uint64]any) {
		m[1] = []any{[]any{a.wallet.Address, uint64(1_000_000)}}
		m[2] = uint64(3_000_000)
	}), ipc.PolicyBlocked, "limits.max_fee")
}

func TestM11_ValidityAndTime(t *testing.T) {
	a := newAttacker(t)
	slot := a.w.Clock.Slot()
	a.rejected("beyond the maximum TTL", a.body(1_000_000, func(m map[uint64]any) { m[3] = slot + 7201 }), ipc.TTLTooLong, "limits.ttl")
	a.rejected("without TTL", a.body(1_000_000, func(m map[uint64]any) { delete(m, 3) }), ipc.TTLTooLong, "no TTL")
	// A TTL that is still valid for a server whose clock is behind has
	// passed for the wallet's own clock (section 9.3).
	a.rejected("passed by the wallet's clock", a.body(1_000_000, func(m map[uint64]any) { m[3] = slot - 10 }), ipc.TTLTooLong, "has passed")
	a.signed("at the maximum", a.body(1_000_000, func(m map[uint64]any) { m[3] = slot + 7200 }))
}

func TestM12_AuxiliaryData(t *testing.T) {
	a := newAttacker(t)
	msg := walletkit.Encode(t, map[uint64]any{674: map[string]any{"msg": []string{"invoice 7"}}})
	other := walletkit.Encode(t, map[uint64]any{674: map[string]any{"msg": []string{"invoice 8"}}})
	nft := walletkit.Encode(t, map[uint64]any{721: map[string]any{"x": uint64(1)}})
	hashOf := func(b []byte) []byte { h := blake2b.Sum256(b); return h[:] }
	cases := []struct {
		name      string
		hash, aux []byte
	}{
		{"auxiliary data that do not match the hash", hashOf(msg), other},
		{"a hash without auxiliary data", hashOf(msg), nil},
		{"auxiliary data without a hash", nil, msg},
		{"metadata other than a CIP-20 message", hashOf(nft), nft},
	}
	for _, c := range cases {
		m := a.body(1_000_000, func(m map[uint64]any) {
			if c.hash != nil {
				m[7] = c.hash
			}
		})
		if res := a.sign(walletkit.Encode(t, m), c.aux); res.Status != ipc.Rejected || res.Rejection.Code != ipc.TxUnsupportedField {
			t.Errorf("%s: got %s %+v", c.name, res.Status, res.Rejection)
		}
	}
	m := a.body(1_000_000, func(m map[uint64]any) { m[7] = hashOf(msg) })
	if res := a.sign(walletkit.Encode(t, m), msg); res.Status != ipc.Signed {
		t.Errorf("a CIP-20 message: got %s %+v", res.Status, res.Rejection)
	}
}

func TestM13_SignTwice(t *testing.T) {
	a := newAttacker(t)
	m := a.body(5_000_000, nil)
	first := a.signed("first", m)
	again := a.signed("again", m)
	if !bytes.Equal(first.Witnesses[0].Signature, again.Witnesses[0].Signature) || a.spentHour() != 5_170_000 {
		t.Errorf("the same body twice: spent %d", a.spentHour())
	}
	// A variant is another transaction, and counts as one.
	a.signed("a variant", a.body(5_000_000, nil))
	if a.spentHour() != 2*5_170_000 {
		t.Errorf("spent %d", a.spentHour())
	}
}

func TestM14_ManyNewDestinations(t *testing.T) {
	a := newAttacker(t)
	a.signed("first new destination", a.body(1_000_000, nil))
	a.w.Clock.Advance(time.Minute)
	a.signed("second", a.body(1_000_000, nil))
	a.w.Clock.Advance(time.Minute)
	a.rejected("third within the hour", a.body(1_000_000, nil), ipc.BudgetExceeded, "limits.new_destinations_per_hour")
	// Two at once count as two.
	a.w.Clock.Advance(time.Hour)
	a.rejected("two in one transaction", a.body(0, func(m map[uint64]any) {
		m[1] = []any{
			[]any{walletkit.Address(6, 200, 0), uint64(1_000_000)},
			[]any{walletkit.Address(6, 201, 0), uint64(1_000_000)},
			[]any{walletkit.Address(6, 202, 0), uint64(1_000_000)},
		}
	}), ipc.BudgetExceeded, "limits.new_destinations_per_hour")
}

func TestM15_UnlistedTokens(t *testing.T) {
	a := newAttacker(t)
	policy := cborx.ByteString(bytes.Repeat([]byte{0xa1}, 28))
	token := map[cborx.ByteString]map[cborx.ByteString]uint64{policy: {"T": 1}}
	a.rejected("one unit of an unlisted token", a.body(0, func(m map[uint64]any) {
		m[1] = []any{[]any{walletkit.Address(6, 77, 0), []any{uint64(1_500_000), token}}, []any{a.wallet.Address, uint64(1_000_000)}}
	}), ipc.PolicyBlocked, "assets")
	a.signed("the token kept as change", a.body(0, func(m map[uint64]any) {
		m[1] = []any{[]any{a.wallet.Address, []any{uint64(1_500_000), token}}}
	}))
}
