// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package model

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestIDs(t *testing.T) {
	w, err := NewWalletID(bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if w != "w_aaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("got %q", w)
	}
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	d, err := NewDraftID(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("%s: %v", d, err)
	}
	a, _ := NewApprovalID(nil)
	if err := a.Validate(); err != nil {
		t.Fatalf("%s: %v", a, err)
	}
	// The example ids of section 4.4 are valid.
	if err := WalletID("w_k3fq2mx7c4v6bn5ta2sd7hpely").Validate(); err != nil {
		t.Error(err)
	}
	if err := DraftID("d_7h2kw4px3c6vbn5mq7z4rafeyu").Validate(); err != nil {
		t.Error(err)
	}
	bad := []WalletID{
		"", "w_", "d_k3fq2mx7c4v6bn5ta2sd7hpelz", "w_K3FQ2MX7C4V6BN5TA2SD7HPELZ",
		"w_k3fq2mx7c4v6bn5ta2sd7hpel", "w_k3fq2mx7c4v6bn5ta2sd7hpelza", "w_k3fq2mx7c4v6bn5ta2sd7hpel1",
		"w_k3fq2mx7c4v6bn5ta2sd7hpelz", // non-zero trailing bits
	}
	for _, id := range bad {
		if err := id.Validate(); !errors.Is(err, ErrInvalidID) {
			t.Errorf("%q: got %v", id, err)
		}
	}
	if _, err := NewWalletID(bytes.NewReader(nil)); err == nil {
		t.Error("short randomness accepted")
	}
}

func TestArithmetic(t *testing.T) {
	if _, err := Add(math.MaxUint64, 1); !errors.Is(err, ErrOverflow) {
		t.Error("Add overflow not detected")
	}
	if s, err := Add(math.MaxUint64-1, 1); err != nil || s != math.MaxUint64 {
		t.Error("Add at the edge failed")
	}
	if _, err := Sub(1, 2); !errors.Is(err, ErrOverflow) {
		t.Error("Sub underflow not detected")
	}
}

func TestAmounts(t *testing.T) {
	ok := map[string]uint64{"0": 0, "1500000": 1500000, "18446744073709551615": math.MaxUint64}
	for s, want := range ok {
		got, err := ParseAmount(s)
		if err != nil || got != want {
			t.Errorf("%q: got %d, %v", s, got, err)
		}
		if FormatAmount(want) != s {
			t.Errorf("format %d", want)
		}
	}
	for _, s := range []string{"", "01", "+1", "-1", "1.5", "1e6", " 1", "١"} {
		if _, err := ParseAmount(s); !errors.Is(err, ErrInvalidAmount) {
			t.Errorf("%q: got %v", s, err)
		}
	}
	if _, err := ParseAmount("18446744073709551616"); !errors.Is(err, ErrOverflow) {
		t.Error("overflow not detected")
	}
}

func TestAssetIDs(t *testing.T) {
	p := strings.Repeat("ab", 28)
	a, err := ParseAssetID(p + ".4d43")
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != "MC" || a.String() != p+".4d43" {
		t.Fatalf("got %+v, %s", a, a)
	}
	if _, err := ParseAssetID(p + "."); err != nil {
		t.Errorf("empty name rejected: %v", err)
	}
	bad := []string{"", p, p[2:] + ".00", p + "." + strings.Repeat("00", 33), strings.ToUpper(p) + ".00", p + ".0", p + ".zz"}
	for _, s := range bad {
		if _, err := ParseAssetID(s); !errors.Is(err, ErrInvalidAsset) {
			t.Errorf("%q: got %v", s, err)
		}
	}
	b, _ := ParseAssetID(p + ".4d44")
	c, _ := ParseAssetID(strings.Repeat("ac", 28) + ".00")
	if a.Compare(b) >= 0 || b.Compare(c) >= 0 || a.Compare(a) != 0 {
		t.Error("asset order is not policy, then name")
	}
}

func TestValueAdd(t *testing.T) {
	a, _ := ParseAssetID(strings.Repeat("ab", 28) + ".01")
	v := Value{Lovelace: 1, Assets: map[AssetID]uint64{a: 2}}
	w := Value{Lovelace: 3, Assets: map[AssetID]uint64{a: 4}}
	s, err := v.Add(w)
	if err != nil || s.Lovelace != 4 || s.Assets[a] != 6 {
		t.Fatalf("got %+v, %v", s, err)
	}
	if v.Assets[a] != 2 {
		t.Error("Add modified its receiver")
	}
	if _, err := v.Add(Value{Assets: map[AssetID]uint64{a: math.MaxUint64}}); !errors.Is(err, ErrOverflow) {
		t.Error("asset overflow not detected")
	}
	if _, err := v.Add(Value{Lovelace: math.MaxUint64}); !errors.Is(err, ErrOverflow) {
		t.Error("lovelace overflow not detected")
	}
}

func TestAddressEqualIsWholeAddress(t *testing.T) {
	own := Address{Raw: []byte{0x00, 1, 2}, Payment: Credential{Hash: [28]byte{1}}, Stake: &Credential{Hash: [28]byte{2}}}
	sameRaw := Address{Raw: []byte{0x00, 1, 2}}
	otherStake := Address{Raw: []byte{0x00, 1, 3}, Payment: own.Payment, Stake: &Credential{Hash: [28]byte{9}}}
	if !own.Equal(sameRaw) || own.Equal(otherStake) {
		t.Error("equality must compare the whole address")
	}
}

func TestIntentValidate(t *testing.T) {
	addr := Address{Raw: []byte{0x60, 1}}
	out := PaymentOutput{Address: addr, Value: Value{Lovelace: 1}}
	many := make([]PaymentOutput, MaxPaymentOutputs+1)
	for i := range many {
		many[i] = out
	}
	a, _ := ParseAssetID(strings.Repeat("ab", 28) + ".01")
	cases := []struct {
		name string
		in   Intent
		ok   bool
	}{
		{"payment", Intent{Kind: IntentPayment, Payment: &Payment{Outputs: []PaymentOutput{out}, Message: "Invoice 42"}}, true},
		{"consolidation", Intent{Kind: IntentConsolidation}, true},
		{"50 outputs", Intent{Kind: IntentPayment, Payment: &Payment{Outputs: many[:MaxPaymentOutputs]}}, true},
		{"51 outputs", Intent{Kind: IntentPayment, Payment: &Payment{Outputs: many}}, false},
		{"no outputs", Intent{Kind: IntentPayment, Payment: &Payment{}}, false},
		{"no payment", Intent{Kind: IntentPayment}, false},
		{"consolidation with outputs", Intent{Kind: IntentConsolidation, Payment: &Payment{Outputs: []PaymentOutput{out}}}, false},
		{"unknown kind", Intent{Kind: "swap"}, false},
		{"long message", Intent{Kind: IntentPayment, Payment: &Payment{Outputs: []PaymentOutput{out}, Message: strings.Repeat("x", MaxMessageBytes+1)}}, false},
		{"invalid utf-8", Intent{Kind: IntentPayment, Payment: &Payment{Outputs: []PaymentOutput{out}, Message: "\xff"}}, false},
		{"empty address", Intent{Kind: IntentPayment, Payment: &Payment{Outputs: []PaymentOutput{{Value: Value{Lovelace: 1}}}}}, false},
		{"sends nothing", Intent{Kind: IntentPayment, Payment: &Payment{Outputs: []PaymentOutput{{Address: addr}}}}, false},
		{"zero tokens", Intent{Kind: IntentPayment, Payment: &Payment{Outputs: []PaymentOutput{{Address: addr, Value: Value{Lovelace: 1, Assets: map[AssetID]uint64{a: 0}}}}}}, false},
		{"tokens only", Intent{Kind: IntentPayment, Payment: &Payment{Outputs: []PaymentOutput{{Address: addr, Value: Value{Assets: map[AssetID]uint64{a: 1}}}}}}, true},
	}
	for _, tc := range cases {
		err := tc.in.Validate()
		if tc.ok && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if !tc.ok && !errors.Is(err, ErrInvalidIntent) {
			t.Errorf("%s: got %v, want ErrInvalidIntent", tc.name, err)
		}
	}
}

func TestDestinations(t *testing.T) {
	a := Address{Raw: []byte{1}}
	b := Address{Raw: []byte{2}}
	if !(Destinations{Any: true}).Permits(a) {
		t.Error("any")
	}
	d := Destinations{Allowed: []Address{a}}
	if !d.Permits(a) || d.Permits(b) {
		t.Error("list")
	}
	if (Destinations{}).Permits(a) {
		t.Error("the zero value must allow nobody")
	}
}
