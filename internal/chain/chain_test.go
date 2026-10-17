// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package chain

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// CIP-19 test vectors.
const (
	payKey     = "9493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e"
	stakeKey   = "337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"
	scriptHash = "c37b1b5dc0669f1d3c61a6fddb2e8fde96be87b881c60bce8e8d542f"
)

func hash28(t *testing.T, s string) [28]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 28 {
		t.Fatalf("bad hash %q", s)
	}
	return [28]byte(b)
}

func TestParseAddressCIP19(t *testing.T) {
	key := model.Credential{Kind: model.KeyHash, Hash: hash28(t, payKey)}
	script := model.Credential{Kind: model.ScriptHash, Hash: hash28(t, scriptHash)}
	stake := model.Credential{Kind: model.KeyHash, Hash: hash28(t, stakeKey)}
	stakeScript := script

	cases := []struct {
		net   model.Network
		addr  string
		typ   uint8
		pay   model.Credential
		stake *model.Credential
	}{
		{model.Mainnet, "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x", 0, key, &stake},
		{model.Mainnet, "addr1z8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gten0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs9yc0hh", 1, script, &stake},
		{model.Mainnet, "addr1yx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerkr0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shs2z78ve", 2, key, &stakeScript},
		{model.Mainnet, "addr1x8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gt7r0vd4msrxnuwnccdxlhdjar77j6lg0wypcc9uar5d2shskhj42g", 3, script, &stakeScript},
		{model.Mainnet, "addr1gx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer5pnz75xxcrzqf96k", 4, key, nil},
		{model.Mainnet, "addr128phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcrtw79hu", 5, script, nil},
		{model.Mainnet, "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8", 6, key, nil},
		{model.Mainnet, "addr1w8phkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcyjy7wx", 7, script, nil},
		{model.Preprod, "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae", 0, key, &stake},
		{model.Preview, "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz", 6, key, nil},
		{model.Preprod, "addr_test1wrphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcl6szpr", 7, script, nil},
	}
	for _, tc := range cases {
		a, err := ParseAddress(tc.net, tc.addr)
		if err != nil {
			t.Errorf("%s: %v", tc.addr, err)
			continue
		}
		if a.Type != tc.typ || a.NetworkID != tc.net.AddressID() || a.Payment != tc.pay {
			t.Errorf("%s: got type %d, network %d, payment %+v", tc.addr, a.Type, a.NetworkID, a.Payment)
		}
		if (a.Stake == nil) != (tc.stake == nil) || (a.Stake != nil && *a.Stake != *tc.stake) {
			t.Errorf("%s: stake %+v, want %+v", tc.addr, a.Stake, tc.stake)
		}
		back, err := FormatAddress(a)
		if err != nil || back != tc.addr {
			t.Errorf("%s: formats back as %q, %v", tc.addr, back, err)
		}
		fromBytes, err := AddressFromBytes(a.Raw)
		if err != nil || !fromBytes.Equal(a) || fromBytes.Type != a.Type {
			t.Errorf("%s: from bytes %+v, %v", tc.addr, fromBytes, err)
		}
	}
}

func TestParseAddressRejects(t *testing.T) {
	const base = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae"
	cases := []struct {
		name string
		net  model.Network
		addr string
		want error
	}{
		{"mainnet address on preprod", model.Preprod, "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8", ErrNetworkMismatch},
		{"testnet address on mainnet", model.Mainnet, base, ErrNetworkMismatch},
		{"stake address", model.Mainnet, "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw", ErrInvalidAddress},
		{"uppercase", model.Preprod, strings.ToUpper(base), ErrInvalidAddress},
		{"bad checksum", model.Preprod, base[:len(base)-1] + "q", ErrInvalidAddress},
		{"truncated", model.Preprod, base[:60], ErrInvalidAddress},
		{"byron base58", model.Mainnet, "Ae2tdPwUPEZFRbyhz3cpfC2CumGzNkFBN2L42rcUc2yjQpEkxDbkPodpMAi", ErrInvalidAddress},
		{"empty", model.Preprod, "", ErrInvalidAddress},
	}
	for _, tc := range cases {
		if _, err := ParseAddress(tc.net, tc.addr); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := ParseAddress("testnet", base); err == nil {
		t.Error("unknown network accepted")
	}
}

func TestAddressFromBytesRejectsRewardAddress(t *testing.T) {
	raw, _ := hex.DecodeString("e1" + stakeKey)
	if _, err := AddressFromBytes(raw); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("got %v", err)
	}
	if _, err := FormatAddress(model.Address{Raw: raw}); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("format: got %v", err)
	}
}

func TestParseDecimal(t *testing.T) {
	ok := map[string]Rational{
		"0.0577":   {577, 10000},
		"7.21e-05": {721, 10000000},
		"15":       {15, 1},
		"0":        {0, 1},
		"1E+2":     {100, 1},
		"0.5":      {1, 2},
	}
	for s, want := range ok {
		got, err := ParseDecimal(s)
		if err != nil || got != want {
			t.Errorf("%q: got %+v, %v", s, got, err)
		}
	}
	bad := []string{"", "-1", "1/2", "0x10", "1e999999999", "1e100", "Inf", "NaN", ".", "1.2.3", "1e", " 1",
		"184467440737095516160", strings.Repeat("1", 41)}
	for _, s := range bad {
		if _, err := ParseDecimal(s); !errors.Is(err, ErrInvalidRational) {
			t.Errorf("%q: got %v", s, err)
		}
	}
}

func preprodParams() ProtocolParameters {
	return ProtocolParameters{
		Epoch: 319, MinFeeA: 44, MinFeeB: 155381, MaxTxSize: 16384, MaxValueSize: 5000, CoinsPerUTxOByte: 4310,
		KeyDeposit: 2_000_000, PoolDeposit: 500_000_000, DRepDeposit: 500_000_000, GovActionDeposit: 1_000_000_000,
		PriceMem: Rational{577, 10000}, PriceStep: Rational{721, 10000000}, MaxTxExMem: 17_500_000, MaxTxExSteps: 10_000_000_000,
		CollateralPercent: 150, MaxCollateralInputs: 3, MinFeeRefScriptByte: Rational{15, 1}, ProtocolMajor: 11,
	}
}

func TestValidateParameters(t *testing.T) {
	if err := preprodParams().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ProtocolParameters){
		"before Conway":  func(p *ProtocolParameters) { p.ProtocolMajor = 8 },
		"zero fee":       func(p *ProtocolParameters) { p.MinFeeA = 0 },
		"huge fee":       func(p *ProtocolParameters) { p.MinFeeB = 1 << 40 },
		"tiny tx size":   func(p *ProtocolParameters) { p.MaxTxSize = 100 },
		"zero utxo cost": func(p *ProtocolParameters) { p.CoinsPerUTxOByte = 0 },
		"no price":       func(p *ProtocolParameters) { p.PriceMem = Rational{} },
		"collateral":     func(p *ProtocolParameters) { p.CollateralPercent = 99 },
	} {
		p := preprodParams()
		mutate(&p)
		if err := p.Validate(); !errors.Is(err, ErrImplausibleParameters) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestTxIn(t *testing.T) {
	a := TxIn{TxID: [32]byte{1}, Index: 2}
	b := TxIn{TxID: [32]byte{1}, Index: 10}
	c := TxIn{TxID: [32]byte{2}}
	if a.Compare(b) >= 0 || b.Compare(c) >= 0 || a.Compare(a) != 0 {
		t.Error("order is not txid, then index")
	}
	if !strings.HasSuffix(b.String(), "#10") || len(b.String()) != 64+3 {
		t.Errorf("String %q", b.String())
	}
}

func TestConfigure(t *testing.T) {
	Configure()
	Configure() // idempotent
}

func FuzzParseAddress(f *testing.F) {
	for _, s := range []string{
		"addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae",
		"addr_test1wrphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtcl6szpr",
		"addr_test1", "addr_test1qqqqqq", "stake_test1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseAddress(model.Preprod, s)
		if err != nil {
			return
		}
		back, err := FormatAddress(a)
		if err != nil || back != s {
			t.Fatalf("%q parses but formats as %q (%v)", s, back, err)
		}
	})
}

func FuzzParseDecimal(f *testing.F) {
	for _, s := range []string{"0.0577", "7.21e-05", "15", "1e99", "9999999999999999999.9"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseDecimal(s)
		if err != nil {
			return
		}
		if r.Den == 0 {
			t.Fatalf("%q gives a zero denominator", s)
		}
	})
}
