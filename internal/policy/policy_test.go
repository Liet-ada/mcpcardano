// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package policy

import (
	"math"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

const slot = 1_000_000

var (
	payKey   = [28]byte{1}
	stakeKey = [28]byte{2}

	ownAddr = model.Address{Raw: []byte{0x00, 1, 2}, Type: 0, NetworkID: 0,
		Payment: model.Credential{Hash: payKey}, Stake: &model.Credential{Hash: stakeKey}}
	// M-02: our payment credential with somebody else's stake credential.
	ownPayOtherStake = model.Address{Raw: []byte{0x00, 1, 9}, NetworkID: 0,
		Payment: model.Credential{Hash: payKey}, Stake: &model.Credential{Hash: [28]byte{9}}}
	shop    = model.Address{Raw: []byte{0x60, 7}, Type: 6, NetworkID: 0}
	other   = model.Address{Raw: []byte{0x60, 8}, Type: 6, NetworkID: 0}
	mainnet = model.Address{Raw: []byte{0x61, 7}, Type: 6, NetworkID: 1}

	token    = mustAsset("ab", "01")
	stranger = mustAsset("cd", "01")
)

func mustAsset(p, n string) model.AssetID {
	a, err := model.ParseAssetID(strings.Repeat(p, 28) + "." + n)
	if err != nil {
		panic(err)
	}
	return a
}

func u64(n uint64) *uint64 { return &n }
func u8(n uint8) *uint8    { return &n }

// base is a mode A wallet paying 5 ADA to the shop, within every rule.
func base() Input {
	return Input{
		Wallet: model.Wallet{Network: model.Preprod, Mode: model.ModeA, Address: ownAddr},
		Policy: model.Policy{
			Networks:     []model.Network{model.Preprod},
			Limits:       model.Limits{PerTx: 10_000_000, MaxFee: 1_000_000, MaxTTLSeconds: 7200},
			Destinations: model.Destinations{Allowed: []model.Address{shop}},
			Assets:       map[model.AssetID]uint64{token: 100},
		},
		View: model.TxView{
			Outputs: []model.Output{
				{Address: shop, Value: model.Value{Lovelace: 5_000_000}},
				{Address: ownAddr, Value: model.Value{Lovelace: 90_000_000}, Own: true},
			},
			Fee: 200_000,
			TTL: u64(slot + 3600),
		},
		CurrentSlot: slot,
	}
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Input)
		status Status
		rule   Rule
		code   Code
	}{
		{"mode A within policy", func(*Input) {}, NeedsApproval, RuleModeA, ""},

		{"frozen", func(in *Input) { in.Policy.Frozen = true }, Blocked, RuleFrozen, CodeFrozen},

		{"network not enabled", func(in *Input) { in.Policy.Networks = []model.Network{model.Preview} }, Blocked, RuleNetwork, CodeNetworkMismatch},
		{"mainnet disabled by default", func(in *Input) { in.Policy.Networks = nil }, Blocked, RuleNetwork, CodeNetworkMismatch},
		{"unknown network", func(in *Input) {
			in.Wallet.Network = "testnet"
			in.Policy.Networks = []model.Network{"testnet"}
		}, Blocked, RuleNetwork, CodeNetworkMismatch},
		{"body network id matches", func(in *Input) { in.View.NetworkID = u8(0) }, NeedsApproval, RuleModeA, ""},
		{"body network id differs", func(in *Input) { in.View.NetworkID = u8(1) }, Blocked, RuleNetwork, CodeNetworkMismatch},
		{"output on another network", func(in *Input) {
			in.Policy.Destinations = model.Destinations{Any: true}
			in.View.Outputs[0].Address = mainnet
		}, Blocked, RuleNetwork, CodeNetworkMismatch},

		{"certificate rejected", func(in *Input) { in.View.Certificates = []model.Certificate{{Kind: "stake_delegation"}} }, Blocked, RuleCertificates, CodePolicyBlocked},
		{"certificate allowed", func(in *Input) {
			in.View.Certificates = []model.Certificate{{Kind: "stake_delegation"}}
			in.Policy.Structure.Certificates = true
		}, NeedsApproval, RuleModeA, ""},
		{"withdrawal rejected", func(in *Input) { in.View.Withdrawals = []model.Withdrawal{{Amount: 1}} }, Blocked, RuleWithdrawals, CodePolicyBlocked},
		{"withdrawal allowed", func(in *Input) {
			in.View.Withdrawals = []model.Withdrawal{{Amount: 1}}
			in.Policy.Structure.Withdrawals = true
		}, NeedsApproval, RuleModeA, ""},
		{"mint rejected", func(in *Input) { in.View.Mint = map[model.AssetID]int64{token: 1} }, Blocked, RuleMint, CodePolicyBlocked},
		{"burn rejected", func(in *Input) { in.View.Mint = map[model.AssetID]int64{token: -1} }, Blocked, RuleMint, CodePolicyBlocked},
		{"mint allowed", func(in *Input) {
			in.View.Mint = map[model.AssetID]int64{token: 1}
			in.Policy.Structure.Mint = true
		}, NeedsApproval, RuleModeA, ""},
		{"vote", func(in *Input) { in.View.Votes = 1 }, Blocked, RuleGovernance, CodePolicyBlocked},
		{"proposal", func(in *Input) { in.View.Proposals = 1 }, Blocked, RuleGovernance, CodePolicyBlocked},
		{"donation", func(in *Input) { in.View.Donation = 1 }, Blocked, RuleDonation, CodePolicyBlocked},
		{"script data hash", func(in *Input) { in.View.ScriptDataHash = true }, Blocked, RuleScripts, CodePolicyBlocked},
		{"reference input", func(in *Input) { in.View.ReferenceInputs = 1 }, Blocked, RuleScripts, CodePolicyBlocked},
		{"collateral input (M-05)", func(in *Input) { in.View.Collateral = 1 }, Blocked, RuleCollateral, CodePolicyBlocked},
		{"collateral return", func(in *Input) { in.View.CollateralReturn = true }, Blocked, RuleCollateral, CodePolicyBlocked},
		{"total collateral", func(in *Input) { in.View.TotalCollateral = u64(0) }, Blocked, RuleCollateral, CodePolicyBlocked},
		{"own key as required signer", func(in *Input) { in.View.RequiredSigners = [][28]byte{payKey} }, NeedsApproval, RuleModeA, ""},
		{"foreign required signer (M-06)", func(in *Input) { in.View.RequiredSigners = [][28]byte{{7}} }, Blocked, RuleRequiredSigners, CodePolicyBlocked},
		{"stake key as required signer", func(in *Input) { in.View.RequiredSigners = [][28]byte{stakeKey} }, Blocked, RuleRequiredSigners, CodePolicyBlocked},
		{"output with datum", func(in *Input) { in.View.Outputs[0].HasDatum = true }, Blocked, RuleOutputDatum, CodePolicyBlocked},
		{"output with reference script", func(in *Input) { in.View.Outputs[1].HasScript = true }, Blocked, RuleOutputDatum, CodePolicyBlocked},

		{"destination not in list", func(in *Input) { in.View.Outputs[0].Address = other }, Blocked, RuleDestination, CodePolicyBlocked},
		{"empty list allows nobody", func(in *Input) { in.Policy.Destinations = model.Destinations{} }, Blocked, RuleDestination, CodePolicyBlocked},
		{"any destination", func(in *Input) {
			in.Policy.Destinations = model.Destinations{Any: true}
			in.View.Outputs[0].Address = other
		}, NeedsApproval, RuleModeA, ""},
		{"own payment, foreign stake (M-02)", func(in *Input) { in.View.Outputs[0].Address = ownPayOtherStake }, Blocked, RuleDestination, CodePolicyBlocked},
		{"token within cap", func(in *Input) { in.View.Outputs[0].Value.Assets = map[model.AssetID]uint64{token: 100} }, NeedsApproval, RuleModeA, ""},
		{"token over cap", func(in *Input) { in.View.Outputs[0].Value.Assets = map[model.AssetID]uint64{token: 101} }, Blocked, RuleAsset, CodePolicyBlocked},
		{"cap counts all outputs", func(in *Input) {
			in.View.Outputs[0].Value.Assets = map[model.AssetID]uint64{token: 60}
			in.View.Outputs = append(in.View.Outputs, model.Output{Address: shop, Value: model.Value{Lovelace: 1, Assets: map[model.AssetID]uint64{token: 41}}})
		}, Blocked, RuleAsset, CodePolicyBlocked},
		{"unlisted token, one unit (M-15)", func(in *Input) { in.View.Outputs[0].Value.Assets = map[model.AssetID]uint64{stranger: 1} }, Blocked, RuleAsset, CodePolicyBlocked},
		{"unlisted token kept as change", func(in *Input) { in.View.Outputs[1].Value.Assets = map[model.AssetID]uint64{stranger: 5} }, NeedsApproval, RuleModeA, ""},

		{"spend at the limit", func(in *Input) { in.View.Outputs[0].Value.Lovelace = 9_800_000 }, NeedsApproval, RuleModeA, ""},
		{"spend over the limit", func(in *Input) { in.View.Outputs[0].Value.Lovelace = 9_800_001 }, Blocked, RulePerTx, CodeBudgetExceeded},
		{"change does not count", func(in *Input) { in.View.Outputs[1].Value.Lovelace = math.MaxUint64 }, NeedsApproval, RuleModeA, ""},
		{"fee at the maximum", func(in *Input) { in.View.Fee = 1_000_000 }, NeedsApproval, RuleModeA, ""},
		{"fee over the maximum (M-10)", func(in *Input) {
			in.View.Fee = 1_000_001
			in.View.Outputs[0].Value.Lovelace = 1
		}, Blocked, RuleMaxFee, CodePolicyBlocked},
		{"no TTL", func(in *Input) { in.View.TTL = nil }, Blocked, RuleTTL, CodeTTLTooLong},
		{"TTL passed", func(in *Input) { in.View.TTL = u64(slot) }, Blocked, RuleTTL, CodeTTLTooLong},
		{"TTL at the maximum", func(in *Input) { in.View.TTL = u64(slot + 7200) }, NeedsApproval, RuleModeA, ""},
		{"TTL beyond the maximum (M-11)", func(in *Input) { in.View.TTL = u64(slot + 7201) }, Blocked, RuleTTL, CodeTTLTooLong},

		{"overflow", func(in *Input) { in.View.Outputs[0].Value.Lovelace = math.MaxUint64 }, Blocked, RuleOverflow, CodePolicyBlocked},
		{"mode B not available yet", func(in *Input) { in.Wallet.Mode = model.ModeB }, Blocked, RuleModeNotAvailable, CodePolicyBlocked},
		{"mode C not available yet", func(in *Input) { in.Wallet.Mode = model.ModeC }, Blocked, RuleModeNotAvailable, CodePolicyBlocked},
		{"unknown mode", func(in *Input) { in.Wallet.Mode = "" }, Blocked, RuleModeNotAvailable, CodePolicyBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			tc.mutate(&in)
			v := Evaluate(in)
			if v.Status != tc.status || v.Rule != tc.rule || v.Code != tc.code {
				t.Fatalf("got %s/%s/%s (%s), want %s/%s/%s", v.Status, v.Rule, v.Code, v.Detail, tc.status, tc.rule, tc.code)
			}
			if v.Status == Blocked && v.Detail == "" {
				t.Error("a blocked verdict must explain itself")
			}
		})
	}
}

// TestOrder checks that the first failing rule in the order of section 3.6
// is the one reported.
func TestOrder(t *testing.T) {
	in := base()
	in.Policy.Frozen = true
	in.Policy.Networks = nil
	in.View.Certificates = []model.Certificate{{}}
	in.View.Outputs[0].Address = other
	in.View.Fee = math.MaxUint32
	want := []Rule{RuleFrozen, RuleNetwork, RuleCertificates, RuleDestination, RulePerTx, RuleModeA}
	for i, rule := range want {
		if got := Evaluate(in).Rule; got != rule {
			t.Fatalf("step %d: got %s, want %s", i, got, rule)
		}
		switch i {
		case 0:
			in.Policy.Frozen = false
		case 1:
			in.Policy.Networks = []model.Network{model.Preprod}
		case 2:
			in.View.Certificates = nil
		case 3:
			in.View.Outputs[0].Address = shop
		case 4:
			in.View.Fee = 200_000
		}
	}
}

func TestComputeSpend(t *testing.T) {
	in := base()
	in.View.Outputs = append(in.View.Outputs,
		model.Output{Address: shop, Value: model.Value{Lovelace: 1_000_000, Assets: map[model.AssetID]uint64{token: 3}}},
		model.Output{Address: ownPayOtherStake, Value: model.Value{Lovelace: 2_000_000}},
	)
	in.View.Donation = 7
	s, err := ComputeSpend(in.View)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(5_000_000 + 1_000_000 + 2_000_000 + 200_000 + 7); s.Lovelace != want {
		t.Errorf("lovelace %d, want %d", s.Lovelace, want)
	}
	if len(s.Assets) != 1 || s.Assets[token] != 3 {
		t.Errorf("assets %v", s.Assets)
	}
	if len(s.Destinations) != 2 || !s.Destinations[0].Equal(shop) || !s.Destinations[1].Equal(ownPayOtherStake) {
		t.Errorf("destinations %v", s.Destinations)
	}
}

// TestConsolidationSpendsOnlyTheFee follows section 8.5: when every output is
// own, the spend is the fee.
func TestConsolidationSpendsOnlyTheFee(t *testing.T) {
	in := base()
	in.View.Outputs = []model.Output{{Address: ownAddr, Value: model.Value{Lovelace: 50_000_000}, Own: true}}
	v := Evaluate(in)
	if v.Status != NeedsApproval || v.Spend.Lovelace != in.View.Fee || len(v.Spend.Destinations) != 0 {
		t.Fatalf("got %+v", v)
	}
}

// TestBlockedVerdictCarriesSpend: the wallet reports its spend even when it
// rejects (section 5.3).
func TestBlockedVerdictCarriesSpend(t *testing.T) {
	in := base()
	in.Policy.Frozen = true
	if v := Evaluate(in); v.Spend.Lovelace != 5_200_000 {
		t.Fatalf("spend %d", v.Spend.Lovelace)
	}
}

func TestDeterministicAssetRule(t *testing.T) {
	in := base()
	in.View.Outputs[0].Value.Assets = map[model.AssetID]uint64{stranger: 1, mustAsset("00", "00"): 1, mustAsset("ff", "00"): 1}
	first := Evaluate(in).Detail
	for range 50 {
		if d := Evaluate(in).Detail; d != first {
			t.Fatalf("detail changed: %q then %q", first, d)
		}
	}
	if !strings.Contains(first, strings.Repeat("00", 28)) {
		t.Errorf("expected the lowest token first, got %q", first)
	}
}
