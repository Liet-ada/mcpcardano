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

	// A reward account of preprod.
	reward = append([]byte{0xe0}, make([]byte, 28)...)

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
		{"withdrawal rejected", func(in *Input) { in.View.Withdrawals = []model.Withdrawal{{Account: reward, Amount: 1}} }, Blocked, RuleWithdrawals, CodePolicyBlocked},
		{"withdrawal allowed", func(in *Input) {
			in.View.Withdrawals = []model.Withdrawal{{Account: reward, Amount: 1}}
			in.Policy.Structure.Withdrawals = true
		}, NeedsApproval, RuleModeA, ""},
		{"withdrawal from another network", func(in *Input) {
			in.View.Withdrawals = []model.Withdrawal{{Account: append([]byte{0xe1}, reward[1:]...), Amount: 1}}
			in.Policy.Structure.Withdrawals = true
		}, Blocked, RuleNetwork, CodeNetworkMismatch},
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
		{"unknown mode", func(in *Input) { in.Wallet.Mode = "" }, Blocked, RuleModeNotAvailable, CodePolicyBlocked},
		// Mode A has no record: the person confirms every transaction.
		{"mode A ignores session and windows", func(in *Input) {
			in.Policy.SessionRequired = true
			in.Usage.Hour = Window{Lovelace: math.MaxUint64, Transactions: math.MaxUint32}
		}, NeedsApproval, RuleModeA, ""},
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

// baseC is a mode C wallet paying 5 ADA to a new destination, within every
// limit, with an empty record.
func baseC() Input {
	in := base()
	in.Wallet.Mode = model.ModeC
	in.Policy.Destinations = model.Destinations{Any: true}
	in.Policy.Limits = model.Limits{
		PerTx: 10_000_000, PerHour: 20_000_000, PerDay: 50_000_000, Budget: 100_000_000,
		ApprovalThreshold: 5_200_000, MaxFee: 1_000_000, TxPerHour: 4,
		NewDestinationsPerHour: 2, NewDestinationsPerDay: 5, MaxTTLSeconds: 7200,
	}
	return in
}

const spend = 5_200_000 // the 5 ADA and the fee of baseC

func knows(addrs ...model.Address) func(model.Address) bool {
	return func(a model.Address) bool {
		for _, x := range addrs {
			if x.Equal(a) {
				return true
			}
		}
		return false
	}
}

func TestModesBC(t *testing.T) {
	modeB := func(in *Input) { in.Wallet.Mode = model.ModeB }
	cases := []struct {
		name   string
		mutate func(*Input)
		status Status
		rule   Rule
		code   Code
	}{
		{"mode C within every limit", func(*Input) {}, Allowed, RuleBudget, ""},

		{"mode B at the threshold", modeB, Allowed, RuleThreshold, ""},
		{"mode B above the threshold", func(in *Input) {
			modeB(in)
			in.Policy.Limits.ApprovalThreshold = spend - 1
		}, NeedsApproval, RuleThreshold, ""},
		{"mode B, threshold zero", func(in *Input) {
			modeB(in)
			in.Policy.Limits.ApprovalThreshold = 0
		}, NeedsApproval, RuleThreshold, ""},
		{"mode B has no budget", func(in *Input) {
			modeB(in)
			in.Usage.BudgetSpent = math.MaxUint64
		}, Allowed, RuleThreshold, ""},

		{"session required, none open", func(in *Input) { in.Policy.SessionRequired = true }, Blocked, RuleSession, CodeNeedsSession},
		{"session covers the spend", func(in *Input) {
			in.Policy.SessionRequired = true
			in.Usage.Session = &Session{Remaining: spend}
		}, Allowed, RuleBudget, ""},
		{"session too small", func(in *Input) {
			in.Policy.SessionRequired = true
			in.Usage.Session = &Session{Remaining: spend - 1}
		}, Blocked, RuleSession, CodeNeedsSession},
		{"a session that is not required does not limit", func(in *Input) { in.Usage.Session = &Session{} }, Allowed, RuleBudget, ""},

		{"hour at the limit", func(in *Input) { in.Usage.Hour.Lovelace = 20_000_000 - spend }, Allowed, RuleBudget, ""},
		{"hour over the limit", func(in *Input) { in.Usage.Hour.Lovelace = 20_000_000 - spend + 1 }, Blocked, RulePerHour, CodeBudgetExceeded},
		{"hour overflows", func(in *Input) { in.Usage.Hour.Lovelace = math.MaxUint64 }, Blocked, RulePerHour, CodeBudgetExceeded},
		{"day at the limit", func(in *Input) { in.Usage.Day.Lovelace = 50_000_000 - spend }, Allowed, RuleBudget, ""},
		{"day over the limit", func(in *Input) { in.Usage.Day.Lovelace = 50_000_000 - spend + 1 }, Blocked, RulePerDay, CodeBudgetExceeded},
		{"last transaction of the hour", func(in *Input) { in.Usage.Hour.Transactions = 3 }, Allowed, RuleBudget, ""},
		{"one transaction too many", func(in *Input) { in.Usage.Hour.Transactions = 4 }, Blocked, RuleTxPerHour, CodeBudgetExceeded},
		{"zero transactions per hour prohibits", func(in *Input) { in.Policy.Limits.TxPerHour = 0 }, Blocked, RuleTxPerHour, CodeBudgetExceeded},

		{"last new destination of the hour", func(in *Input) { in.Usage.Hour.NewDestinations = 1 }, Allowed, RuleBudget, ""},
		{"new destination over the hour (M-14)", func(in *Input) { in.Usage.Hour.NewDestinations = 2 }, Blocked, RuleNewPerHour, CodeBudgetExceeded},
		{"known destination at the limit", func(in *Input) {
			in.Usage.Hour.NewDestinations = 2
			in.Usage.Known = knows(shop)
		}, Allowed, RuleBudget, ""},
		{"two new destinations at once", func(in *Input) {
			in.Usage.Hour.NewDestinations = 1
			in.View.Outputs = append(in.View.Outputs, model.Output{Address: other, Value: model.Value{Lovelace: 1}})
		}, Blocked, RuleNewPerHour, CodeBudgetExceeded},
		{"new destination over the day", func(in *Input) { in.Usage.Day.NewDestinations = 5 }, Blocked, RuleNewPerDay, CodeBudgetExceeded},
		{"a consolidation has no destination", func(in *Input) {
			in.View.Outputs = in.View.Outputs[1:]
			in.Usage.Hour.NewDestinations = 2
			in.Usage.Day.NewDestinations = 5
		}, Allowed, RuleBudget, ""},

		{"budget at the limit", func(in *Input) { in.Usage.BudgetSpent = 100_000_000 - spend }, Allowed, RuleBudget, ""},
		{"budget exceeded", func(in *Input) { in.Usage.BudgetSpent = 100_000_000 - spend + 1 }, Blocked, RuleBudget, CodeBudgetExceeded},
		{"zero budget prohibits", func(in *Input) { in.Policy.Limits.Budget = 0 }, Blocked, RuleBudget, CodeBudgetExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseC()
			tc.mutate(&in)
			v := Evaluate(in)
			if v.Status != tc.status || v.Rule != tc.rule || v.Code != tc.code {
				t.Fatalf("got %s/%s/%s (%s), want %s/%s/%s", v.Status, v.Rule, v.Code, v.Detail, tc.status, tc.rule, tc.code)
			}
			if v.Detail == "" || v.Spend.Lovelace == 0 {
				t.Errorf("verdict without detail or spend: %+v", v)
			}
		})
	}
}

// TestOrderBC follows section 3.6 through the rules of modes B and C.
func TestOrderBC(t *testing.T) {
	in := baseC()
	in.Policy.SessionRequired = true
	in.View.Certificates = []model.Certificate{{}}
	in.Policy.Limits.PerTx = 1
	in.Usage.Hour.Lovelace = math.MaxUint64
	in.Usage.BudgetSpent = math.MaxUint64
	want := []Rule{RuleSession, RuleCertificates, RulePerTx, RulePerHour, RuleBudget, RuleBudget}
	for i, rule := range want {
		if got := Evaluate(in).Rule; got != rule {
			t.Fatalf("step %d: got %s, want %s", i, got, rule)
		}
		switch i {
		case 0:
			in.Usage.Session = &Session{Remaining: math.MaxUint64}
		case 1:
			in.View.Certificates = nil
		case 2:
			in.Policy.Limits.PerTx = 10_000_000
		case 3:
			in.Usage.Hour.Lovelace = 0
		case 4:
			in.Usage.BudgetSpent = 0
		}
	}
	if v := Evaluate(in); v.Status != Allowed {
		t.Fatalf("got %+v", v)
	}
}

func TestDefaultTemplate(t *testing.T) {
	tpl := DefaultTemplate(model.Preprod)
	p, l := tpl.Policy, tpl.Policy.Limits
	if tpl.Mode != model.ModeC || !p.Destinations.Any || p.SessionRequired || p.Frozen {
		t.Errorf("mode %s, destinations %+v, session %v", tpl.Mode, p.Destinations, p.SessionRequired)
	}
	if len(p.Networks) != 1 || p.Networks[0] != model.Preprod {
		t.Errorf("networks %v", p.Networks)
	}
	// Decision 96.
	if l.Budget != 100_000_000 || l.PerTx != l.Budget/5 || l.NewDestinationsPerHour != 2 || l.NewDestinationsPerDay != 5 {
		t.Errorf("limits %+v", l)
	}
	// A zero limit prohibits (decision 38): every limit of mode C has a
	// value, and nothing beyond plain outputs is allowed.
	for name, v := range map[string]uint64{
		"per_tx": l.PerTx, "per_hour": l.PerHour, "per_day": l.PerDay, "max_fee": l.MaxFee,
		"tx_per_hour": uint64(l.TxPerHour), "max_live_drafts": uint64(l.MaxLiveDrafts), "max_ttl_seconds": uint64(l.MaxTTLSeconds),
	} {
		if v == 0 {
			t.Errorf("%s is zero", name)
		}
	}
	if p.Structure != (model.Structure{}) || len(p.Assets) != 0 {
		t.Errorf("structure %+v, assets %v", p.Structure, p.Assets)
	}
	// Each call gives its own policy.
	DefaultTemplate(model.Preprod).Policy.Networks[0] = model.Mainnet
	if DefaultTemplate(model.Preprod).Policy.Networks[0] != model.Preprod {
		t.Error("templates share their networks")
	}
}
