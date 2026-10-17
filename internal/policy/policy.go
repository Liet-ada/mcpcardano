// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package policy evaluates a transaction view against a wallet's policy
// (sections 3.6 and 8.5 of the specification). Evaluate is a pure function:
// no I/O, no clock, no state, so it behaves the same in the server and in
// the wallet and is tested without network or disk.
//
// Milestone H-1 implements the rules that mode A uses. The rules that need
// the spending record (session, windows, budget and threshold) come with the
// wallet in H-2; until then modes B and C are always blocked.
package policy

import (
	"fmt"
	"slices"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Status is the outcome of an evaluation.
type Status string

const (
	Allowed       Status = "allowed"
	NeedsApproval Status = "needs_approval"
	Blocked       Status = "blocked"
)

// Code classifies a block. The boundaries translate it to the error codes of
// sections 4.5 and 5.6.
type Code string

const (
	CodeFrozen          Code = "FROZEN"
	CodeNetworkMismatch Code = "NETWORK_MISMATCH"
	CodePolicyBlocked   Code = "POLICY_BLOCKED"
	CodeBudgetExceeded  Code = "BUDGET_EXCEEDED"
	CodeTTLTooLong      Code = "TTL_TOO_LONG"
)

// Rule names the rule that decided. Names are stable: they reach the agent
// and the audit log.
type Rule string

const (
	RuleOverflow         Rule = "overflow"
	RuleFrozen           Rule = "frozen"
	RuleNetwork          Rule = "network"
	RuleCertificates     Rule = "structure.certificates"
	RuleWithdrawals      Rule = "structure.withdrawals"
	RuleMint             Rule = "structure.mint"
	RuleGovernance       Rule = "structure.governance"
	RuleDonation         Rule = "structure.donation"
	RuleScripts          Rule = "structure.scripts"
	RuleCollateral       Rule = "structure.collateral"
	RuleRequiredSigners  Rule = "structure.required_signers"
	RuleOutputDatum      Rule = "structure.output_datum"
	RuleDestination      Rule = "destinations"
	RuleAsset            Rule = "assets"
	RulePerTx            Rule = "limits.per_tx"
	RuleMaxFee           Rule = "limits.max_fee"
	RuleTTL              Rule = "limits.ttl"
	RuleModeA            Rule = "mode.a"
	RuleModeNotAvailable Rule = "mode.not_available"
)

// Input is everything an evaluation looks at.
type Input struct {
	Wallet model.Wallet
	Policy model.Policy
	View   model.TxView
	// CurrentSlot comes from the evaluating process's own clock, never from
	// the other process (section 9.3).
	CurrentSlot uint64
}

// Verdict is the result of Evaluate. Spend is filled in whenever it could be
// computed, also for blocked transactions.
type Verdict struct {
	Status Status
	Rule   Rule
	Code   Code   // empty unless Blocked
	Detail string // for people and the audit log, never a secret
	Spend  Spend
}

// Spend is what a transaction takes out of the wallet (section 8.5).
type Spend struct {
	// Lovelace is the sum of the outputs that are not the wallet's own, the
	// fee and the donation.
	Lovelace uint64
	// Assets is the quantity of each token in outputs that are not own.
	Assets map[model.AssetID]uint64
	// Destinations are the addresses of the outputs that are not own, once
	// each, in order of appearance.
	Destinations []model.Address
}

// ComputeSpend derives the spend from the body alone: the wallet cannot see
// the value of the inputs, so the spend never depends on them (M-01).
func ComputeSpend(v model.TxView) (Spend, error) {
	var s Spend
	var err error
	if s.Lovelace, err = model.Add(v.Fee, v.Donation); err != nil {
		return Spend{}, err
	}
	for _, o := range v.Outputs {
		if o.Own {
			continue
		}
		if s.Lovelace, err = model.Add(s.Lovelace, o.Value.Lovelace); err != nil {
			return Spend{}, err
		}
		for a, q := range o.Value.Assets {
			if q == 0 {
				continue
			}
			if s.Assets == nil {
				s.Assets = make(map[model.AssetID]uint64)
			}
			if s.Assets[a], err = model.Add(s.Assets[a], q); err != nil {
				return Spend{}, err
			}
		}
		if !containsAddress(s.Destinations, o.Address) {
			s.Destinations = append(s.Destinations, o.Address)
		}
	}
	return s, nil
}

func containsAddress(list []model.Address, a model.Address) bool {
	for _, x := range list {
		if x.Equal(a) {
			return true
		}
	}
	return false
}

// failure is a rule that did not pass.
type failure struct {
	rule   Rule
	code   Code
	detail string
}

func fail(r Rule, c Code, format string, args ...any) *failure {
	return &failure{rule: r, code: c, detail: fmt.Sprintf(format, args...)}
}

// Evaluate applies the rules in the order of section 3.6, from the cheapest
// rejection to the most expensive, and stops at the first that fails.
func Evaluate(in Input) Verdict {
	spend, err := ComputeSpend(in.View)
	if err != nil {
		return Verdict{Status: Blocked, Rule: RuleOverflow, Code: CodePolicyBlocked, Detail: "amounts overflow"}
	}
	checks := []func(Input, Spend) *failure{
		checkFrozen,
		checkNetwork,
		// The session check goes here (H-2).
		checkStructure,
		checkDestinationsAndAssets,
		checkPerTx,
		// Windows, budget and threshold go here (H-2).
	}
	for _, check := range checks {
		if f := check(in, spend); f != nil {
			return Verdict{Status: Blocked, Rule: f.rule, Code: f.code, Detail: f.detail, Spend: spend}
		}
	}
	switch in.Wallet.Mode {
	case model.ModeA:
		// The person always confirms on the hardware wallet.
		return Verdict{Status: NeedsApproval, Rule: RuleModeA, Detail: "sign on the hardware wallet", Spend: spend}
	default:
		return Verdict{Status: Blocked, Rule: RuleModeNotAvailable, Code: CodePolicyBlocked,
			Detail: fmt.Sprintf("mode %q is not available yet", in.Wallet.Mode), Spend: spend}
	}
}

func checkFrozen(in Input, _ Spend) *failure {
	if in.Policy.Frozen {
		return fail(RuleFrozen, CodeFrozen, "the wallet is frozen")
	}
	return nil
}

func checkNetwork(in Input, _ Spend) *failure {
	n := in.Wallet.Network
	enabled := false
	for _, x := range in.Policy.Networks {
		if x == n {
			enabled = true
		}
	}
	if !n.Valid() || !enabled {
		return fail(RuleNetwork, CodeNetworkMismatch, "network %q is not enabled for this wallet", n)
	}
	id := n.AddressID()
	if in.View.NetworkID != nil && *in.View.NetworkID != id {
		return fail(RuleNetwork, CodeNetworkMismatch, "the transaction is for network id %d", *in.View.NetworkID)
	}
	for i, o := range in.View.Outputs {
		if o.Address.NetworkID != id {
			return fail(RuleNetwork, CodeNetworkMismatch, "output %d is an address of network id %d", i, o.Address.NetworkID)
		}
	}
	return nil
}

// checkStructure rejects every feature beyond plain outputs that the policy
// does not allow. Scripts, collateral, governance and donations have no
// policy switch in the MVP and are always rejected (M-03 to M-06).
func checkStructure(in Input, _ Spend) *failure {
	v, s := in.View, in.Policy.Structure
	switch {
	case len(v.Certificates) > 0 && !s.Certificates:
		return fail(RuleCertificates, CodePolicyBlocked, "certificates are not allowed")
	case len(v.Withdrawals) > 0 && !s.Withdrawals:
		return fail(RuleWithdrawals, CodePolicyBlocked, "reward withdrawals are not allowed")
	case len(v.Mint) > 0 && !s.Mint:
		return fail(RuleMint, CodePolicyBlocked, "minting and burning are not allowed")
	case v.Votes > 0 || v.Proposals > 0:
		return fail(RuleGovernance, CodePolicyBlocked, "votes and proposals are not allowed")
	case v.Donation > 0:
		return fail(RuleDonation, CodePolicyBlocked, "treasury donations are not allowed")
	case v.ScriptDataHash || v.ReferenceInputs > 0:
		return fail(RuleScripts, CodePolicyBlocked, "scripts are not allowed")
	case v.Collateral > 0 || v.CollateralReturn || v.TotalCollateral != nil:
		return fail(RuleCollateral, CodePolicyBlocked, "collateral is not allowed")
	}
	for _, h := range v.RequiredSigners {
		p := in.Wallet.Address.Payment
		if p.Kind != model.KeyHash || h != p.Hash {
			return fail(RuleRequiredSigners, CodePolicyBlocked, "the transaction requires a signer other than the wallet")
		}
	}
	for i, o := range v.Outputs {
		if o.HasDatum || o.HasScript {
			return fail(RuleOutputDatum, CodePolicyBlocked, "output %d carries a datum or a script", i)
		}
	}
	return nil
}

// checkDestinationsAndAssets checks where the funds go and which tokens leave
// (M-15: a token not in the list is blocked in any quantity).
func checkDestinationsAndAssets(in Input, spend Spend) *failure {
	for _, d := range spend.Destinations {
		if !in.Policy.Destinations.Permits(d) {
			return fail(RuleDestination, CodePolicyBlocked, "destination %x is not in the allowed list", d.Raw)
		}
	}
	assets := make([]model.AssetID, 0, len(spend.Assets))
	for a := range spend.Assets {
		assets = append(assets, a)
	}
	// Sorted, so the same transaction always names the same token.
	slices.SortFunc(assets, model.AssetID.Compare)
	for _, a := range assets {
		q := spend.Assets[a]
		limit, ok := in.Policy.Assets[a]
		if !ok {
			return fail(RuleAsset, CodePolicyBlocked, "token %s may not leave the wallet", a)
		}
		if q > limit {
			return fail(RuleAsset, CodePolicyBlocked, "%d units of %s exceed the cap of %d", q, a, limit)
		}
	}
	return nil
}

// checkPerTx applies the limits of a single transaction: amount, fee and
// validity (M-10, M-11).
func checkPerTx(in Input, spend Spend) *failure {
	l := in.Policy.Limits
	if spend.Lovelace > l.PerTx {
		return fail(RulePerTx, CodeBudgetExceeded, "spend of %d lovelace exceeds the per-transaction limit of %d", spend.Lovelace, l.PerTx)
	}
	if in.View.Fee > l.MaxFee {
		return fail(RuleMaxFee, CodePolicyBlocked, "fee of %d lovelace exceeds the maximum of %d", in.View.Fee, l.MaxFee)
	}
	ttl := in.View.TTL
	if ttl == nil {
		return fail(RuleTTL, CodeTTLTooLong, "the transaction has no TTL")
	}
	// Slots last one second on mainnet, preprod and preview.
	maxTTL, err := model.Add(in.CurrentSlot, uint64(l.MaxTTLSeconds))
	if err != nil {
		maxTTL = ^uint64(0)
	}
	if *ttl <= in.CurrentSlot {
		return fail(RuleTTL, CodeTTLTooLong, "the TTL slot %d has passed", *ttl)
	}
	if *ttl > maxTTL {
		return fail(RuleTTL, CodeTTLTooLong, "the TTL slot %d is beyond the maximum of %d", *ttl, maxTTL)
	}
	return nil
}
