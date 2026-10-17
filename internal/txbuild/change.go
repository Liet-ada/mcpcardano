// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package txbuild

import (
	"slices"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// maxAssetsPerChange is the most tokens a change output carries (section
// 8.3, step 2).
const maxAssetsPerChange = 10

// changePlan is the change of a transaction: token outputs, each with its
// minimum ADA, and the ADA that remains split per the target number of
// UTxOs.
type changePlan struct {
	outputs []model.Value
	// short is how much more lovelace the inputs must bring for the change
	// to be valid; zero when the plan is complete.
	short uint64
	// dust is a positive remainder below the minimum of an ADA-only output.
	// It is only reported with short > 0.
	dust uint64
}

// planChange splits surplus into change outputs (section 8.3). adaOnly is the
// number of ADA-only UTxOs the wallet keeps besides this change.
func planChange(c *cborx.Codec, own model.Address, surplus model.Value, adaOnly int, pol model.UTxOPolicy, perByte uint64) (changePlan, error) {
	var plan changePlan
	tokens, err := tokenChange(c, own, surplus.Assets, perByte)
	if err != nil {
		return plan, err
	}
	var locked uint64
	for _, v := range tokens {
		locked += v.Lovelace // bounded by the inputs, which fit in uint64
	}
	plan.outputs = tokens
	if surplus.Lovelace < locked {
		plan.short = locked - surplus.Lovelace
		return plan, nil
	}
	rest := surplus.Lovelace - locked
	if rest == 0 {
		return plan, nil
	}
	single, err := minADA(c, own, nil, perByte)
	if err != nil {
		return plan, err
	}
	if rest < single {
		// The dead band: too little for an output of its own.
		plan.short, plan.dust = single-rest, rest
		return plan, nil
	}
	parts := uint64(1)
	split := max(pol.MinSplit, single)
	target := uint64(pol.TargetADAOnly)
	if uint64(adaOnly)+1 < target && pol.MinSplit > 0 && rest >= 2*split {
		parts = min(target-uint64(adaOnly), rest/split)
	}
	each, extra := rest/parts, rest%parts
	for i := range parts {
		l := each
		if i == 0 {
			l += extra
		}
		plan.outputs = append(plan.outputs, model.Value{Lovelace: l})
	}
	return plan, nil
}

// tokenChange groups tokens by policy into outputs of at most ten tokens: a
// policy's tokens stay together and share an output with other policies when
// they fit, and a policy with more than ten fills outputs of its own. Each
// output holds its minimum ADA.
func tokenChange(c *cborx.Codec, own model.Address, assets map[model.AssetID]uint64, perByte uint64) ([]model.Value, error) {
	byPolicy := map[model.PolicyID][]model.AssetID{}
	for a, q := range assets {
		if q > 0 {
			byPolicy[a.Policy] = append(byPolicy[a.Policy], a)
		}
	}
	policies := make([]model.PolicyID, 0, len(byPolicy))
	for p := range byPolicy {
		policies = append(policies, p)
	}
	slices.SortFunc(policies, func(a, b model.PolicyID) int { return slices.Compare(a[:], b[:]) })

	var groups [][]model.AssetID
	var current []model.AssetID
	flush := func() {
		if len(current) > 0 {
			groups = append(groups, current)
			current = nil
		}
	}
	for _, p := range policies {
		ids := byPolicy[p]
		slices.SortFunc(ids, model.AssetID.Compare)
		if len(ids) > maxAssetsPerChange {
			flush()
			for len(ids) > 0 {
				n := min(len(ids), maxAssetsPerChange)
				groups = append(groups, ids[:n])
				ids = ids[n:]
			}
			continue
		}
		if len(current)+len(ids) > maxAssetsPerChange {
			flush()
		}
		current = append(current, ids...)
	}
	flush()

	out := make([]model.Value, 0, len(groups))
	for _, g := range groups {
		v := model.Value{Assets: make(map[model.AssetID]uint64, len(g))}
		for _, a := range g {
			v.Assets[a] = assets[a]
		}
		l, err := minADA(c, own, v.Assets, perByte)
		if err != nil {
			return nil, err
		}
		v.Lovelace = l
		out = append(out, v)
	}
	return out, nil
}
