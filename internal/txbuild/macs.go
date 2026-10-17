// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package txbuild

import (
	"cmp"
	"errors"
	"math/bits"
	"slices"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// errNotCovered reports a pool that cannot cover the target.
var errNotCovered = errors.New("txbuild: the available UTxOs do not cover the target")

// selectOptions configure MACS. They mirror Apollo's MACSSelector.
type selectOptions struct {
	DustThreshold uint64 // ADA-only UTxOs below this are swept; 0 disables sweeping
	MaxDust       int    // dust inputs added per selection
	MinChange     uint64 // smallest lovelace leftover worth keeping; 0 disables the steering
}

// selectMACS chooses inputs with the Multi-Asset Coin Selection algorithm as
// Apollo v2 implements it, which is the oracle of the tests (section 8.2):
//
//  1. For the first asset class still missing (tokens by policy and name,
//     lovelace last), prefer a UTxO that covers it alone; among those, the
//     highest priority v ÷ (|v − mean| + 1), skipping for lovelace any that
//     would leave less than MinChange; failing that, the largest. If none
//     covers it alone, take the highest priority.
//  2. Repeat until the target is covered, then drop the inputs that later
//     picks made redundant, lowest priority first.
//  3. Sweep up to MaxDust ADA-only UTxOs below DustThreshold, smallest first.
//
// Means are floors over the whole pool, counting absent assets as zero.
// Priorities are compared exactly in 128-bit integers. Ties go to the larger
// value and then to the smaller reference as text ("txid#index"), as in
// Apollo. The result is deterministic.
func selectMACS(pool []chain.UTxO, target model.Value, o selectOptions) ([]chain.UTxO, error) {
	remaining := cloneValue(target)
	if remaining.Lovelace == 0 && !remaining.HasAssets() {
		return nil, nil
	}
	cands := make([]candidate, len(pool))
	for i, u := range pool {
		cands[i] = candidate{utxo: u, ref: u.In.String()}
	}
	classes := targetClasses(target)
	views := make([]*classView, len(classes))
	for i, c := range classes {
		views[i] = newClassView(c, cands)
	}

	selected := make([]bool, len(cands))
	var picks []pick
	for {
		ci, deficit, ok := firstDeficit(remaining, classes)
		if !ok {
			break
		}
		var minChange uint64
		if classes[ci].coin {
			minChange = o.MinChange
		}
		idx := views[ci].next(cands, selected, deficit, minChange)
		if idx < 0 {
			return nil, errNotCovered
		}
		selected[idx] = true
		picks = append(picks, pick{idx: idx, v: views[ci].vals[idx], dev: views[ci].devs[idx]})
		subtractSaturating(&remaining, cands[idx].utxo.Value)
	}

	pruneRedundant(picks, views, classes, target, cands)
	var out []chain.UTxO
	keep := make([]bool, len(cands))
	for _, p := range picks {
		if !p.pruned {
			out = append(out, cands[p.idx].utxo)
			keep[p.idx] = true
		}
	}
	return sweepDust(out, keep, cands, o), nil
}

type candidate struct {
	utxo chain.UTxO
	ref  string
}

// class is one asset class of the target: a token or lovelace.
type class struct {
	asset model.AssetID
	coin  bool
}

func (c class) of(v model.Value) uint64 {
	if c.coin {
		return v.Lovelace
	}
	return v.Assets[c.asset]
}

// targetClasses lists the target's tokens by policy and name, then lovelace.
func targetClasses(target model.Value) []class {
	var out []class
	for a, q := range target.Assets {
		if q > 0 {
			out = append(out, class{asset: a})
		}
	}
	slices.SortFunc(out, func(x, y class) int { return x.asset.Compare(y.asset) })
	return append(out, class{coin: true})
}

func firstDeficit(remaining model.Value, classes []class) (int, uint64, bool) {
	for i, c := range classes {
		if q := c.of(remaining); q > 0 {
			return i, q, true
		}
	}
	return 0, 0, false
}

// classView holds one class's per-candidate quantities and deviations from
// the pool mean, which stay fixed during a selection.
type classView struct {
	vals, devs []uint64
	held       []int // candidates with a positive quantity, in pool order
	poolMax    uint64

	byPriority, byValue []int // built on first use
	prioCur, valCur     int
}

func newClassView(c class, cands []candidate) *classView {
	v := &classView{vals: make([]uint64, len(cands)), devs: make([]uint64, len(cands))}
	var hi, lo uint64
	for j, cand := range cands {
		q := c.of(cand.utxo.Value)
		v.vals[j] = q
		var carry uint64
		lo, carry = bits.Add64(lo, q, 0)
		hi += carry
		if q > 0 {
			v.held = append(v.held, j)
			v.poolMax = max(v.poolMax, q)
		}
	}
	var mean uint64
	if n := uint64(len(cands)); n > 0 {
		mean, _ = bits.Div64(hi, lo, n) // hi < n, since each term is below 2^64
	}
	for _, j := range v.held {
		if v.vals[j] >= mean {
			v.devs[j] = v.vals[j] - mean
		} else {
			v.devs[j] = mean - v.vals[j]
		}
	}
	return v
}

// availableMax is an upper bound on the largest unselected quantity: the
// pool maximum until byValue exists, the exact maximum afterwards.
func (v *classView) availableMax(selected []bool) uint64 {
	if v.byValue == nil {
		return v.poolMax
	}
	for v.valCur < len(v.byValue) && selected[v.byValue[v.valCur]] {
		v.valCur++
	}
	if v.valCur >= len(v.byValue) {
		return 0
	}
	return v.vals[v.byValue[v.valCur]]
}

// next returns the candidate to pick for a deficit, or -1.
func (v *classView) next(cands []candidate, selected []bool, deficit, minChange uint64) int {
	if v.availableMax(selected) >= deficit {
		best, largest := -1, -1
		for _, i := range v.held {
			if selected[i] || v.vals[i] < deficit {
				continue
			}
			if largest == -1 || biggerThen(v.vals[i], cands[i].ref, v.vals[largest], cands[largest].ref) {
				largest = i
			}
			if left := v.vals[i] - deficit; minChange > 0 && left != 0 && left < minChange {
				continue
			}
			if best == -1 || higherPriority(v.vals[i], v.devs[i], cands[i].ref, v.vals[best], v.devs[best], cands[best].ref) {
				best = i
			}
		}
		if best >= 0 {
			return best
		}
		if largest >= 0 {
			return largest
		}
		// The bound was stale: earlier picks took the largest candidates.
		v.byValue = slices.Clone(v.held)
		slices.SortFunc(v.byValue, func(x, y int) int {
			if c := cmp.Compare(v.vals[y], v.vals[x]); c != 0 {
				return c
			}
			return cmp.Compare(cands[x].ref, cands[y].ref)
		})
	}
	if v.byPriority == nil {
		v.byPriority = slices.Clone(v.held)
		slices.SortFunc(v.byPriority, func(x, y int) int {
			return priorityOrder(v.vals[x], v.devs[x], cands[x].ref, v.vals[y], v.devs[y], cands[y].ref)
		})
	}
	for v.prioCur < len(v.byPriority) && selected[v.byPriority[v.prioCur]] {
		v.prioCur++
	}
	if v.prioCur >= len(v.byPriority) {
		return -1
	}
	return v.byPriority[v.prioCur]
}

// biggerThen orders fallbacks: the larger quantity, then the smaller ref.
func biggerThen(v1 uint64, ref1 string, v2 uint64, ref2 string) bool {
	if v1 != v2 {
		return v1 > v2
	}
	return ref1 < ref2
}

// mulAddOne returns v·(d+1) as a 128-bit number. It cannot overflow:
// v·d + v ≤ (2⁶⁴−1)² + 2⁶⁴−1 < 2¹²⁸.
func mulAddOne(v, d uint64) (hi, lo uint64) {
	hi, lo = bits.Mul64(v, d)
	var carry uint64
	lo, carry = bits.Add64(lo, v, 0)
	return hi + carry, lo
}

// priorityOrder is negative when (v1, d1) has the higher priority
// v ÷ (d + 1), compared by cross-multiplication; ties go to the larger value,
// then the smaller ref.
func priorityOrder(v1, d1 uint64, ref1 string, v2, d2 uint64, ref2 string) int {
	lh, ll := mulAddOne(v1, d2)
	rh, rl := mulAddOne(v2, d1)
	if c := cmp.Compare(rh, lh); c != 0 {
		return c
	}
	if c := cmp.Compare(rl, ll); c != 0 {
		return c
	}
	if v1 != v2 {
		return cmp.Compare(v2, v1)
	}
	return cmp.Compare(ref1, ref2)
}

func higherPriority(v1, d1 uint64, ref1 string, v2, d2 uint64, ref2 string) bool {
	return priorityOrder(v1, d1, ref1, v2, d2, ref2) < 0
}

type pick struct {
	idx    int
	v, dev uint64 // priority terms in the class the pick was made for
	pruned bool
}

// pruneRedundant drops picks whose removal keeps every class covered, trying
// the lowest priority first.
func pruneRedundant(picks []pick, views []*classView, classes []class, target model.Value, cands []candidate) {
	if len(picks) < 2 {
		return
	}
	// Token quantities are only bounded per output, so sums use 128 bits.
	sums := make([]u128, len(classes))
	for i := range classes {
		for _, p := range picks {
			sums[i] = sums[i].add(views[i].vals[p.idx])
		}
	}
	order := make([]*pick, len(picks))
	for i := range picks {
		order[i] = &picks[i]
	}
	slices.SortStableFunc(order, func(a, b *pick) int {
		return -priorityOrder(a.v, a.dev, cands[a.idx].ref, b.v, b.dev, cands[b.idx].ref)
	})
	for _, p := range order {
		redundant := true
		for i, c := range classes {
			if !sums[i].sub(views[i].vals[p.idx]).atLeast(c.of(target)) {
				redundant = false
				break
			}
		}
		if redundant {
			p.pruned = true
			for i := range classes {
				sums[i] = sums[i].sub(views[i].vals[p.idx])
			}
		}
	}
}

// u128 is an unsigned 128-bit sum. sub is only called with a term that was
// added before, so it never goes below zero.
type u128 struct{ hi, lo uint64 }

func (x u128) add(q uint64) u128 {
	lo, carry := bits.Add64(x.lo, q, 0)
	return u128{x.hi + carry, lo}
}

func (x u128) sub(q uint64) u128 {
	lo, borrow := bits.Sub64(x.lo, q, 0)
	return u128{x.hi - borrow, lo}
}

func (x u128) atLeast(q uint64) bool { return x.hi > 0 || x.lo >= q }

// sweepDust appends up to MaxDust unselected ADA-only UTxOs below the
// threshold, smallest first. UTxOs with tokens are never swept.
func sweepDust(out []chain.UTxO, keep []bool, cands []candidate, o selectOptions) []chain.UTxO {
	if o.DustThreshold == 0 || o.MaxDust <= 0 || len(out) == 0 {
		return out
	}
	var dust []int
	for i, c := range cands {
		if !keep[i] && c.utxo.Value.Lovelace < o.DustThreshold && !c.utxo.Value.HasAssets() {
			dust = append(dust, i)
		}
	}
	slices.SortFunc(dust, func(x, y int) int {
		if c := cmp.Compare(cands[x].utxo.Value.Lovelace, cands[y].utxo.Value.Lovelace); c != 0 {
			return c
		}
		return cmp.Compare(cands[x].ref, cands[y].ref)
	})
	for i := 0; i < len(dust) && i < o.MaxDust; i++ {
		out = append(out, cands[dust[i]].utxo)
	}
	return out
}

func cloneValue(v model.Value) model.Value {
	out := model.Value{Lovelace: v.Lovelace}
	if len(v.Assets) > 0 {
		out.Assets = make(map[model.AssetID]uint64, len(v.Assets))
		for a, q := range v.Assets {
			out.Assets[a] = q
		}
	}
	return out
}

// subtractSaturating removes from r what u holds of r's classes, stopping
// at zero.
func subtractSaturating(r *model.Value, u model.Value) {
	r.Lovelace -= min(r.Lovelace, u.Lovelace)
	for a, q := range r.Assets {
		r.Assets[a] = q - min(q, u.Assets[a])
	}
}
