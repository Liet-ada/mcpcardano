// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Command apollo-oracle runs Apollo's MACS coin selection, the oracle of the
// builder's tests (section 8.2 of the specification), on deterministic
// scenarios and writes the results as a fixture for internal/txbuild.
//
// It is a separate module so that Apollo and its dependencies, including an
// older gouroboros, never enter the project's module graph. Regenerate the
// fixture with `make oracle`.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/big"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Salvionied/apollo/v2"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
)

type asset struct {
	Policy string `json:"policy"`
	Name   string `json:"name"`
	Qty    uint64 `json:"qty"`
}

// utxo identifies its transaction by a number: the id is that number in
// the last four of 32 bytes, which keeps the fixture small.
type utxo struct {
	Tx       uint32  `json:"tx"`
	Index    uint32  `json:"ix"`
	Lovelace uint64  `json:"l"`
	Assets   []asset `json:"a,omitempty"`
}

type value struct {
	Lovelace uint64  `json:"lovelace"`
	Assets   []asset `json:"assets,omitempty"`
}

type scenario struct {
	Name          string   `json:"name"`
	Pool          []utxo   `json:"pool"`
	Target        value    `json:"target"`
	DustThreshold uint64   `json:"dust_threshold"`
	MaxDust       int      `json:"max_dust"`
	MinChange     uint64   `json:"min_change"`
	Selected      []string `json:"selected"` // in Apollo's order
	Error         bool     `json:"error"`
}

type fixture struct {
	Apollo    string     `json:"apollo"`
	Seed      uint64     `json:"seed"`
	Scenarios []scenario `json:"scenarios"`
}

// A preprod address from CIP-19; selection does not look at it.
const address = "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgs68faae"

func main() {
	out := flag.String("out", "../../internal/txbuild/testdata/apollo_macs.json.gz", "fixture to write, gzip-compressed")
	seed := flag.Uint64("seed", 20261016, "generator seed")
	n := flag.Int("n", 800, "random scenarios")
	flag.Parse()

	addr, err := common.NewAddress(address)
	check(err)
	f := fixture{Apollo: "v2.1.3", Seed: *seed, Scenarios: handmade()}
	r := rand.New(rand.NewPCG(*seed, *seed^0x9e3779b97f4a7c15))
	for i := range *n {
		f.Scenarios = append(f.Scenarios, random(r, fmt.Sprintf("random-%03d", i)))
	}
	for i := range f.Scenarios {
		run(&f.Scenarios[i], addr)
	}
	b, err := json.Marshal(f)
	check(err)
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	check(err)
	zw.ModTime = time.Time{} // reproducible bytes
	_, err = zw.Write(b)
	check(err)
	check(zw.Close())
	check(os.WriteFile(*out, buf.Bytes(), 0o644))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(s *scenario, addr common.Address) {
	pool := make([]common.Utxo, len(s.Pool))
	for i, u := range s.Pool {
		pool[i] = common.Utxo{
			Id:     shelley.NewShelleyTransactionInput(txid(u.Tx), int(u.Index)),
			Output: apollo.NewBabbageOutput(addr, apollo.NewValue(u.Lovelace, multiAsset(u.Assets)), nil, nil),
		}
	}
	sel := &apollo.MACSSelector{DustThreshold: s.DustThreshold, MaxDustInputs: s.MaxDust, MinChange: s.MinChange}
	got, err := sel.Select(context.Background(), pool, apollo.NewValue(s.Target.Lovelace, multiAsset(s.Target.Assets)))
	if err != nil {
		s.Error = true
		return
	}
	s.Selected = []string{}
	for _, u := range got {
		s.Selected = append(s.Selected, hex.EncodeToString(u.Id.Id().Bytes())+"#"+strconv.FormatUint(uint64(u.Id.Index()), 10))
	}
}

func multiAsset(as []asset) *common.MultiAsset[common.MultiAssetTypeOutput] {
	if len(as) == 0 {
		return nil
	}
	data := map[common.Blake2b224]map[cbor.ByteString]common.MultiAssetTypeOutput{}
	for _, a := range as {
		p, err := hex.DecodeString(a.Policy)
		check(err)
		n, err := hex.DecodeString(a.Name)
		check(err)
		policy := common.NewBlake2b224(p)
		if data[policy] == nil {
			data[policy] = map[cbor.ByteString]common.MultiAssetTypeOutput{}
		}
		data[policy][cbor.NewByteString(n)] = new(big.Int).SetUint64(a.Qty)
	}
	ma := common.NewMultiAsset(data)
	return &ma
}

func txid(n uint32) string {
	h := make([]byte, 32)
	h[28], h[29], h[30], h[31] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
	return hex.EncodeToString(h)
}

// handmade are the cases worked out by hand in the specification and in
// Apollo's own tests.
func handmade() []scenario {
	var out []scenario
	// Section 6 of investigacion/gestion-utxos.md: a 10 ADA payment plus fee
	// picks the 20 ADA UTxO and sweeps the 0.8 ADA one.
	pool := []utxo{}
	for i, ada := range []uint64{100_000_000, 50_000_000, 20_000_000, 10_000_000, 5_000_000, 3_000_000, 1_200_000, 800_000} {
		pool = append(pool, utxo{Tx: uint32(i + 1), Lovelace: ada})
	}
	out = append(out, scenario{Name: "paper-example", Pool: pool, Target: value{Lovelace: 10_170_000},
		DustThreshold: 1_000_000, MaxDust: 2, MinChange: 1_500_000})
	// Apollo's TestMACSPrefersNearAverageUtxo.
	pool = nil
	for i, ada := range []uint64{10_000_000, 10_000_000, 10_000_000, 10_000_000, 12_000_000, 50_000_000} {
		pool = append(pool, utxo{Tx: uint32(i + 1), Lovelace: ada})
	}
	out = append(out, scenario{Name: "near-average", Pool: pool, Target: value{Lovelace: 5_000_000}})
	// References "#10" and "#2" of one transaction tie on value: Apollo
	// compares them as text, so "#10" wins.
	out = append(out, scenario{Name: "ref-text-order", Pool: []utxo{
		{Tx: 9, Index: 2, Lovelace: 7_000_000},
		{Tx: 9, Index: 10, Lovelace: 7_000_000},
	}, Target: value{Lovelace: 3_000_000}})
	return out
}

var policies = []string{
	"0000000000000000000000000000000000000000000000000000aa01",
	"0000000000000000000000000000000000000000000000000000aa02",
	"ff00000000000000000000000000000000000000000000000000aa03",
	"7f00000000000000000000000000000000000000000000000000aa04",
}

var names = []string{"", "41", "4142", "ff", "0000"}

func randomAssets(r *rand.Rand) []asset {
	n := 1 + r.IntN(4)
	seen := map[string]bool{}
	var out []asset
	for range n {
		a := asset{Policy: policies[r.IntN(len(policies))], Name: names[r.IntN(len(names))]}
		if seen[a.Policy+a.Name] {
			continue
		}
		seen[a.Policy+a.Name] = true
		switch r.IntN(10) {
		case 0:
			a.Qty = math.MaxUint64/2 + r.Uint64N(math.MaxUint64/4) // sums overflow 64 bits
		case 1, 2:
			a.Qty = 1
		default:
			a.Qty = 1 + r.Uint64N(1_000_000)
		}
		out = append(out, a)
	}
	return out
}

func randomLovelace(r *rand.Rand) uint64 {
	switch r.IntN(10) {
	case 0, 1:
		return 200_000 + r.Uint64N(800_000) // dust
	case 2, 3, 4:
		return 1_000_000 + r.Uint64N(19_000_000)
	case 5, 6, 7, 8:
		return 20_000_000 + r.Uint64N(480_000_000)
	default:
		return 500_000_000 + r.Uint64N(20_000_000_000)
	}
}

func random(r *rand.Rand, name string) scenario {
	s := scenario{Name: name}
	size := 1 + r.IntN(60)
	if r.IntN(8) == 0 {
		size = 100 + r.IntN(100)
	}
	var sum uint64
	held := map[[2]string]uint64{}
	var lastTx uint32
	for i := range size {
		u := utxo{Lovelace: randomLovelace(r)}
		if i > 0 && r.IntN(4) == 0 {
			u.Tx, u.Index = lastTx, uint32(1+r.IntN(14))
		} else {
			u.Tx = r.Uint32()
		}
		lastTx = u.Tx
		if r.IntN(10) < 3 {
			u.Assets = randomAssets(r)
			for _, a := range u.Assets {
				k := [2]string{a.Policy, a.Name}
				held[k] = min(held[k]+a.Qty, math.MaxUint64) // only a hint for the target
			}
		}
		sum += u.Lovelace
		s.Pool = append(s.Pool, dedupe(s.Pool, u))
	}
	// Mostly payable targets, some just above the pool's total, and some
	// just below one UTxO, so that its leftover falls in the change dead band.
	switch r.IntN(10) {
	case 0:
		s.Target.Lovelace = sum + 1
	case 1:
		s.Target.Lovelace = 0
	case 2, 3, 4:
		u := s.Pool[r.IntN(len(s.Pool))].Lovelace
		s.Target.Lovelace = u - min(u-1, r.Uint64N(5_000_000))
	default:
		s.Target.Lovelace = 1 + r.Uint64N(sum)
	}
	// Repeated values exercise the tie-breaks.
	if r.IntN(5) == 0 && len(s.Pool) > 1 {
		for i := range s.Pool {
			if r.IntN(2) == 0 {
				s.Pool[i].Lovelace = s.Pool[0].Lovelace
			}
		}
	}
	if len(held) > 0 && r.IntN(10) < 4 {
		keys := make([][2]string, 0, len(held))
		for k := range held {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b [2]string) int { return strings.Compare(a[0]+"."+a[1], b[0]+"."+b[1]) })
		for _, k := range keys {
			q := held[k]
			want := 1 + r.Uint64N(q)
			if r.IntN(12) == 0 {
				want = q + 1
			}
			s.Target.Assets = append(s.Target.Assets, asset{Policy: k[0], Name: k[1], Qty: want})
			if r.IntN(2) == 0 {
				break
			}
		}
	}
	switch r.IntN(3) {
	case 0: // the paper's algorithm, no sweep
	case 1:
		s.DustThreshold, s.MaxDust, s.MinChange = 1_000_000, 2, 1_500_000 // Apollo's defaults
	default:
		s.DustThreshold, s.MaxDust, s.MinChange = 2_000_000, 3, 1_000_000
	}
	return s
}

// dedupe makes sure no reference repeats within a pool.
func dedupe(pool []utxo, u utxo) utxo {
	for {
		clash := false
		for _, p := range pool {
			if p.Tx == u.Tx && p.Index == u.Index {
				clash = true
				break
			}
		}
		if !clash {
			return u
		}
		u.Index++
	}
}
