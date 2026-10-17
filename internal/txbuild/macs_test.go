// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package txbuild

import (
	"compress/gzip"
	"encoding/json"
	"math"
	"os"
	"slices"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The fixture is written by test/apollo-oracle, which runs Apollo v2's
// MACSSelector on the same scenarios (`make oracle`).
type oracleAsset struct {
	Policy string `json:"policy"`
	Name   string `json:"name"`
	Qty    uint64 `json:"qty"`
}

type oracleUTxO struct {
	Tx       uint32        `json:"tx"`
	Index    uint32        `json:"ix"`
	Lovelace uint64        `json:"l"`
	Assets   []oracleAsset `json:"a"`
}

type oracleScenario struct {
	Name   string       `json:"name"`
	Pool   []oracleUTxO `json:"pool"`
	Target struct {
		Lovelace uint64        `json:"lovelace"`
		Assets   []oracleAsset `json:"assets"`
	} `json:"target"`
	DustThreshold uint64   `json:"dust_threshold"`
	MaxDust       int      `json:"max_dust"`
	MinChange     uint64   `json:"min_change"`
	Selected      []string `json:"selected"`
	Error         bool     `json:"error"`
}

func oracleTxID(n uint32) [32]byte {
	var h [32]byte
	h[28], h[29], h[30], h[31] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
	return h
}

func oracleValue(t *testing.T, lovelace uint64, assets []oracleAsset) model.Value {
	v := model.Value{Lovelace: lovelace}
	for _, a := range assets {
		id, err := model.ParseAssetID(a.Policy + "." + a.Name)
		if err != nil {
			t.Fatal(err)
		}
		if v.Assets == nil {
			v.Assets = map[model.AssetID]uint64{}
		}
		v.Assets[id] = a.Qty
	}
	return v
}

func TestMACSMatchesApollo(t *testing.T) {
	f, err := os.Open("testdata/apollo_macs.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Apollo    string           `json:"apollo"`
		Scenarios []oracleScenario `json:"scenarios"`
	}
	if err := json.NewDecoder(zr).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Scenarios) < 500 {
		t.Fatalf("only %d scenarios", len(fixture.Scenarios))
	}
	for _, s := range fixture.Scenarios {
		pool := make([]chain.UTxO, len(s.Pool))
		for i, u := range s.Pool {
			pool[i] = chain.UTxO{In: chain.TxIn{TxID: oracleTxID(u.Tx), Index: u.Index}, Value: oracleValue(t, u.Lovelace, u.Assets)}
		}
		got, err := selectMACS(pool, oracleValue(t, s.Target.Lovelace, s.Target.Assets),
			selectOptions{DustThreshold: s.DustThreshold, MaxDust: s.MaxDust, MinChange: s.MinChange})
		if s.Error {
			if err == nil {
				t.Errorf("%s: Apollo fails, we selected %d inputs", s.Name, len(got))
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", s.Name, err)
			continue
		}
		refs := make([]string, len(got))
		for i, u := range got {
			refs[i] = u.In.String()
		}
		if !slices.Equal(refs, s.Selected) {
			t.Errorf("%s:\n ours   %v\n Apollo %v", s.Name, refs, s.Selected)
		}
	}
	t.Logf("%d scenarios against Apollo %s", len(fixture.Scenarios), fixture.Apollo)
}

// defaultSelect is Apollo's recommended configuration.
var defaultSelect = selectOptions{DustThreshold: 1_000_000, MaxDust: 2, MinChange: 1_500_000}

func ada(n float64) uint64 { return uint64(n * 1_000_000) }

func utxo(tx byte, ix uint32, lovelace uint64) chain.UTxO {
	return chain.UTxO{In: chain.TxIn{TxID: [32]byte{31: tx}, Index: ix}, Value: model.Value{Lovelace: lovelace}}
}

func TestMACSExample(t *testing.T) {
	// investigacion/gestion-utxos.md, section 6.
	var pool []chain.UTxO
	for i, a := range []float64{100, 50, 20, 10, 5, 3, 1.2, 0.8} {
		pool = append(pool, utxo(byte(i+1), 0, ada(a)))
	}
	got, err := selectMACS(pool, model.Value{Lovelace: ada(10.17)}, defaultSelect)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Value.Lovelace != ada(20) || got[1].Value.Lovelace != ada(0.8) {
		t.Fatalf("got %v", got)
	}
}

func TestMACSEdges(t *testing.T) {
	if got, err := selectMACS(nil, model.Value{}, defaultSelect); err != nil || got != nil {
		t.Errorf("empty target: %v, %v", got, err)
	}
	if _, err := selectMACS([]chain.UTxO{utxo(1, 0, 5)}, model.Value{Lovelace: 6}, defaultSelect); err == nil {
		t.Error("an uncoverable target was covered")
	}
	// Means and priorities stay exact near the top of uint64.
	big := []chain.UTxO{utxo(1, 0, math.MaxUint64-1), utxo(2, 0, math.MaxUint64), utxo(3, 0, 1)}
	got, err := selectMACS(big, model.Value{Lovelace: math.MaxUint64}, selectOptions{})
	if err != nil || len(got) != 1 || got[0].Value.Lovelace != math.MaxUint64 {
		t.Errorf("huge values: %v, %v", got, err)
	}
	// Results never repeat an input and always cover the target.
	pool := []chain.UTxO{utxo(1, 0, ada(3)), utxo(2, 0, ada(4)), utxo(3, 0, ada(0.5)), utxo(4, 0, ada(0.6))}
	got, err = selectMACS(pool, model.Value{Lovelace: ada(6)}, defaultSelect)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[chain.TxIn]bool{}
	var sum uint64
	for _, u := range got {
		if seen[u.In] {
			t.Fatal("repeated input")
		}
		seen[u.In] = true
		sum += u.Value.Lovelace
	}
	if sum < ada(6) {
		t.Fatalf("selection of %d does not cover", sum)
	}
}
