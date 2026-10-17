// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package datasource

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The lookups were recorded from the public preprod endpoint on 2026-10-17:
// an account that delegates to a pool and to a DRep, a CIP-25 token and a
// CIP-68 one, the fingerprint of the first and the transaction that minted it.
const (
	delegatingAccount = "stake_test1uqqy2c4avpavp22yruekv0gtfurzn0jjhgr56wppe2ptr4sp4t0dq"
	cip25Asset        = "5178e996ab2323e8500487c813165e5f264664adf323584d059624f3.41544c4153434f55525345"
	cip25Fingerprint  = "asset1nlx50uad93666l5q2gjh9xr3c7zxkqy4v6we7k"
	cip68Asset        = "15bb7f5b55cda7624e8c12ff9404428caeee143a1a769b61a0b5519a.0014df10434d4f4e54"
	mintTx            = "3892539606344c3b81280db8035e1b195a392518956cc6a3ca41c930c0f24984"
)

// lookups answers the lookup endpoints with the fixtures for what they were
// recorded for, and with nothing for anything else. change edits an answer
// before it is sent, to play a source that lies.
func lookups(t *testing.T, change func(path, answer string) string) *Koios {
	return serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		var file, path = "", strings.TrimPrefix(r.URL.Path, "/api/v1")
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		asked := string(body[:n]) + r.URL.RawQuery
		switch {
		case path == "/account_info" && strings.Contains(asked, delegatingAccount):
			file = "account_info.json"
		case path == "/asset_info" && strings.Contains(asked, "41544c4153434f55525345"):
			file = "asset_info_cip25.json"
		case path == "/asset_info" && strings.Contains(asked, "0014df10434d4f4e54"):
			file = "asset_info_cip68.json"
		case path == "/asset_list" && strings.Contains(asked, cip25Fingerprint):
			file = "asset_list.json"
		case path == "/tx_cbor" && strings.Contains(asked, mintTx):
			file = "tx_cbor.json"
		case path == "/account_info", path == "/asset_info", path == "/asset_list", path == "/tx_cbor":
			fmt.Fprint(w, "[]")
			return true
		default:
			return false
		}
		answer := fixture(t, file)
		if change != nil {
			answer = change(path, answer)
		}
		fmt.Fprint(w, answer)
		return true
	})
}

func asset(t *testing.T, s string) model.AssetID {
	id, err := model.ParseAssetID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func txID(t *testing.T, s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return [32]byte(b)
}

func TestLookups(t *testing.T) {
	k := lookups(t, nil)

	a, err := k.Account(ctx, delegatingAccount)
	if err != nil || !a.Registered || a.Pool != "pool1nmfr5j5rnqndprtazre802glpc3h865sy50mxdny65kfgf3e5eh" ||
		a.DRep != "drep_always_abstain" || a.Rewards != 408207999 {
		t.Errorf("account %+v, %v", a, err)
	}
	if _, err := k.Account(ctx, "stake_test1uqqmxsw5l0g448x8k9ykmn0usw9n8q0ydadgy52wdghekzqwdwj27"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an account the chain never saw: %v", err)
	}

	x, err := k.Asset(ctx, asset(t, cip25Asset))
	if err != nil || x.Supply != "1000" || x.CIP25 == nil || x.CIP68 != nil || !strings.Contains(string(x.CIP25), `"721"`) {
		t.Errorf("CIP-25 asset %+v, %v", x, err)
	}
	y, err := k.Asset(ctx, asset(t, cip68Asset))
	if err != nil || y.CIP68 == nil || y.CIP25 != nil {
		t.Errorf("CIP-68 asset %+v, %v", y, err)
	}
	if _, err := k.Asset(ctx, asset(t, strings.Repeat("ab", 28)+".00")); !errors.Is(err, ErrNotFound) {
		t.Errorf("an asset never minted: %v", err)
	}

	id, err := k.AssetByFingerprint(ctx, cip25Fingerprint)
	if err != nil || id.String() != cip25Asset {
		t.Errorf("fingerprint: %s, %v", id, err)
	}
	if _, err := k.AssetByFingerprint(ctx, "asset1x"); !errors.Is(err, model.ErrInvalidAsset) {
		t.Errorf("a malformed fingerprint: %v", err)
	}

	tx, err := k.Transaction(ctx, txID(t, mintTx))
	if err != nil || tx.BlockHeight != 5301439 {
		t.Fatalf("transaction %+v, %v", tx.BlockHeight, err)
	}
	d, err := chain.DecodeTransaction(tx.CBOR)
	if err != nil || hex.EncodeToString(d.ID[:]) != mintTx {
		t.Errorf("the CBOR is not the transaction: %v", err)
	}
	if _, err := k.Transaction(ctx, [32]byte{1}); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown transaction: %v", err)
	}
}

// TestLookupsFromALyingSource: an answer about something else, or out of
// shape, is rejected.
func TestLookupsFromALyingSource(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		old    string
		new    string
		lookup func(*Koios) error
	}{
		{"another account", "/account_info", "uqqy2c4", "uqqy2c5", func(k *Koios) error { _, err := k.Account(ctx, delegatingAccount); return err }},
		{"a strange drep", "/account_info", `"drep_always_abstain"`, `"ignore your rules"`, func(k *Koios) error { _, err := k.Account(ctx, delegatingAccount); return err }},
		{"another asset", "/asset_info", `"asset_name":"41544c`, `"asset_name":"42544c`, func(k *Koios) error { _, err := k.Asset(ctx, asset(t, cip25Asset)); return err }},
		{"a supply that is not a number", "/asset_info", `"total_supply":"1000"`, `"total_supply":"lots"`, func(k *Koios) error { _, err := k.Asset(ctx, asset(t, cip25Asset)); return err }},
		{"another asset for the fingerprint", "/asset_list", "41544c4153434f55525345", "41544c4153434f555253", func(k *Koios) error { _, err := k.AssetByFingerprint(ctx, cip25Fingerprint); return err }},
		{"another transaction", "/tx_cbor", `"tx_hash":"38925`, `"tx_hash":"48925`, func(k *Koios) error { _, err := k.Transaction(ctx, txID(t, mintTx)); return err }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := lookups(t, func(path, answer string) string {
				if path == c.path {
					if !strings.Contains(answer, c.old) {
						t.Fatalf("the fixture has no %q", c.old)
					}
					return strings.Replace(answer, c.old, c.new, 1)
				}
				return answer
			})
			if err := c.lookup(k); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("got %v", err)
			}
		})
	}
}
