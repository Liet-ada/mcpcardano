// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package datasource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

var ctx = context.Background()

// The fixtures in testdata/koios-preprod are answers recorded from the public
// preprod endpoint on 2026-10-16, for the queries this client makes.
func fixture(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "koios-preprod", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func fixtureAddress(t testing.TB) model.Address {
	t.Helper()
	a, err := chain.ParseAddress(model.Preprod, fixture(t, "address.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// serve answers the four Koios endpoints with the fixtures, or with override
// when it returns true.
func serve(t *testing.T, override func(w http.ResponseWriter, r *http.Request) bool) *Koios {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if override != nil && override(w, r) {
			return
		}
		switch r.URL.Path {
		case "/api/v1/genesis":
			fmt.Fprint(w, fixture(t, "genesis.json"))
		case "/api/v1/tip":
			fmt.Fprint(w, fixture(t, "tip.json"))
		case "/api/v1/epoch_params":
			if r.URL.Query().Get("_epoch_no") != "319" {
				fmt.Fprint(w, "[]")
				return
			}
			fmt.Fprint(w, fixture(t, "epoch_params.json"))
		case "/api/v1/address_utxos":
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			var body struct {
				Addresses []string `json:"_addresses"`
				Extended  bool     `json:"_extended"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !body.Extended ||
				len(body.Addresses) != 1 || body.Addresses[0] != fixture(t, "address.txt") {
				fmt.Fprint(w, "[]")
				return
			}
			if r.URL.Query().Get("offset") != "0" {
				fmt.Fprint(w, "[]")
				return
			}
			fmt.Fprint(w, fixture(t, "address_utxos.json"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	k, err := NewKoios(KoiosConfig{
		Network: model.Preprod,
		BaseURL: srv.URL + "/api/v1",
		sleep:   func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestFixtures(t *testing.T) {
	k := serve(t, nil)
	if err := k.CheckNetwork(ctx); err != nil {
		t.Fatal(err)
	}

	tip, err := k.Tip(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tip.Slot != 136515214 || tip.Height != 5301025 || tip.Epoch != 319 ||
		!tip.Time.Equal(time.Unix(1792198414, 0)) || fmt.Sprintf("%x", tip.Hash[:2]) != "2fb0" {
		t.Errorf("tip %+v", tip)
	}

	p, err := k.ProtocolParameters(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := chain.ProtocolParameters{
		Epoch: 319, MinFeeA: 44, MinFeeB: 155381, MaxTxSize: 16384, MaxValueSize: 5000, CoinsPerUTxOByte: 4310,
		KeyDeposit: 2_000_000, PoolDeposit: 500_000_000, DRepDeposit: 500_000_000, GovActionDeposit: 1_000_000_000,
		PriceMem: chain.Rational{Num: 577, Den: 10000}, PriceStep: chain.Rational{Num: 721, Den: 10000000},
		MaxTxExMem: 17_500_000, MaxTxExSteps: 10_000_000_000, CollateralPercent: 150, MaxCollateralInputs: 3,
		MinFeeRefScriptByte: chain.Rational{Num: 15, Den: 1}, ProtocolMajor: 11,
	}
	if p != want {
		t.Errorf("parameters\n got %+v\nwant %+v", p, want)
	}

	addr := fixtureAddress(t)
	utxos, err := k.UTxOs(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 3 {
		t.Fatalf("%d UTxOs", len(utxos))
	}
	first := utxos[0]
	if first.In.String() != "149d2aa2323ab07106df7b82512e1f9cb897a12d6ac5c03693c1a7cd81d622b2#0" ||
		first.Value.Lovelace != 3_000_000 || len(first.Value.Assets) != 4 || !first.Address.Equal(addr) ||
		first.HasDatum || first.HasScript {
		t.Errorf("first UTxO %+v", first)
	}
	vega, _ := model.ParseAssetID("c0e65618da9d3d39d20d0f7cdefc6481aebe616fe063a447d8647c90.56454741")
	if first.Value.Assets[vega] != 1_000_000_000 {
		t.Errorf("assets %v", first.Value.Assets)
	}
	for i := 1; i < len(utxos); i++ {
		if utxos[i-1].In.Compare(utxos[i].In) >= 0 {
			t.Error("UTxOs are not ordered by reference")
		}
	}
}

func TestNetworkMismatch(t *testing.T) {
	k := serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/v1/genesis" {
			fmt.Fprint(w, `[{"networkmagic":"2"}]`)
			return true
		}
		return false
	})
	if err := k.CheckNetwork(ctx); !errors.Is(err, ErrNetworkMismatch) {
		t.Fatalf("got %v", err)
	}
	mainnet, _ := chain.ParseAddress(model.Mainnet, "addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8")
	if _, err := k.UTxOs(ctx, mainnet); !errors.Is(err, ErrNetworkMismatch) {
		t.Fatalf("mainnet address: got %v", err)
	}
}

func TestRetries(t *testing.T) {
	var calls atomic.Int32
	k := serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/v1/tip" && calls.Add(1) < 3 {
			http.Error(w, "busy", http.StatusTooManyRequests)
			return true
		}
		return false
	})
	if _, err := k.Tip(ctx); err != nil {
		t.Fatalf("third attempt should succeed: %v", err)
	}

	calls.Store(0)
	k = serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		calls.Add(1)
		http.Error(w, "down", http.StatusBadGateway)
		return true
	})
	if _, err := k.Tip(ctx); !errors.Is(err, ErrUnavailable) || calls.Load() != 3 {
		t.Fatalf("got %v after %d calls", err, calls.Load())
	}

	calls.Store(0)
	k = serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		calls.Add(1)
		http.Error(w, "no", http.StatusBadRequest)
		return true
	})
	if _, err := k.Tip(ctx); !errors.Is(err, ErrUnavailable) || calls.Load() != 1 {
		t.Fatalf("a 400 must not be retried: %v after %d calls", err, calls.Load())
	}
}

func TestCanceledContext(t *testing.T) {
	k := serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return true
	})
	k.cfg.sleep = sleep
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := k.Tip(c); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	k := serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/v1/tip" {
			http.Redirect(w, r, "https://example.com/tip", http.StatusFound)
			return true
		}
		return false
	})
	if _, err := k.Tip(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestOversizedAnswer(t *testing.T) {
	k := serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		fmt.Fprint(w, "["+strings.Repeat(" ", 1<<10)+"]")
		return true
	})
	k.cfg.MaxResponseBytes = 512
	if _, err := k.Tip(ctx); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("got %v", err)
	}
}

// replaceUTxOs serves a modified copy of the recorded UTxOs.
func replaceUTxOs(t *testing.T, change func([]map[string]any) []map[string]any) *Koios {
	var rows []map[string]any
	if err := json.Unmarshal([]byte(fixture(t, "address_utxos.json")), &rows); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(change(rows))
	return serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/v1/address_utxos" {
			w.Write(b)
			return true
		}
		return false
	})
}

func TestLyingUTxOs(t *testing.T) {
	addr := fixtureAddress(t)
	cases := map[string]func([]map[string]any) []map[string]any{
		"another address": func(r []map[string]any) []map[string]any {
			r[1]["address"] = "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz"
			return r
		},
		"short hash": func(r []map[string]any) []map[string]any { r[0]["tx_hash"] = "149d"; return r },
		"uppercase hash": func(r []map[string]any) []map[string]any {
			r[0]["tx_hash"] = strings.ToUpper(r[0]["tx_hash"].(string))
			return r
		},
		"negative value":     func(r []map[string]any) []map[string]any { r[0]["value"] = "-1"; return r },
		"value as float":     func(r []map[string]any) []map[string]any { r[0]["value"] = "3000000.5"; return r },
		"value overflow":     func(r []map[string]any) []map[string]any { r[0]["value"] = "18446744073709551616"; return r },
		"missing value":      func(r []map[string]any) []map[string]any { delete(r[0], "value"); return r },
		"index out of range": func(r []map[string]any) []map[string]any { r[0]["tx_index"] = 70000; return r },
		"duplicate":          func(r []map[string]any) []map[string]any { return append(r, r[0]) },
		"zero quantity": func(r []map[string]any) []map[string]any {
			r[0]["asset_list"].([]any)[0].(map[string]any)["quantity"] = "0"
			return r
		},
		"bad policy": func(r []map[string]any) []map[string]any {
			r[0]["asset_list"].([]any)[0].(map[string]any)["policy_id"] = "54f9"
			return r
		},
		"long asset name": func(r []map[string]any) []map[string]any {
			r[0]["asset_list"].([]any)[0].(map[string]any)["asset_name"] = strings.Repeat("00", 33)
			return r
		},
		"duplicate asset": func(r []map[string]any) []map[string]any {
			l := r[0]["asset_list"].([]any)
			r[0]["asset_list"] = append(l, l[0])
			return r
		},
	}
	for name, change := range cases {
		k := replaceUTxOs(t, change)
		if _, err := k.UTxOs(ctx, addr); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestUTxOFlags(t *testing.T) {
	k := replaceUTxOs(t, func(r []map[string]any) []map[string]any {
		r[0]["inline_datum"] = map[string]any{"bytes": "d87980"}
		r[1]["reference_script"] = map[string]any{"type": "plutusV3"}
		r[2]["is_spent"] = true
		return r
	})
	utxos, err := k.UTxOs(ctx, fixtureAddress(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 2 || !utxos[0].HasDatum || utxos[0].HasScript || !utxos[1].HasScript {
		t.Fatalf("got %+v", utxos)
	}
}

// TestPaging serves 2,500 generated UTxOs in pages of 1,000.
func TestPaging(t *testing.T) {
	addr := fixtureAddress(t)
	bech := fixture(t, "address.txt")
	const total = 2500
	var requests atomic.Int32
	k := serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/v1/address_utxos" {
			return false
		}
		requests.Add(1)
		q := r.URL.Query()
		if q.Get("order") != "tx_hash.asc,tx_index.asc" || q.Get("limit") != "1000" {
			http.Error(w, "unexpected query", http.StatusBadRequest)
			return true
		}
		var offset int
		fmt.Sscan(q.Get("offset"), &offset)
		var rows []map[string]any
		for i := offset; i < total && i < offset+1000; i++ {
			rows = append(rows, map[string]any{
				"tx_hash": fmt.Sprintf("%064x", i/10), "tx_index": i % 10, "address": bech,
				"value": "1000000", "asset_list": []any{}, "is_spent": false,
			})
		}
		json.NewEncoder(w).Encode(rows)
		return true
	})
	utxos, err := k.UTxOs(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != total || requests.Load() != 3 {
		t.Fatalf("%d UTxOs in %d requests", len(utxos), requests.Load())
	}
	k.cfg.maxUTxOs = 2000
	if _, err := k.UTxOs(ctx, addr); !errors.Is(err, ErrTooManyUTxOs) {
		t.Fatalf("got %v", err)
	}
}

func TestLyingParameters(t *testing.T) {
	cases := map[string]string{
		"huge exponent":   `[{"epoch_no":319,"min_fee_a":44,"min_fee_b":155381,"max_tx_size":16384,"max_val_size":5000,"coins_per_utxo_size":"4310","key_deposit":"2000000","pool_deposit":"500000000","drep_deposit":"500000000","gov_action_deposit":"1000000000","price_mem":1e999999999,"price_step":7.21e-05,"max_tx_ex_mem":17500000,"max_tx_ex_steps":10000000000,"collateral_percent":150,"max_collateral_inputs":3,"min_fee_ref_script_cost_per_byte":15,"protocol_major":11,"protocol_minor":0}]`,
		"another epoch":   strings.Replace(fixture(t, "epoch_params.json"), `"epoch_no":319`, `"epoch_no":318`, 1),
		"implausible fee": strings.Replace(fixture(t, "epoch_params.json"), `"min_fee_a":44`, `"min_fee_a":0`, 1),
		"float integer":   strings.Replace(fixture(t, "epoch_params.json"), `"min_fee_a":44`, `"min_fee_a":44.5`, 1),
		"missing field":   strings.Replace(fixture(t, "epoch_params.json"), `"min_fee_b":155381,`, ``, 1),
		"not json":        `<html>`,
		"two rows":        "[" + strings.Trim(fixture(t, "epoch_params.json"), "[]") + "," + strings.Trim(fixture(t, "epoch_params.json"), "[]") + "]",
	}
	for name, body := range cases {
		k := serve(t, func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == "/api/v1/epoch_params" {
				fmt.Fprint(w, body)
				return true
			}
			return false
		})
		if _, err := k.ProtocolParameters(ctx); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	k := serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/v1/epoch_params" {
			fmt.Fprint(w, "[]")
			return true
		}
		return false
	})
	if _, err := k.ProtocolParameters(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("new epoch without parameters: got %v", err)
	}
}

func TestLyingTip(t *testing.T) {
	for name, body := range map[string]string{
		"no rows":       `[]`,
		"missing slot":  `[{"hash":"2fb012b6c372b9b3f34a16c170d288dd214ea642c65bc79f9e313a82963009c7","epoch_no":319,"block_height":1,"block_time":1}]`,
		"negative slot": `[{"hash":"2fb012b6c372b9b3f34a16c170d288dd214ea642c65bc79f9e313a82963009c7","epoch_no":319,"abs_slot":-1,"block_height":1,"block_time":1}]`,
		"bad hash":      `[{"hash":"zz","epoch_no":319,"abs_slot":1,"block_height":1,"block_time":1}]`,
	} {
		k := serve(t, func(w http.ResponseWriter, r *http.Request) bool {
			fmt.Fprint(w, body)
			return true
		})
		if _, err := k.Tip(ctx); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestNewKoios(t *testing.T) {
	for _, u := range []string{"", "https://koios.example/api/v1", "http://127.0.0.1:8053/api/v1", "http://localhost/api/v1", "http://[::1]/api/v1"} {
		if _, err := NewKoios(KoiosConfig{Network: model.Preprod, BaseURL: u}); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
	for _, u := range []string{"http://koios.example/api/v1", "ftp://x/", "https://user:pw@x/", "https://x/?a=1", "not a url", "https://"} {
		if _, err := NewKoios(KoiosConfig{Network: model.Preprod, BaseURL: u}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if _, err := NewKoios(KoiosConfig{Network: "testnet"}); err == nil {
		t.Error("unknown network accepted")
	}
	for _, n := range []model.Network{model.Mainnet, model.Preprod, model.Preview} {
		if !strings.HasPrefix(DefaultKoiosURL(n), "https://") {
			t.Errorf("default URL of %s", n)
		}
	}
}

// FuzzParseUTxOs feeds arbitrary answers to the UTxO parser: it must never
// panic and never return a UTxO for another address.
func FuzzParseUTxOs(f *testing.F) {
	f.Add([]byte(fixture(f, "address_utxos.json")))
	f.Add([]byte(`[{"tx_hash":null}]`))
	f.Add([]byte(`[]`))
	addr := fixtureAddress(f)
	var body atomic.Pointer[[]byte]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(*body.Load())
	}))
	defer srv.Close()
	k, err := NewKoios(KoiosConfig{Network: model.Preprod, BaseURL: srv.URL, Attempts: 1})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(&data)
		utxos, err := k.UTxOs(ctx, addr)
		if err != nil {
			return
		}
		for _, u := range utxos {
			if !u.Address.Equal(addr) {
				t.Fatal("UTxO for another address")
			}
		}
	})
}
