// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package datasource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// testProjectID is the key the test endpoint expects.
const testProjectID = "preprodTestKey0123456789"

// The fixtures in testdata/blockfrost-preprod hold the same chain data as
// those of koios-preprod, written by hand in the shapes of Blockfrost's
// OpenAPI description, so that both clients must read the same things.
func bfFixture(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "blockfrost-preprod", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// bfEdit returns a fixture after change, which edits it as JSON.
func bfEdit[T any](t testing.TB, name string, change func(*T)) string {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(bfFixture(t, name)), &v); err != nil {
		t.Fatal(err)
	}
	change(&v)
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func notFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `{"status_code":404,"error":"Not Found","message":"The requested component has not been found."}`)
}

// serveBlockfrost answers the Blockfrost endpoints the client calls with the
// fixtures, or with override when it returns true. Every request must carry
// the project id.
func serveBlockfrost(t *testing.T, override func(w http.ResponseWriter, r *http.Request) bool) *Blockfrost {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("project_id") != testProjectID {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"status_code":403,"error":"Forbidden","message":"Invalid project token."}`)
			return
		}
		if override != nil && override(w, r) {
			return
		}
		path, _ := strings.CutPrefix(r.URL.Path, "/api/v0")
		switch path {
		case "/genesis":
			fmt.Fprint(w, bfFixture(t, "genesis.json"))
		case "/blocks/latest":
			fmt.Fprint(w, bfFixture(t, "blocks_latest.json"))
		case "/epochs/latest/parameters":
			fmt.Fprint(w, bfFixture(t, "epochs_latest_parameters.json"))
		case "/addresses/" + bfFixture(t, "address.txt") + "/utxos":
			if r.URL.Query().Get("page") != "1" || r.URL.Query().Get("order") != "asc" {
				fmt.Fprint(w, "[]")
				return
			}
			fmt.Fprint(w, bfFixture(t, "address_utxos.json"))
		case "/accounts/" + delegatingAccount:
			fmt.Fprint(w, bfFixture(t, "account.json"))
		case "/assets/" + strings.ReplaceAll(cip25Asset, ".", ""):
			fmt.Fprint(w, bfFixture(t, "asset_cip25.json"))
		case "/assets/" + strings.ReplaceAll(cip68Asset, ".", ""):
			fmt.Fprint(w, bfFixture(t, "asset_cip68.json"))
		case "/txs/" + mintTx:
			fmt.Fprint(w, bfFixture(t, "tx.json"))
		case "/txs/" + mintTx + "/cbor":
			fmt.Fprint(w, bfFixture(t, "tx_cbor.json"))
		default:
			notFound(w)
		}
	}))
	t.Cleanup(srv.Close)
	b, err := NewBlockfrost(BlockfrostConfig{
		Network:   model.Preprod,
		ProjectID: testProjectID,
		BaseURL:   srv.URL + "/api/v0",
		sleep:     func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// noKey fails if an error names the project id.
func noKey(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), testProjectID) {
		t.Errorf("the error shows the project id: %v", err)
	}
}

func TestBlockfrostFixtures(t *testing.T) {
	b := serveBlockfrost(t, nil)
	if err := b.CheckNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	k := serve(t, nil)

	tip, err := b.Tip(ctx)
	if want, _ := k.Tip(ctx); err != nil || tip != want {
		t.Errorf("tip %+v, %v; Koios reads %+v", tip, err, want)
	}
	p, err := b.ProtocolParameters(ctx)
	if want, _ := k.ProtocolParameters(ctx); err != nil || p != want {
		t.Errorf("parameters %+v, %v\nKoios reads %+v", p, err, want)
	}
	utxos, err := b.UTxOs(ctx, fixtureAddress(t))
	if want, _ := k.UTxOs(ctx, fixtureAddress(t)); err != nil || len(utxos) != 3 || !reflect.DeepEqual(utxos, want) {
		t.Errorf("UTxOs %+v, %v\nKoios reads %+v", utxos, err, want)
	}
}

func TestBlockfrostLookups(t *testing.T) {
	b := serveBlockfrost(t, nil)
	k := lookups(t, nil)

	a, err := b.Account(ctx, delegatingAccount)
	if want, _ := k.Account(ctx, delegatingAccount); err != nil || a != want {
		t.Errorf("account %+v, %v; Koios reads %+v", a, err, want)
	}
	if _, err := b.Account(ctx, "stake_test1uqqmxsw5l0g448x8k9ykmn0usw9n8q0ydadgy52wdghekzqwdwj27"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an account the chain never saw: %v", err)
	}
	if _, err := b.Account(ctx, "stake_test1../../txs"); err == nil || passes(err) {
		t.Errorf("a stake address that is a path: %v", err)
	}

	for _, s := range []string{cip25Asset, cip68Asset} {
		x, err := b.Asset(ctx, asset(t, s))
		if want, _ := k.Asset(ctx, asset(t, s)); err != nil || x.Standard == "" || !reflect.DeepEqual(x, want) {
			t.Errorf("asset %+v, %v\nKoios reads %+v", x, err, want)
		}
	}
	if _, err := b.Asset(ctx, asset(t, strings.Repeat("ab", 28)+".00")); !errors.Is(err, ErrNotFound) {
		t.Errorf("an asset never minted: %v", err)
	}

	if _, err := b.AssetByFingerprint(ctx, cip25Fingerprint); !errors.Is(err, ErrUnsupported) {
		t.Errorf("by fingerprint: %v", err)
	}
	if _, err := b.AssetByFingerprint(ctx, "asset1!"); !errors.Is(err, model.ErrInvalidAsset) {
		t.Errorf("not a fingerprint: %v", err)
	}

	tx, err := b.Transaction(ctx, txID(t, mintTx))
	if want, _ := k.Transaction(ctx, txID(t, mintTx)); err != nil || !reflect.DeepEqual(tx, want) {
		t.Errorf("transaction %+v, %v\nKoios reads %+v", tx, err, want)
	}
	if _, err := b.Transaction(ctx, [32]byte{1}); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown transaction: %v", err)
	}
}

func TestBlockfrostStatuses(t *testing.T) {
	for _, c := range []struct {
		status   int
		attempts int32
		says     string
	}{
		{http.StatusForbidden, 1, "project id"},
		{http.StatusPaymentRequired, 1, "daily requests"},
		{http.StatusTeapot, 1, "banned"},
		{http.StatusTooManyRequests, 3, "429"},
		{http.StatusInternalServerError, 3, "500"},
		{http.StatusBadRequest, 1, "400"},
	} {
		var calls atomic.Int32
		b := serveBlockfrost(t, func(w http.ResponseWriter, r *http.Request) bool {
			calls.Add(1)
			w.WriteHeader(c.status)
			return true
		})
		_, err := b.Tip(ctx)
		if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), c.says) || calls.Load() != c.attempts {
			t.Errorf("HTTP %d: %v after %d calls", c.status, err, calls.Load())
		}
		noKey(t, err)
	}

	// The latest block always exists: a 404 is a source that does not work.
	b := serveBlockfrost(t, func(w http.ResponseWriter, r *http.Request) bool {
		notFound(w)
		return true
	})
	if _, err := b.Tip(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("404 for the latest block: %v", err)
	}
}

func TestBlockfrostKey(t *testing.T) {
	var got string
	b := serveBlockfrost(t, func(w http.ResponseWriter, r *http.Request) bool {
		got = r.Header.Get("project_id")
		return false
	})
	if _, err := b.Tip(ctx); err != nil || got != testProjectID {
		t.Errorf("project_id %q, %v", got, err)
	}
	if s := fmt.Sprintf("%+v %#v", b, b); strings.Contains(s, testProjectID) {
		t.Errorf("the client prints its key: %s", s)
	}

	for _, key := range []string{"", "preprod key", "preprod\r\nX-Other: 1", "preprodé", strings.Repeat("a", 129)} {
		_, err := NewBlockfrost(BlockfrostConfig{Network: model.Preprod, ProjectID: key})
		if err == nil || (key != "" && strings.Contains(err.Error(), key)) {
			t.Errorf("project id %q: %v", key, err)
		}
	}
	for _, u := range []string{"http://blockfrost.example/api/v0", "https://user@blockfrost.example", "ftp://x", "https://x?y=1"} {
		if _, err := NewBlockfrost(BlockfrostConfig{Network: model.Preprod, ProjectID: testProjectID, BaseURL: u}); err == nil {
			t.Errorf("URL %q accepted", u)
		}
	}
	if _, err := NewBlockfrost(BlockfrostConfig{Network: "testnet", ProjectID: testProjectID}); err == nil {
		t.Error("unknown network accepted")
	}
	if c, err := NewBlockfrost(BlockfrostConfig{Network: model.Mainnet, ProjectID: testProjectID}); err != nil || c.base.Host != "cardano-mainnet.blockfrost.io" {
		t.Errorf("default URL: %v", err)
	}

	mismatch := serveBlockfrost(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/genesis") {
			fmt.Fprint(w, bfEdit(t, "genesis.json", func(g *map[string]any) { (*g)["network_magic"] = 2 }))
			return true
		}
		return false
	})
	if err := mismatch.CheckNetwork(ctx); !errors.Is(err, ErrNetworkMismatch) {
		t.Errorf("preview's genesis: %v", err)
	}
}

// utxoServer answers the address's UTxOs with rows, count per page.
func utxoServer(t *testing.T, rows []map[string]any) *Blockfrost {
	return serveBlockfrost(t, func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/utxos") {
			return false
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		count, _ := strconv.Atoi(r.URL.Query().Get("count"))
		from, to := min((page-1)*count, len(rows)), min(page*count, len(rows))
		json.NewEncoder(w).Encode(rows[from:to])
		return true
	})
}

func fixtureUTxOs(t *testing.T) []map[string]any {
	var rows []map[string]any
	json.Unmarshal([]byte(bfFixture(t, "address_utxos.json")), &rows)
	return rows
}

func TestBlockfrostLyingUTxOs(t *testing.T) {
	addr := fixtureAddress(t)
	for name, change := range map[string]func([]map[string]any) []map[string]any{
		"another address": func(r []map[string]any) []map[string]any {
			r[1]["address"] = "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz"
			return r
		},
		"twice":       func(r []map[string]any) []map[string]any { return append(r, r[0]) },
		"no lovelace": func(r []map[string]any) []map[string]any { r[0]["amount"] = r[0]["amount"].([]any)[1:]; return r },
		"lovelace twice": func(r []map[string]any) []map[string]any {
			a := r[2]["amount"].([]any)
			r[2]["amount"] = append(a, a[0])
			return r
		},
		"a bad unit": func(r []map[string]any) []map[string]any {
			r[0]["amount"].([]any)[1].(map[string]any)["unit"] = "abc"
			return r
		},
		"zero tokens": func(r []map[string]any) []map[string]any {
			r[0]["amount"].([]any)[1].(map[string]any)["quantity"] = "0"
			return r
		},
		"a token twice": func(r []map[string]any) []map[string]any {
			a := r[0]["amount"].([]any)
			r[0]["amount"] = append(a, a[1])
			return r
		},
		"a negative": func(r []map[string]any) []map[string]any {
			r[0]["amount"].([]any)[0].(map[string]any)["quantity"] = "-1"
			return r
		},
		"no index":        func(r []map[string]any) []map[string]any { delete(r[0], "output_index"); return r },
		"a large index":   func(r []map[string]any) []map[string]any { r[0]["output_index"] = 70000; return r },
		"a short tx hash": func(r []map[string]any) []map[string]any { r[0]["tx_hash"] = "abcd"; return r },
	} {
		_, err := utxoServer(t, change(fixtureUTxOs(t))).UTxOs(ctx, addr)
		if !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// An address the chain has never seen.
	b := serveBlockfrost(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/utxos") {
			notFound(w)
			return true
		}
		return false
	})
	if u, err := b.UTxOs(ctx, addr); err != nil || len(u) != 0 {
		t.Errorf("unseen address: %v, %v", u, err)
	}

	// The datum and the reference script.
	rows := fixtureUTxOs(t)
	rows[0]["inline_datum"] = "19a6aa"
	rows[1]["reference_script_hash"] = "13a3efd825703a352a8f71f4e2758d08c28c564e8dfcce9f77776ad1"
	u, err := utxoServer(t, rows).UTxOs(ctx, addr)
	if err != nil || !u[0].HasDatum || u[0].HasScript || u[1].HasDatum || !u[1].HasScript {
		t.Errorf("flags %+v, %v", u, err)
	}
}

func TestBlockfrostPaging(t *testing.T) {
	addr := fixtureAddress(t)
	base := fixtureUTxOs(t)[2]
	var rows []map[string]any
	for i := range 5 {
		r := map[string]any{}
		for k, v := range base {
			r[k] = v
		}
		r["output_index"] = i
		rows = append(rows, r)
	}
	b := utxoServer(t, rows)
	b.cfg.pageSize = 2
	if u, err := b.UTxOs(ctx, addr); err != nil || len(u) != 5 {
		t.Errorf("five UTxOs in pages of two: %d, %v", len(u), err)
	}
	b.cfg.maxUTxOs = 4
	if _, err := b.UTxOs(ctx, addr); !errors.Is(err, ErrTooManyUTxOs) {
		t.Errorf("over the most: %v", err)
	}
}

func TestBlockfrostLyingParameters(t *testing.T) {
	for name, c := range map[string]struct {
		change func(*map[string]any)
		want   error
	}{
		"the next epoch":   {func(p *map[string]any) { (*p)["epoch"] = 320 }, ErrUnavailable},
		"the last epoch":   {func(p *map[string]any) { (*p)["epoch"] = 318 }, ErrUnavailable},
		"an old epoch":     {func(p *map[string]any) { (*p)["epoch"] = 300 }, ErrInvalidResponse},
		"no fee":           {func(p *map[string]any) { delete(*p, "min_fee_a") }, ErrInvalidResponse},
		"a null price":     {func(p *map[string]any) { (*p)["price_mem"] = nil }, ErrInvalidResponse},
		"a negative price": {func(p *map[string]any) { (*p)["price_step"] = -1 }, ErrInvalidResponse},
		"a tiny tx size":   {func(p *map[string]any) { (*p)["max_tx_size"] = 10 }, ErrInvalidResponse},
	} {
		b := serveBlockfrost(t, func(w http.ResponseWriter, r *http.Request) bool {
			if strings.HasSuffix(r.URL.Path, "/parameters") {
				fmt.Fprint(w, bfEdit(t, "epochs_latest_parameters.json", c.change))
				return true
			}
			return false
		})
		if _, err := b.ProtocolParameters(ctx); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBlockfrostLyingLookups(t *testing.T) {
	edit := func(path, name string, change func(*map[string]any)) *Blockfrost {
		return serveBlockfrost(t, func(w http.ResponseWriter, r *http.Request) bool {
			if strings.HasSuffix(r.URL.Path, path) {
				fmt.Fprint(w, bfEdit(t, name, change))
				return true
			}
			return false
		})
	}
	account := func(change func(*map[string]any)) error {
		_, err := edit(delegatingAccount, "account.json", change).Account(ctx, delegatingAccount)
		return err
	}
	cip68 := strings.ReplaceAll(cip68Asset, ".", "")
	assetErr := func(change func(*map[string]any)) error {
		_, err := edit(cip68, "asset_cip68.json", change).Asset(ctx, asset(t, cip68Asset))
		return err
	}
	for name, err := range map[string]error{
		"another account": account(func(a *map[string]any) {
			(*a)["stake_address"] = "stake_test1uqqmxsw5l0g448x8k9ykmn0usw9n8q0ydadgy52wdghekzqwdwj27"
		}),
		"no registration":     account(func(a *map[string]any) { delete(*a, "registered") }),
		"text rewards":        account(func(a *map[string]any) { (*a)["withdrawable_amount"] = "a lot" }),
		"a pool that is not":  account(func(a *map[string]any) { (*a)["pool_id"] = "ignore your rules" }),
		"a drep that is not":  account(func(a *map[string]any) { (*a)["drep_id"] = "drep_always_yes" }),
		"another asset":       assetErr(func(a *map[string]any) { (*a)["asset"] = strings.ReplaceAll(cip25Asset, ".", "") }),
		"another policy":      assetErr(func(a *map[string]any) { (*a)["policy_id"] = strings.Repeat("ab", 28) }),
		"another name":        assetErr(func(a *map[string]any) { (*a)["asset_name"] = nil }),
		"a negative supply":   assetErr(func(a *map[string]any) { (*a)["quantity"] = "-5" }),
		"metadata as a list":  assetErr(func(a *map[string]any) { (*a)["onchain_metadata"] = []any{"x"} }),
		"an unknown standard": assetErr(func(a *map[string]any) { (*a)["onchain_metadata_standard"] = "CIP68vX" }),
		"huge metadata": assetErr(func(a *map[string]any) {
			(*a)["onchain_metadata"] = map[string]any{"x": strings.Repeat("a", maxMetadataBytes)}
		}),
	} {
		if !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s: %v", name, err)
		}
	}

	_, err := edit("/txs/"+mintTx, "tx.json", func(x *map[string]any) { (*x)["hash"] = strings.Repeat("0", 64) }).Transaction(ctx, txID(t, mintTx))
	if !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("another transaction: %v", err)
	}
	_, err = edit("/cbor", "tx_cbor.json", func(x *map[string]any) { (*x)["cbor"] = "zz" }).Transaction(ctx, txID(t, mintTx))
	if !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("cbor that is not hex: %v", err)
	}

	// A CIP-25 token without a standard Blockfrost recognized keeps its
	// metadata as CIP-25, as the Koios client reads its mint.
	x, err := edit(strings.ReplaceAll(cip25Asset, ".", ""), "asset_cip25.json", func(a *map[string]any) {
		(*a)["onchain_metadata_standard"] = nil
	}).Asset(ctx, asset(t, cip25Asset))
	if err != nil || x.Standard != CIP25 || x.Metadata == nil {
		t.Errorf("no standard: %+v, %v", x, err)
	}
}

func TestBlockfrostSubmit(t *testing.T) {
	id := txID(t, mintTx)
	tx := []byte{0x84, 0xa0}
	submit := func(status int, body string) (error, int32) {
		var calls atomic.Int32
		b := serveBlockfrost(t, func(w http.ResponseWriter, r *http.Request) bool {
			if !strings.HasSuffix(r.URL.Path, "/tx/submit") {
				return false
			}
			calls.Add(1)
			got, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/cbor" || string(got) != string(tx) {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return true
			}
			w.WriteHeader(status)
			fmt.Fprint(w, body)
			return true
		})
		err := b.Submit(ctx, tx, id)
		noKey(t, err)
		return err, calls.Load()
	}
	if err, _ := submit(http.StatusOK, `"`+mintTx+`"`); err != nil {
		t.Errorf("accepted: %v", err)
	}
	if err, _ := submit(http.StatusOK, `"`+strings.Repeat("0", 64)+`"`); !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("another id: %v", err)
	}
	rejected := `{"status_code":400,"error":"Bad Request","message":"\"transaction submit error ShelleyTxValidationError ShelleyBasedEraConway (ApplyTxError (ConwayUtxowFailure (UtxoFailure (BadInputsUTxO (fromList [TxIn (TxId {unTxId = SafeHash \\\"ab\\\"}) (TxIx 0)]))) :| []))\""}`
	if err, _ := submit(http.StatusBadRequest, rejected); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "BadInputsUTxO") {
		t.Errorf("rejected: %v", err)
	}
	for _, status := range []int{http.StatusTooEarly, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusNotFound} {
		if err, calls := submit(status, ""); !errors.Is(err, ErrUnavailable) || calls != 1 {
			t.Errorf("HTTP %d: %v after %d calls", status, err, calls)
		}
	}
}

func TestBlockfrostConfirmations(t *testing.T) {
	var height atomic.Int64
	height.Store(5301441) // the transaction is in block 5301439
	b := serveBlockfrost(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/blocks/latest") {
			fmt.Fprint(w, bfEdit(t, "blocks_latest.json", func(b *map[string]any) { (*b)["height"] = height.Load() }))
			return true
		}
		return false
	})
	other := [32]byte{1}
	got, err := b.Confirmations(ctx, [][32]byte{txID(t, mintTx), other})
	if err != nil || got[txID(t, mintTx)] != 3 || got[other] != 0 || len(got) != 2 {
		t.Errorf("confirmations %v, %v", got, err)
	}
	// A block made after the tip was read.
	height.Store(5301438)
	if got, err := b.Confirmations(ctx, [][32]byte{txID(t, mintTx)}); err != nil || got[txID(t, mintTx)] != 1 {
		t.Errorf("a block after the tip: %v, %v", got, err)
	}
	height.Store(5301000)
	if _, err := b.Confirmations(ctx, [][32]byte{txID(t, mintTx)}); !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("a block far past the tip: %v", err)
	}
}

func TestBlockfrostReadsTheSameChainAsKoios(t *testing.T) {
	// The parameters are read with an exponent, as Blockfrost writes small
	// numbers.
	if p := bfFixture(t, "epochs_latest_parameters.json"); !strings.Contains(p, `"price_step":7.21e-05`) {
		t.Fatalf("the fixture does not have the exponent: %s", p)
	}
	b := serveBlockfrost(t, nil)
	p, err := b.ProtocolParameters(ctx)
	if err != nil || p.PriceStep != (chain.Rational{Num: 721, Den: 10000000}) {
		t.Errorf("price_step %+v, %v", p.PriceStep, err)
	}
}
