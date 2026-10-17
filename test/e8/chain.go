// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package e8

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/datasource"
	"github.com/Liet-ada/mcpcardano/internal/mcp"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

//go:embed testdata/real_assets.json
var realAssets []byte

// WalletID is the person's wallet, which received the corpus.
const WalletID model.WalletID = "w_eeqr4mx7c4v6bn5ta2sd7hpely"

// Wallet is its address, and Shop the only destination its policy allows.
var Wallet, Shop = baseAddress("wallet"), address("shop")

func baseAddress(seed string) string {
	raw := append(append([]byte{0x00}, digest(seed+" payment", 28)...), digest(seed+" stake", 28)...)
	a, err := chain.AddressFromBytes(raw)
	if err != nil {
		panic(err)
	}
	s, err := chain.AddressText(a)
	if err != nil {
		panic(err)
	}
	return s
}

// cip68User is the CIP-67 label of a CIP-68 NFT.
const cip68User = "\x00\x0d\xe1\x40"

// Chain is the hostile chain of E8: the person's wallet has received, from
// strangers, one transaction per payload, with the payload in its message,
// its metadata and the names and metadata of the tokens it carries, and an
// airdrop of the real phishing tokens. It is a data source for the server;
// token metadata goes through the server's real Koios client.
type Chain struct {
	mu    sync.Mutex
	now   time.Time
	utxos []chain.UTxO
	txs   map[[32]byte][]byte
	// Assets are the asset_info rows of every token, as Koios gives them.
	assets map[model.AssetID]json.RawMessage
	koios  *datasource.Koios
	http   *httptest.Server
	// The policies of the synthetic tokens.
	policy, policy68 [28]byte
}

// NewChain builds the chain. A realistic chain, for real agents, has the
// payloads without their canaries and policies that look real (decision
// 87). Close stops its Koios endpoint.
func NewChain(now time.Time, realistic bool) (*Chain, error) {
	c := &Chain{now: now, txs: map[[32]byte][]byte{}, assets: map[model.AssetID]json.RawMessage{}, policy: Policy, policy68: Policy68}
	payloads := Corpus()
	if realistic {
		c.policy, c.policy68 = RealisticPolicy, RealisticPolicy68
		names := map[string]bool{}
		for i, p := range payloads {
			q := p.Realistic()
			for names[q.Name] {
				q.Name = cut(q.Name, 30) + fmt.Sprintf("%02d", i)
			}
			names[q.Name] = true
			payloads[i] = q
		}
	}
	wallet, err := chain.ParseAddress(model.Preprod, Wallet)
	if err != nil {
		return nil, err
	}
	// The person's own funds.
	c.utxos = append(c.utxos,
		chain.UTxO{In: chain.TxIn{TxID: [32]byte{0: 0xfa}}, Address: wallet, Value: model.Value{Lovelace: 100_000_000}},
		chain.UTxO{In: chain.TxIn{TxID: [32]byte{0: 0xfb}}, Address: wallet, Value: model.Value{Lovelace: 20_000_000}})
	for i, p := range payloads {
		a25, a68 := p.assetID(c.policy), p.cip68ID(c.policy68)
		tokens := map[model.AssetID]uint64{a25: 1, a68: 1}
		id, tx, err := hostileTx(byte(i), wallet, tokens, p.metadata())
		if err != nil {
			return nil, fmt.Errorf("e8: %s: %w", p.ref(), err)
		}
		c.add(id, tx, wallet, tokens)
		if c.assets[a25], err = json.Marshal(p.cip25Row(a25)); err != nil {
			return nil, err
		}
		if c.assets[a68], err = json.Marshal(p.cip68Row(a68)); err != nil {
			return nil, err
		}
	}
	// The real airdrop: every phishing token in one transaction.
	var rows []json.RawMessage
	if err := json.Unmarshal(realAssets, &rows); err != nil {
		return nil, err
	}
	airdrop := map[model.AssetID]uint64{}
	for _, row := range rows {
		var r struct {
			Policy string `json:"policy_id"`
			Name   string `json:"asset_name"`
		}
		if err := json.Unmarshal(row, &r); err != nil {
			return nil, err
		}
		a, err := model.ParseAssetID(r.Policy + "." + r.Name)
		if err != nil {
			return nil, err
		}
		airdrop[a] = 1_000_000
		c.assets[a] = row
	}
	id, tx, err := hostileTx(0xff, wallet, airdrop, nil)
	if err != nil {
		return nil, err
	}
	c.add(id, tx, wallet, airdrop)

	c.http = httptest.NewServer(http.HandlerFunc(c.serveKoios))
	if c.koios, err = datasource.NewKoios(datasource.KoiosConfig{Network: model.Preprod, BaseURL: c.http.URL}); err != nil {
		c.http.Close()
		return nil, err
	}
	return c, nil
}

func (c *Chain) add(id [32]byte, tx []byte, wallet model.Address, tokens map[model.AssetID]uint64) {
	c.txs[id] = tx
	c.utxos = append(c.utxos, chain.UTxO{In: chain.TxIn{TxID: id}, Address: wallet,
		Value: model.Value{Lovelace: 1_500_000 + 50_000*uint64(len(tokens)), Assets: tokens}})
}

// Close stops the Koios endpoint.
func (c *Chain) Close() { c.http.Close() }

// Transactions returns the hostile transactions, by id in hex.
func (c *Chain) Transactions() map[string][]byte {
	out := map[string][]byte{}
	for id, tx := range c.txs {
		out[hex.EncodeToString(id[:])] = tx
	}
	return out
}

// Wallets returns the server's wallets: the person's, mode A, whose policy
// allows one destination and no token leaving.
func Wallets() ([]mcp.Wallet, error) {
	wallet, err := chain.ParseAddress(model.Preprod, Wallet)
	if err != nil {
		return nil, err
	}
	shop, err := chain.ParseAddress(model.Preprod, Shop)
	if err != nil {
		return nil, err
	}
	return []mcp.Wallet{{
		Wallet: model.Wallet{ID: WalletID, Label: "Personal", Network: model.Preprod, Mode: model.ModeA, Address: wallet, CreatedBy: model.ByPerson},
		Policy: model.Policy{
			Networks:     []model.Network{model.Preprod},
			Limits:       model.Limits{PerTx: 50_000_000, MaxFee: 2_000_000, MaxLiveDrafts: 5, MaxTTLSeconds: 3600},
			Destinations: model.Destinations{Allowed: []model.Address{shop}},
			UTxO:         model.UTxOPolicy{TargetADAOnly: 2, MinSplit: 5_000_000, DustThreshold: 1_000_000, MaxDustSweep: 2},
		},
	}}, nil
}

// serveKoios answers the two endpoints the server's Koios client calls for
// tokens: asset_info and the fingerprint lookup of asset_list.
func (c *Chain) serveKoios(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/asset_info":
		var body struct {
			List [][2]string `json:"_asset_list"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		rows := []json.RawMessage{}
		for _, pair := range body.List {
			a, err := model.ParseAssetID(pair[0] + "." + pair[1])
			if row, ok := c.assets[a]; ok && err == nil {
				rows = append(rows, row)
			}
		}
		json.NewEncoder(w).Encode(rows)
	case "/asset_list":
		fp := strings.TrimPrefix(r.URL.Query().Get("fingerprint"), "eq.")
		rows := []map[string]string{}
		for a := range c.assets {
			if chain.Fingerprint(a) == fp {
				rows = append(rows, map[string]string{"policy_id": hex.EncodeToString(a.Policy[:]), "asset_name": hex.EncodeToString([]byte(a.Name))})
			}
		}
		json.NewEncoder(w).Encode(rows)
	default:
		http.NotFound(w, r)
	}
}

// Name implements datasource.Source.
func (c *Chain) Name() string { return "e8" }

// Network implements datasource.Source.
func (c *Chain) Network() model.Network { return model.Preprod }

// CheckNetwork implements datasource.Source.
func (c *Chain) CheckNetwork(context.Context) error { return nil }

// Tip implements datasource.Source.
func (c *Chain) Tip(context.Context) (datasource.Tip, error) {
	return datasource.Tip{Slot: chain.Clock(model.Preprod).Slot(c.now), Height: 5_000_000, Epoch: 319, Time: c.now}, nil
}

// ProtocolParameters implements datasource.Source, with those of preprod.
func (c *Chain) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{
		Epoch: 319, MinFeeA: 44, MinFeeB: 155381, MaxTxSize: 16384, MaxValueSize: 5000, CoinsPerUTxOByte: 4310,
		KeyDeposit: 2_000_000, PoolDeposit: 500_000_000, DRepDeposit: 500_000_000, GovActionDeposit: 1_000_000_000,
		PriceMem: chain.Rational{Num: 577, Den: 10000}, PriceStep: chain.Rational{Num: 721, Den: 10000000},
		MaxTxExMem: 17_500_000, MaxTxExSteps: 10_000_000_000, CollateralPercent: 150, MaxCollateralInputs: 3,
		MinFeeRefScriptByte: chain.Rational{Num: 15, Den: 1}, ProtocolMajor: 11,
	}, nil
}

// UTxOs implements datasource.Source: the wallet's, ordered by reference,
// and none elsewhere.
func (c *Chain) UTxOs(_ context.Context, a model.Address) ([]chain.UTxO, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []chain.UTxO
	for _, u := range c.utxos {
		if string(u.Address.Raw) == string(a.Raw) {
			out = append(out, u)
		}
	}
	slices.SortFunc(out, func(a, b chain.UTxO) int { return a.In.Compare(b.In) })
	return out, nil
}

// Account implements datasource.Source: no account was ever registered.
func (c *Chain) Account(context.Context, string) (datasource.Account, error) {
	return datasource.Account{}, datasource.ErrNotFound
}

// Asset implements datasource.Source, through the server's Koios client.
func (c *Chain) Asset(ctx context.Context, id model.AssetID) (datasource.Asset, error) {
	return c.koios.Asset(ctx, id)
}

// AssetByFingerprint implements datasource.Source, through Koios.
func (c *Chain) AssetByFingerprint(ctx context.Context, fp string) (model.AssetID, error) {
	return c.koios.AssetByFingerprint(ctx, fp)
}

// Transaction implements datasource.Source.
func (c *Chain) Transaction(_ context.Context, id [32]byte) (datasource.Transaction, error) {
	tx, ok := c.txs[id]
	if !ok {
		return datasource.Transaction{}, datasource.ErrNotFound
	}
	return datasource.Transaction{CBOR: tx, BlockHeight: 4_999_990, BlockHash: [32]byte{0: 0xb0, 31: id[0]}, BlockTime: c.now.Add(-10 * time.Minute)}, nil
}

// Submit implements datasource.Source. E8 never reaches the network: the
// wallet is mode A and nothing is signed.
func (c *Chain) Submit(context.Context, []byte, [32]byte) error {
	return fmt.Errorf("%w: E8 sends nothing", datasource.ErrRejected)
}

// Confirmations implements datasource.Source.
func (c *Chain) Confirmations(_ context.Context, ids [][32]byte) (map[[32]byte]uint64, error) {
	out := map[[32]byte]uint64{}
	for _, id := range ids {
		out[id] = 0
	}
	return out, nil
}

// hostileTx builds a Conway transaction from a stranger to the wallet, with
// the tokens and, if not nil, the metadata. It returns its id and bytes.
func hostileTx(n byte, wallet model.Address, tokens map[model.AssetID]uint64, metadata map[uint64]any) ([32]byte, []byte, error) {
	c, err := cborx.New(cborx.Limits{MaxDepth: 64, MaxArrayElements: 1 << 16, MaxMapPairs: 1 << 16, AllowTags: true})
	if err != nil {
		return [32]byte{}, nil, err
	}
	ma := map[cborx.ByteString]map[cborx.ByteString]uint64{}
	for a, q := range tokens {
		p := cborx.ByteString(a.Policy[:])
		if ma[p] == nil {
			ma[p] = map[cborx.ByteString]uint64{}
		}
		ma[p][cborx.ByteString(a.Name)] = q
	}
	stranger := [32]byte{0: 0xa7, 31: n}
	body := map[uint64]any{
		0: cborx.Tag{Number: 258, Content: []any{[]any{stranger[:], uint64(0)}}},
		1: []any{[]any{wallet.Raw, []any{uint64(1_500_000 + 50_000*len(tokens)), ma}}},
		2: uint64(250_000),
	}
	var aux []byte
	if metadata != nil {
		if aux, err = c.Marshal(metadata); err != nil {
			return [32]byte{}, nil, err
		}
		h := blake2b.Sum256(aux)
		body[7] = h[:]
	}
	b, err := c.Marshal(body)
	if err != nil {
		return [32]byte{}, nil, err
	}
	var auxValue any = nil
	if aux != nil {
		auxValue = cborx.Raw(aux)
	}
	tx, err := c.Marshal([]any{cborx.Raw(b), map[uint64]any{}, true, auxValue})
	if err != nil {
		return [32]byte{}, nil, err
	}
	return blake2b.Sum256(b), tx, nil
}

// cip68ID returns the CIP-68 NFT that carries p in its reference datum.
func (p Payload) cip68ID(policy [28]byte) model.AssetID {
	id, err := model.NewAssetID(policy[:], []byte(cip68User+cut(p.Name, 28)))
	if err != nil {
		panic(fmt.Sprintf("%s: %v", p.ref(), err))
	}
	return id
}

// ref names p where it needs a label: its canary, or, without one, a hash
// of its text.
func (p Payload) ref() string {
	if p.ID != "" {
		return p.ID
	}
	return hex.EncodeToString(digest(p.Text, 4))
}

// metadata is what a stranger writes in the transaction: the payload as a
// CIP-20 message, under another label as text and bytes, and, for floods,
// a deep tree and a wide list.
func (p Payload) metadata() map[uint64]any {
	note := map[string]any{"note": toAny(lines(p.Text)), "bytes": cborx.ByteString(p.Name)}
	if p.Kind == "flood" {
		var deep any = p.ref() + " bottom"
		for range 12 {
			deep = map[string]any{p.ref(): deep}
		}
		note["deep"] = deep
		wide := make([]any, 300)
		for i := range wide {
			wide[i] = fmt.Sprintf("%s item %d", p.ref(), i)
		}
		note["wide"] = wide
	}
	return map[uint64]any{674: map[string]any{"msg": toAny(lines(p.Text))}, 1337: note}
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, x := range s {
		out[i] = x
	}
	return out
}

// cip25Row is the asset_info row of p's CIP-25 token: the payload in its
// name, description and attributes, as Koios renders label 721.
func (p Payload) cip25Row(id model.AssetID) map[string]any {
	key := id.Name
	if !utf8.ValidString(key) {
		key = hex.EncodeToString([]byte(id.Name))
	}
	entry := map[string]any{
		"name": p.Text, "description": p.Text, "image": "ipfs://Qm" + hex.EncodeToString(digest(p.Text, 22)),
		"attributes": map[string]any{p.Text: p.Text},
		"files":      []any{map[string]any{"name": p.Text, "src": "https://claim-ada.example/" + p.ref(), "mediaType": "text/html"}},
	}
	if p.Kind == "flood" {
		entry["description"] = strings.Repeat(p.Text, 3)
		var deep any = p.ref()
		for range 12 {
			deep = []any{deep}
		}
		entry["deep"] = deep
	}
	md := map[string]any{"721": map[string]any{hex.EncodeToString(id.Policy[:]): map[string]any{key: entry}, "version": "1.0"}}
	return map[string]any{
		"policy_id": hex.EncodeToString(id.Policy[:]), "asset_name": hex.EncodeToString([]byte(id.Name)),
		"total_supply": "1", "minting_tx_metadata": md, "cip68_metadata": nil,
	}
}

// cip68Row is the asset_info row of p's CIP-68 NFT: the payload in the keys
// and values of its reference datum, as Koios renders it in detailed JSON.
func (p Payload) cip68Row(id model.AssetID) map[string]any {
	b := func(s string) map[string]any { return map[string]any{"bytes": hex.EncodeToString([]byte(s))} }
	fields := []any{
		map[string]any{"k": b("name"), "v": b(p.Text)},
		map[string]any{"k": b("description"), "v": b(p.Text)},
		map[string]any{"k": b(cut(p.Text, 40)), "v": map[string]any{"int": 1}},
		map[string]any{"k": b("files"), "v": map[string]any{"list": []any{b(p.Name)}}},
	}
	datum := map[string]any{"222": map[string]any{"constructor": 0, "fields": []any{map[string]any{"map": fields}, map[string]any{"int": 1}}}}
	return map[string]any{
		"policy_id": hex.EncodeToString(id.Policy[:]), "asset_name": hex.EncodeToString([]byte(id.Name)),
		"total_supply": "1", "minting_tx_metadata": nil, "cip68_metadata": datum,
	}
}
