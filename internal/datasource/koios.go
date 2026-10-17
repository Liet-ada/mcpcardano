// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package datasource

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// DefaultKoiosURL returns the public Koios endpoint of a network.
func DefaultKoiosURL(n model.Network) string {
	switch n {
	case model.Mainnet:
		return "https://api.koios.rest/api/v1"
	case model.Preprod:
		return "https://preprod.koios.rest/api/v1"
	case model.Preview:
		return "https://preview.koios.rest/api/v1"
	}
	return ""
}

// networkMagic is the protocol magic Koios reports in /genesis.
var networkMagic = map[model.Network]string{
	model.Mainnet: "764824073",
	model.Preprod: "1",
	model.Preview: "2",
}

// KoiosConfig configures a Koios client. Zero values take the defaults.
type KoiosConfig struct {
	Network model.Network
	// BaseURL defaults to the public endpoint of the network. It must be
	// HTTPS, or plain HTTP to a loopback address for a self-hosted instance.
	BaseURL          string
	HTTPClient       *http.Client // defaults to a 15 s timeout and no redirects
	Attempts         int          // per read, including the first; defaults to 3
	MaxResponseBytes int64        // defaults to 8 MiB

	// For tests.
	sleep    func(context.Context, time.Duration) error
	pageSize int
	maxUTxOs int
}

// Koios is a minimal client of the Koios API (paper, section 6.5).
type Koios struct {
	cfg  KoiosConfig
	base *url.URL
}

var _ Source = (*Koios)(nil)

// NewKoios returns a Koios client.
func NewKoios(cfg KoiosConfig) (*Koios, error) {
	if _, ok := networkMagic[cfg.Network]; !ok {
		return nil, fmt.Errorf("datasource: unknown network %q", cfg.Network)
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultKoiosURL(cfg.Network)
	}
	base, err := url.Parse(strings.TrimSuffix(cfg.BaseURL, "/"))
	if err != nil || base.Host == "" || base.RawQuery != "" || base.User != nil {
		return nil, fmt.Errorf("datasource: invalid Koios URL %q", cfg.BaseURL)
	}
	if base.Scheme != "https" && !(base.Scheme == "http" && isLoopback(base.Hostname())) {
		return nil, fmt.Errorf("datasource: Koios URL must use HTTPS unless it is on this machine")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = 3
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 8 << 20
	}
	if cfg.sleep == nil {
		cfg.sleep = sleep
	}
	if cfg.pageSize <= 0 {
		cfg.pageSize = 1000 // the most Koios returns per request
	}
	if cfg.maxUTxOs <= 0 {
		cfg.maxUTxOs = MaxUTxOs
	}
	return &Koios{cfg: cfg, base: base}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Name implements Source.
func (k *Koios) Name() string { return "koios" }

// Network implements Source.
func (k *Koios) Network() model.Network { return k.cfg.Network }

// CheckNetwork implements Source.
func (k *Koios) CheckNetwork(ctx context.Context) error {
	var rows []struct {
		NetworkMagic *string `json:"networkmagic"`
	}
	if err := k.call(ctx, "/genesis", url.Values{"select": {"networkmagic"}}, nil, &rows); err != nil {
		return err
	}
	if len(rows) != 1 || rows[0].NetworkMagic == nil {
		return fmt.Errorf("%w: genesis", ErrInvalidResponse)
	}
	if got, want := *rows[0].NetworkMagic, networkMagic[k.cfg.Network]; got != want {
		return fmt.Errorf("%w: network magic %s, want %s for %s", ErrNetworkMismatch, got, want, k.cfg.Network)
	}
	return nil
}

// Tip implements Source.
func (k *Koios) Tip(ctx context.Context) (Tip, error) {
	var rows []struct {
		Hash   *string `json:"hash"`
		Epoch  *uint64 `json:"epoch_no"`
		Slot   *uint64 `json:"abs_slot"`
		Height *uint64 `json:"block_height"`
		Time   *uint64 `json:"block_time"`
	}
	q := url.Values{"select": {"hash,epoch_no,abs_slot,block_height,block_time"}}
	if err := k.call(ctx, "/tip", q, nil, &rows); err != nil {
		return Tip{}, err
	}
	if len(rows) != 1 {
		return Tip{}, fmt.Errorf("%w: tip has %d rows", ErrInvalidResponse, len(rows))
	}
	r := rows[0]
	if r.Hash == nil || r.Epoch == nil || r.Slot == nil || r.Height == nil || r.Time == nil {
		return Tip{}, fmt.Errorf("%w: tip is missing fields", ErrInvalidResponse)
	}
	h, err := hash32(*r.Hash)
	if err != nil {
		return Tip{}, fmt.Errorf("%w: tip hash: %v", ErrInvalidResponse, err)
	}
	return Tip{
		Slot: uint64(*r.Slot), Height: uint64(*r.Height), Epoch: uint64(*r.Epoch), Hash: h,
		Time: time.Unix(int64(*r.Time), 0).UTC(),
	}, nil
}

// paramFields are the epoch_params columns ProtocolParameters reads.
const paramFields = "epoch_no,min_fee_a,min_fee_b,max_tx_size,max_val_size,coins_per_utxo_size," +
	"key_deposit,pool_deposit,drep_deposit,gov_action_deposit,price_mem,price_step," +
	"max_tx_ex_mem,max_tx_ex_steps,collateral_percent,max_collateral_inputs," +
	"min_fee_ref_script_cost_per_byte,protocol_major,protocol_minor"

// ProtocolParameters implements Source. It reads the epoch from the tip and
// then that epoch's parameters.
func (k *Koios) ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error) {
	tip, err := k.Tip(ctx)
	if err != nil {
		return chain.ProtocolParameters{}, err
	}
	var rows []map[string]json.RawMessage
	q := url.Values{"_epoch_no": {strconv.FormatUint(tip.Epoch, 10)}, "select": {paramFields}}
	if err := k.call(ctx, "/epoch_params", q, nil, &rows); err != nil {
		return chain.ProtocolParameters{}, err
	}
	switch len(rows) {
	case 1:
	case 0:
		// Koios fills in a new epoch's row shortly after the boundary.
		return chain.ProtocolParameters{}, fmt.Errorf("%w: no parameters yet for epoch %d", ErrUnavailable, tip.Epoch)
	default:
		return chain.ProtocolParameters{}, fmt.Errorf("%w: %d rows of parameters", ErrInvalidResponse, len(rows))
	}
	f := fields{row: rows[0]}
	p := chain.ProtocolParameters{
		Epoch:               f.uint("epoch_no", 1<<63),
		MinFeeA:             f.uint("min_fee_a", 1<<63),
		MinFeeB:             f.uint("min_fee_b", 1<<63),
		MaxTxSize:           uint32(f.uint("max_tx_size", 1<<32-1)),
		MaxValueSize:        uint32(f.uint("max_val_size", 1<<32-1)),
		CoinsPerUTxOByte:    f.uint("coins_per_utxo_size", 1<<63),
		KeyDeposit:          f.uint("key_deposit", 1<<63),
		PoolDeposit:         f.uint("pool_deposit", 1<<63),
		DRepDeposit:         f.uint("drep_deposit", 1<<63),
		GovActionDeposit:    f.uint("gov_action_deposit", 1<<63),
		PriceMem:            f.rational("price_mem"),
		PriceStep:           f.rational("price_step"),
		MaxTxExMem:          f.uint("max_tx_ex_mem", 1<<63),
		MaxTxExSteps:        f.uint("max_tx_ex_steps", 1<<63),
		CollateralPercent:   uint32(f.uint("collateral_percent", 1<<32-1)),
		MaxCollateralInputs: uint32(f.uint("max_collateral_inputs", 1<<32-1)),
		MinFeeRefScriptByte: f.rational("min_fee_ref_script_cost_per_byte"),
		ProtocolMajor:       uint32(f.uint("protocol_major", 1<<32-1)),
		ProtocolMinor:       uint32(f.uint("protocol_minor", 1<<32-1)),
	}
	if f.err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("%w: epoch_params: %v", ErrInvalidResponse, f.err)
	}
	if p.Epoch != tip.Epoch {
		return chain.ProtocolParameters{}, fmt.Errorf("%w: parameters for epoch %d, asked for %d", ErrInvalidResponse, p.Epoch, tip.Epoch)
	}
	if err := p.Validate(); err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	return p, nil
}

// fields reads typed values from one JSON row and remembers the first error.
// Koios sends some integers as numbers and others as strings, so both are
// accepted.
type fields struct {
	row map[string]json.RawMessage
	err error
}

func (f *fields) text(name string) string {
	raw, ok := f.row[name]
	if !ok || string(raw) == "null" {
		f.fail(fmt.Errorf("missing %s", name))
		return ""
	}
	var s string
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &s); err != nil {
			f.fail(fmt.Errorf("%s: %v", name, err))
		}
		return s
	}
	return string(raw)
}

func (f *fields) uint(name string, max uint64) uint64 {
	s := f.text(name)
	if f.err != nil {
		return 0
	}
	n, err := model.ParseAmount(s)
	if err != nil || n > max {
		f.fail(fmt.Errorf("%s: %q is not an integer in range", name, s))
	}
	return n
}

func (f *fields) rational(name string) chain.Rational {
	s := f.text(name)
	if f.err != nil {
		return chain.Rational{}
	}
	r, err := chain.ParseDecimal(s)
	if err != nil {
		f.fail(fmt.Errorf("%s: %v", name, err))
	}
	return r
}

func (f *fields) fail(err error) {
	if f.err == nil {
		f.err = err
	}
}

// utxoFields are the address_utxos columns UTxOs reads.
const utxoFields = "tx_hash,tx_index,address,value,datum_hash,inline_datum,reference_script,asset_list,is_spent"

type koiosUTxO struct {
	TxHash          *string         `json:"tx_hash"`
	TxIndex         *uint64         `json:"tx_index"`
	Address         *string         `json:"address"`
	Value           *string         `json:"value"`
	DatumHash       json.RawMessage `json:"datum_hash"`
	InlineDatum     json.RawMessage `json:"inline_datum"`
	ReferenceScript json.RawMessage `json:"reference_script"`
	AssetList       []koiosAsset    `json:"asset_list"`
	IsSpent         *bool           `json:"is_spent"`
}

type koiosAsset struct {
	PolicyID  *string `json:"policy_id"`
	AssetName *string `json:"asset_name"`
	Quantity  *string `json:"quantity"`
}

// UTxOs implements Source. It pages through the address's UTxOs in a fixed
// order and checks every row against the address that was asked for.
func (k *Koios) UTxOs(ctx context.Context, addr model.Address) ([]chain.UTxO, error) {
	if addr.NetworkID != k.cfg.Network.AddressID() {
		return nil, fmt.Errorf("%w: address of network id %d", ErrNetworkMismatch, addr.NetworkID)
	}
	bech, err := chain.FormatAddress(addr)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"_addresses": []string{bech}, "_extended": true}
	var out []chain.UTxO
	seen := make(map[chain.TxIn]bool)
	for offset := 0; ; offset += k.cfg.pageSize {
		q := url.Values{
			"select": {utxoFields},
			"order":  {"tx_hash.asc,tx_index.asc"},
			"offset": {strconv.Itoa(offset)},
			"limit":  {strconv.Itoa(k.cfg.pageSize)},
		}
		var page []koiosUTxO
		if err := k.call(ctx, "/address_utxos", q, body, &page); err != nil {
			return nil, err
		}
		for i, row := range page {
			u, spent, err := parseUTxO(row, bech, addr)
			if err != nil {
				return nil, fmt.Errorf("%w: utxo %d: %v", ErrInvalidResponse, offset+i, err)
			}
			if spent {
				continue
			}
			if seen[u.In] {
				return nil, fmt.Errorf("%w: utxo %s listed twice", ErrInvalidResponse, u.In)
			}
			seen[u.In] = true
			out = append(out, u)
		}
		if len(out) > k.cfg.maxUTxOs {
			return nil, fmt.Errorf("%w: more than %d", ErrTooManyUTxOs, k.cfg.maxUTxOs)
		}
		if len(page) < k.cfg.pageSize {
			break
		}
	}
	slices.SortFunc(out, func(a, b chain.UTxO) int { return a.In.Compare(b.In) })
	return out, nil
}

func parseUTxO(r koiosUTxO, bech string, addr model.Address) (u chain.UTxO, spent bool, err error) {
	if r.TxHash == nil || r.TxIndex == nil || r.Address == nil || r.Value == nil || r.IsSpent == nil {
		return u, false, errors.New("missing fields")
	}
	if *r.Address != bech {
		return u, false, fmt.Errorf("address %q was not asked for", *r.Address)
	}
	if u.In.TxID, err = hash32(*r.TxHash); err != nil {
		return u, false, err
	}
	if *r.TxIndex > 65535 {
		return u, false, fmt.Errorf("output index %d", *r.TxIndex)
	}
	u.In.Index = uint32(*r.TxIndex)
	u.Address = addr
	if u.Value.Lovelace, err = model.ParseAmount(*r.Value); err != nil {
		return u, false, fmt.Errorf("value %q", *r.Value)
	}
	for _, a := range r.AssetList {
		if a.PolicyID == nil || a.AssetName == nil || a.Quantity == nil {
			return u, false, errors.New("asset is missing fields")
		}
		id, err := model.ParseAssetID(*a.PolicyID + "." + *a.AssetName)
		if err != nil {
			return u, false, fmt.Errorf("asset %q.%q", *a.PolicyID, *a.AssetName)
		}
		q, err := model.ParseAmount(*a.Quantity)
		if err != nil || q == 0 {
			return u, false, fmt.Errorf("asset %s quantity %q", id, *a.Quantity)
		}
		if u.Value.Assets == nil {
			u.Value.Assets = make(map[model.AssetID]uint64)
		}
		if _, dup := u.Value.Assets[id]; dup {
			return u, false, fmt.Errorf("asset %s listed twice", id)
		}
		u.Value.Assets[id] = q
	}
	u.HasDatum = present(r.DatumHash) || present(r.InlineDatum)
	u.HasScript = present(r.ReferenceScript)
	return u, *r.IsSpent, nil
}

func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

func hash32(s string) ([32]byte, error) {
	var h [32]byte
	if len(s) != 64 || strings.ToLower(s) != s {
		return h, fmt.Errorf("hash %q", s)
	}
	if _, err := hex.Decode(h[:], []byte(s)); err != nil {
		return h, fmt.Errorf("hash %q", s)
	}
	return h, nil
}

// call sends one request, retrying network errors, rate limits and server
// errors with a growing pause (section 9.6), and decodes the JSON answer.
// Every Koios call it makes is a read, so retrying is safe.
func (k *Koios) call(ctx context.Context, path string, q url.Values, body, out any) error {
	u := *k.base
	u.Path += path
	u.RawQuery = q.Encode()
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	var last error
	for attempt := 0; attempt < k.cfg.Attempts; attempt++ {
		if attempt > 0 {
			if err := k.cfg.sleep(ctx, time.Duration(250<<(attempt-1))*time.Millisecond); err != nil {
				return fmt.Errorf("%w: %w", ErrUnavailable, err)
			}
		}
		data, retry, err := k.once(ctx, u.String(), payload)
		if err == nil {
			if err := json.Unmarshal(data, out); err != nil {
				return fmt.Errorf("%w: %s: %v", ErrInvalidResponse, path, err)
			}
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("%w: %w", ErrUnavailable, ctx.Err())
		}
		if !retry {
			return err
		}
		last = err
	}
	return last
}

// once performs a single HTTP exchange. retry says whether trying again may
// help.
func (k *Koios) once(ctx context.Context, target string, payload []byte) (data []byte, retry bool, err error) {
	method := http.MethodGet
	var rd io.Reader
	if payload != nil {
		method, rd = http.MethodPost, bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mcpcardano")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("%w: HTTP %d", ErrUnavailable, resp.StatusCode)
	default:
		return nil, false, fmt.Errorf("%w: HTTP %d", ErrUnavailable, resp.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, k.cfg.MaxResponseBytes+1))
	if err != nil {
		return nil, true, fmt.Errorf("%w: reading the answer: %v", ErrUnavailable, err)
	}
	if int64(len(data)) > k.cfg.MaxResponseBytes {
		return nil, false, fmt.Errorf("%w: answer larger than %d bytes", ErrInvalidResponse, k.cfg.MaxResponseBytes)
	}
	return data, false, nil
}
