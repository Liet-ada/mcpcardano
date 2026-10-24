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
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// DefaultBlockfrostURL returns Blockfrost's endpoint for a network.
func DefaultBlockfrostURL(n model.Network) string {
	switch n {
	case model.Mainnet:
		return "https://cardano-mainnet.blockfrost.io/api/v0"
	case model.Preprod:
		return "https://cardano-preprod.blockfrost.io/api/v0"
	case model.Preview:
		return "https://cardano-preview.blockfrost.io/api/v0"
	}
	return ""
}

// BlockfrostConfig configures a Blockfrost client. Zero values take the
// defaults.
type BlockfrostConfig struct {
	Network model.Network
	// ProjectID is the key of a Blockfrost project for this network. It
	// goes only in the project_id header of each request, never in an
	// error, and the client does not keep it in a field that a %v could
	// print.
	ProjectID string
	// BaseURL defaults to Blockfrost's endpoint for the network. It must be
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

// Blockfrost is a minimal client of the Blockfrost API (paper, section 6.5;
// decision 136).
type Blockfrost struct {
	cfg  BlockfrostConfig
	base *url.URL
	// auth sets the project_id header. A closure, so that the key is in no
	// field of the client.
	auth func(http.Header)
}

var _ Source = (*Blockfrost)(nil)

// NewBlockfrost returns a Blockfrost client.
func NewBlockfrost(cfg BlockfrostConfig) (*Blockfrost, error) {
	if _, ok := networkMagic[cfg.Network]; !ok {
		return nil, fmt.Errorf("datasource: unknown network %q", cfg.Network)
	}
	if !projectID(cfg.ProjectID) {
		return nil, errors.New("datasource: the Blockfrost project id must be 1 to 128 letters and digits")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBlockfrostURL(cfg.Network)
	}
	base, err := baseURL("Blockfrost", cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = newHTTPClient()
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
		cfg.pageSize = 100 // the most Blockfrost returns per page
	}
	if cfg.maxUTxOs <= 0 {
		cfg.maxUTxOs = MaxUTxOs
	}
	key := cfg.ProjectID
	cfg.ProjectID = ""
	return &Blockfrost{cfg: cfg, base: base, auth: func(h http.Header) { h.Set("project_id", key) }}, nil
}

// projectID checks the shape of a Blockfrost key, so that nothing else can
// reach the request's headers.
func projectID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// Name implements Source.
func (b *Blockfrost) Name() string { return "blockfrost" }

// Network implements Source.
func (b *Blockfrost) Network() model.Network { return b.cfg.Network }

// CheckNetwork implements Source.
func (b *Blockfrost) CheckNetwork(ctx context.Context) error {
	var g struct {
		NetworkMagic *uint64 `json:"network_magic"`
	}
	if err := b.get(ctx, "/genesis", nil, &g); err != nil {
		return err
	}
	if g.NetworkMagic == nil {
		return fmt.Errorf("%w: genesis", ErrInvalidResponse)
	}
	if got, want := strconv.FormatUint(*g.NetworkMagic, 10), networkMagic[b.cfg.Network]; got != want {
		return fmt.Errorf("%w: network magic %s, want %s for %s", ErrNetworkMismatch, got, want, b.cfg.Network)
	}
	return nil
}

// Tip implements Source.
func (b *Blockfrost) Tip(ctx context.Context) (Tip, error) {
	var r struct {
		Hash   *string `json:"hash"`
		Epoch  *uint64 `json:"epoch"`
		Slot   *uint64 `json:"slot"`
		Height *uint64 `json:"height"`
		Time   *uint64 `json:"time"`
	}
	if err := b.get(ctx, "/blocks/latest", nil, &r); err != nil {
		return Tip{}, err
	}
	if r.Hash == nil || r.Epoch == nil || r.Slot == nil || r.Height == nil || r.Time == nil {
		return Tip{}, fmt.Errorf("%w: latest block is missing fields", ErrInvalidResponse)
	}
	h, err := hash32(*r.Hash)
	if err != nil {
		return Tip{}, fmt.Errorf("%w: latest block hash: %v", ErrInvalidResponse, err)
	}
	return Tip{Slot: *r.Slot, Height: *r.Height, Epoch: *r.Epoch, Hash: h, Time: time.Unix(int64(*r.Time), 0).UTC()}, nil
}

// ProtocolParameters implements Source. It reads the tip and then the
// parameters of the latest epoch, which must be the tip's.
func (b *Blockfrost) ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error) {
	tip, err := b.Tip(ctx)
	if err != nil {
		return chain.ProtocolParameters{}, err
	}
	var row map[string]json.RawMessage
	if err := b.get(ctx, "/epochs/latest/parameters", nil, &row); err != nil {
		return chain.ProtocolParameters{}, err
	}
	f := fields{row: row}
	p := chain.ProtocolParameters{
		Epoch:               f.uint("epoch", 1<<63),
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
		ProtocolMajor:       uint32(f.uint("protocol_major_ver", 1<<32-1)),
		ProtocolMinor:       uint32(f.uint("protocol_minor_ver", 1<<32-1)),
	}
	if f.err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("%w: epoch parameters: %v", ErrInvalidResponse, f.err)
	}
	switch {
	case p.Epoch == tip.Epoch:
	case p.Epoch+1 == tip.Epoch || p.Epoch == tip.Epoch+1:
		// The epoch changed between the two requests, or Blockfrost has not
		// filled in the new epoch yet.
		return chain.ProtocolParameters{}, fmt.Errorf("%w: parameters for epoch %d at a tip in epoch %d", ErrUnavailable, p.Epoch, tip.Epoch)
	default:
		return chain.ProtocolParameters{}, fmt.Errorf("%w: parameters for epoch %d, asked for %d", ErrInvalidResponse, p.Epoch, tip.Epoch)
	}
	if err := p.Validate(); err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	return p, nil
}

type blockfrostUTxO struct {
	Address     *string           `json:"address"`
	TxHash      *string           `json:"tx_hash"`
	OutputIndex *uint64           `json:"output_index"`
	Amount      []blockfrostValue `json:"amount"`
	DataHash    json.RawMessage   `json:"data_hash"`
	InlineDatum json.RawMessage   `json:"inline_datum"`
	ScriptHash  json.RawMessage   `json:"reference_script_hash"`
}

type blockfrostValue struct {
	Unit     *string `json:"unit"`
	Quantity *string `json:"quantity"`
}

// UTxOs implements Source. It pages through the address's UTxOs and checks
// every row against the address that was asked for. Blockfrost answers 404
// for an address the chain has never seen, which has none.
func (b *Blockfrost) UTxOs(ctx context.Context, addr model.Address) ([]chain.UTxO, error) {
	if addr.NetworkID != b.cfg.Network.AddressID() {
		return nil, fmt.Errorf("%w: address of network id %d", ErrNetworkMismatch, addr.NetworkID)
	}
	bech, err := chain.FormatAddress(addr)
	if err != nil {
		return nil, err
	}
	var out []chain.UTxO
	seen := make(map[chain.TxIn]bool)
	for page := 1; ; page++ {
		q := url.Values{"page": {strconv.Itoa(page)}, "count": {strconv.Itoa(b.cfg.pageSize)}, "order": {"asc"}}
		var rows []blockfrostUTxO
		err := b.call(ctx, "/addresses/"+bech+"/utxos", q, &rows)
		switch {
		case errors.Is(err, ErrNotFound) && page == 1:
			return nil, nil
		case errors.Is(err, ErrNotFound):
			return nil, fmt.Errorf("%w: page %d of the UTxOs is gone", ErrInvalidResponse, page)
		case err != nil:
			return nil, err
		}
		for i, row := range rows {
			u, err := parseBlockfrostUTxO(row, bech, addr)
			if err != nil {
				return nil, fmt.Errorf("%w: utxo %d: %v", ErrInvalidResponse, (page-1)*b.cfg.pageSize+i, err)
			}
			if seen[u.In] {
				return nil, fmt.Errorf("%w: utxo %s listed twice", ErrInvalidResponse, u.In)
			}
			seen[u.In] = true
			out = append(out, u)
		}
		if len(out) > b.cfg.maxUTxOs {
			return nil, fmt.Errorf("%w: more than %d", ErrTooManyUTxOs, b.cfg.maxUTxOs)
		}
		if len(rows) < b.cfg.pageSize {
			break
		}
	}
	slices.SortFunc(out, func(x, y chain.UTxO) int { return x.In.Compare(y.In) })
	return out, nil
}

func parseBlockfrostUTxO(r blockfrostUTxO, bech string, addr model.Address) (u chain.UTxO, err error) {
	if r.Address == nil || r.TxHash == nil || r.OutputIndex == nil || r.Amount == nil {
		return u, errors.New("missing fields")
	}
	if *r.Address != bech {
		return u, fmt.Errorf("address %q was not asked for", *r.Address)
	}
	if u.In.TxID, err = hash32(*r.TxHash); err != nil {
		return u, err
	}
	if *r.OutputIndex > 65535 {
		return u, fmt.Errorf("output index %d", *r.OutputIndex)
	}
	u.In.Index = uint32(*r.OutputIndex)
	u.Address = addr
	lovelace := false
	for _, a := range r.Amount {
		if a.Unit == nil || a.Quantity == nil {
			return u, errors.New("amount is missing fields")
		}
		q, err := model.ParseAmount(*a.Quantity)
		if err != nil {
			return u, fmt.Errorf("%s quantity %q", *a.Unit, *a.Quantity)
		}
		if *a.Unit == "lovelace" {
			if lovelace {
				return u, errors.New("lovelace listed twice")
			}
			lovelace, u.Value.Lovelace = true, q
			continue
		}
		id, err := unitAsset(*a.Unit)
		if err != nil {
			return u, err
		}
		if q == 0 {
			return u, fmt.Errorf("asset %s quantity 0", id)
		}
		if u.Value.Assets == nil {
			u.Value.Assets = make(map[model.AssetID]uint64)
		}
		if _, dup := u.Value.Assets[id]; dup {
			return u, fmt.Errorf("asset %s listed twice", id)
		}
		u.Value.Assets[id] = q
	}
	if !lovelace {
		return u, errors.New("no lovelace")
	}
	u.HasDatum = present(r.DataHash) || present(r.InlineDatum)
	u.HasScript = present(r.ScriptHash)
	return u, nil
}

// unitAsset reads a Blockfrost unit: the policy id and the name, both in hex
// and back to back.
func unitAsset(unit string) (model.AssetID, error) {
	if len(unit) < 56 {
		return model.AssetID{}, fmt.Errorf("unit %q", unit)
	}
	id, err := model.ParseAssetID(unit[:56] + "." + unit[56:])
	if err != nil {
		return model.AssetID{}, fmt.Errorf("unit %q", unit)
	}
	return id, nil
}

// get reads a resource that always exists, such as the latest block: a 404
// means the source is not answering as it should.
func (b *Blockfrost) get(ctx context.Context, path string, q url.Values, out any) error {
	err := b.call(ctx, path, q, out)
	if errors.Is(err, ErrNotFound) {
		return fmt.Errorf("%w: HTTP 404 for %s", ErrUnavailable, path)
	}
	return err
}

// call sends one GET request, retrying network errors, rate limits and
// server errors with a growing pause (section 9.6), and decodes the JSON
// answer. A 404 is ErrNotFound: the resource, such as a transaction, does
// not exist.
func (b *Blockfrost) call(ctx context.Context, path string, q url.Values, out any) error {
	u := *b.base
	u.Path += path
	u.RawQuery = q.Encode()
	var last error
	for attempt := 0; attempt < b.cfg.Attempts; attempt++ {
		if attempt > 0 {
			if err := b.cfg.sleep(ctx, time.Duration(250<<(attempt-1))*time.Millisecond); err != nil {
				return fmt.Errorf("%w: %w", ErrUnavailable, err)
			}
		}
		data, retry, err := b.once(ctx, u.String())
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

// once performs a single GET. retry says whether trying again may help.
func (b *Blockfrost) once(ctx context.Context, target string) (data []byte, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mcpcardano")
	b.auth(req.Header)
	resp, err := b.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if err := blockfrostStatus(resp.StatusCode); err != nil {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, err
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, b.cfg.MaxResponseBytes+1))
	if err != nil {
		return nil, true, fmt.Errorf("%w: reading the answer: %v", ErrUnavailable, err)
	}
	if int64(len(data)) > b.cfg.MaxResponseBytes {
		return nil, false, fmt.Errorf("%w: answer larger than %d bytes", ErrInvalidResponse, b.cfg.MaxResponseBytes)
	}
	return data, false, nil
}

// blockfrostStatus reads the status codes of Blockfrost's documentation.
func blockfrostStatus(code int) error {
	switch code {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusForbidden:
		return fmt.Errorf("%w: Blockfrost refuses the project id (HTTP 403): it is not valid, or it is for another network", ErrUnavailable)
	case http.StatusPaymentRequired:
		return fmt.Errorf("%w: the Blockfrost project used up its daily requests (HTTP 402)", ErrUnavailable)
	case http.StatusTeapot:
		return fmt.Errorf("%w: Blockfrost banned this client for a while after too many requests (HTTP 418)", ErrUnavailable)
	case http.StatusTooEarly:
		return fmt.Errorf("%w: Blockfrost's mempool is full (HTTP 425)", ErrUnavailable)
	}
	return fmt.Errorf("%w: HTTP %d", ErrUnavailable, code)
}
