// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ipc

import (
	"bytes"
	"slices"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The types in this file appear in messages of both sockets. Each has a fixed
// field set and, where it holds a list, a fixed order, so that it has a
// single encoding.

// Sizes of the fields that hold hashes and keys.
const (
	HashSize      = 32 // transaction ids and body hashes
	VKeySize      = 32
	SignatureSize = 64
)

// Bounds of the variable fields.
const (
	MaxLabel        = 64   // bytes of a wallet label
	MaxAddress      = 64   // bytes of a raw address; Shelley ones have at most 57
	MaxWitnesses    = 16   // per SignDraft; the MVP signs with one key
	MaxInputs       = 1024 // resolved inputs per SignDraft
	MaxSoftware     = 64   // bytes of a binary version
	MaxSecret       = 1024 // bytes of a password or a recovery phrase
	MaxSummaryLine  = 256
	MaxSummaryLines = 200
)

// Wallet is a wallet of the wallet process (section 3.2), plus whether it is
// frozen, which list_wallets shows.
type Wallet struct {
	ID        string `cbor:"id"`
	Label     string `cbor:"label"`
	Network   string `cbor:"network"`
	Mode      string `cbor:"mode"`
	Address   []byte `cbor:"address"`
	CreatedBy string `cbor:"created_by"`
	Frozen    bool   `cbor:"frozen"`
}

// WalletFrom converts a model wallet.
func WalletFrom(w model.Wallet, frozen bool) Wallet {
	return Wallet{
		ID: string(w.ID), Label: w.Label, Network: string(w.Network), Mode: string(w.Mode),
		Address: w.Address.Raw, CreatedBy: string(w.CreatedBy), Frozen: frozen,
	}
}

// Model converts w back. Only the raw address is filled in; whoever needs its
// parts decodes it.
func (w Wallet) Model() model.Wallet {
	return model.Wallet{
		ID: model.WalletID(w.ID), Label: w.Label, Network: model.Network(w.Network), Mode: model.Mode(w.Mode),
		Address: model.Address{Raw: w.Address}, CreatedBy: model.CreatedBy(w.CreatedBy),
	}
}

// Validate implements Body.
func (w *Wallet) Validate() error {
	switch {
	case model.WalletID(w.ID).Validate() != nil:
		return malformed("wallet id")
	case !text(w.Label, MaxLabel):
		return malformed("wallet label")
	case !model.Network(w.Network).Valid():
		return malformed("wallet network")
	case !walletMode(w.Mode):
		return malformed("wallet mode")
	case !address(w.Address):
		return malformed("wallet address")
	case w.CreatedBy != string(model.ByPerson) && w.CreatedBy != string(model.ByAgent):
		return malformed("wallet created_by")
	}
	return nil
}

// walletMode reports whether m is a mode of the wallet process: B or C. Mode A
// wallets live in the server's configuration.
func walletMode(m string) bool {
	return m == string(model.ModeB) || m == string(model.ModeC)
}

func address(b []byte) bool { return len(b) > 0 && len(b) <= MaxAddress }

// Policy is a wallet's policy (section 3.6) on the wire.
type Policy struct {
	Frozen          bool         `cbor:"frozen"`
	SessionRequired bool         `cbor:"session_required"`
	Networks        []string     `cbor:"networks"` // sorted
	Limits          Limits       `cbor:"limits"`
	Destinations    Destinations `cbor:"destinations"`
	Assets          []AssetCap   `cbor:"assets"` // sorted by asset
	Structure       Structure    `cbor:"structure"`
	UTxO            UTxOPolicy   `cbor:"utxo"`
}

// Limits are the limits of a policy.
type Limits struct {
	PerTx                  uint64 `cbor:"per_tx"`
	PerHour                uint64 `cbor:"per_hour"`
	PerDay                 uint64 `cbor:"per_day"`
	Budget                 uint64 `cbor:"budget"`
	ApprovalThreshold      uint64 `cbor:"approval_threshold"`
	MaxFee                 uint64 `cbor:"max_fee"`
	TxPerHour              uint32 `cbor:"tx_per_hour"`
	NewDestinationsPerHour uint32 `cbor:"new_destinations_per_hour"`
	NewDestinationsPerDay  uint32 `cbor:"new_destinations_per_day"`
	MaxLiveDrafts          uint32 `cbor:"max_live_drafts"`
	MaxTTLSeconds          uint32 `cbor:"max_ttl_seconds"`
}

// Destinations is any address, or a list of raw addresses sorted bytewise.
type Destinations struct {
	Any     bool     `cbor:"any"`
	Allowed [][]byte `cbor:"allowed"`
}

// AssetCap is a token that may leave, with its cap in units per transaction.
type AssetCap struct {
	Policy []byte `cbor:"policy"`
	Name   []byte `cbor:"name"`
	Cap    uint64 `cbor:"cap"`
}

// Structure is what a transaction may carry beyond plain outputs.
type Structure struct {
	Certificates      bool `cbor:"certificates"`
	Withdrawals       bool `cbor:"withdrawals"`
	Mint              bool `cbor:"mint"`
	InternalTransfers bool `cbor:"internal_transfers"`
}

// UTxOPolicy steers change and input selection.
type UTxOPolicy struct {
	TargetADAOnly uint32 `cbor:"target_ada_only"`
	MinSplit      uint64 `cbor:"min_split"`
	DustThreshold uint64 `cbor:"dust_threshold"`
	MaxDustSweep  uint32 `cbor:"max_dust_sweep"`
}

// PolicyFrom converts a model policy, putting its lists in their wire order.
func PolicyFrom(p model.Policy) Policy {
	w := Policy{
		Frozen:          p.Frozen,
		SessionRequired: p.SessionRequired,
		Networks:        []string{},
		Limits:          Limits(p.Limits),
		Destinations:    Destinations{Any: p.Destinations.Any, Allowed: [][]byte{}},
		Assets:          []AssetCap{},
		Structure:       Structure(p.Structure),
		UTxO:            UTxOPolicy(p.UTxO),
	}
	for _, n := range p.Networks {
		w.Networks = append(w.Networks, string(n))
	}
	slices.Sort(w.Networks)
	for _, a := range p.Destinations.Allowed {
		w.Destinations.Allowed = append(w.Destinations.Allowed, a.Raw)
	}
	slices.SortFunc(w.Destinations.Allowed, bytes.Compare)
	ids := make([]model.AssetID, 0, len(p.Assets))
	for a := range p.Assets {
		ids = append(ids, a)
	}
	slices.SortFunc(ids, model.AssetID.Compare)
	for _, a := range ids {
		w.Assets = append(w.Assets, AssetCap{Policy: a.Policy[:], Name: []byte(a.Name), Cap: p.Assets[a]})
	}
	return w
}

// Model converts p back. It expects a validated policy.
func (p Policy) Model() model.Policy {
	m := model.Policy{
		Frozen:          p.Frozen,
		SessionRequired: p.SessionRequired,
		Limits:          model.Limits(p.Limits),
		Destinations:    model.Destinations{Any: p.Destinations.Any},
		Assets:          make(map[model.AssetID]uint64, len(p.Assets)),
		Structure:       model.Structure(p.Structure),
		UTxO:            model.UTxOPolicy(p.UTxO),
	}
	for _, n := range p.Networks {
		m.Networks = append(m.Networks, model.Network(n))
	}
	for _, a := range p.Destinations.Allowed {
		m.Destinations.Allowed = append(m.Destinations.Allowed, model.Address{Raw: a})
	}
	for _, a := range p.Assets {
		id, _ := model.NewAssetID(a.Policy, a.Name)
		m.Assets[id] = a.Cap
	}
	return m
}

// Validate implements Body.
func (p *Policy) Validate() error {
	for i, n := range p.Networks {
		if !model.Network(n).Valid() || (i > 0 && p.Networks[i-1] >= n) {
			return malformed("policy networks: unknown, repeated or out of order")
		}
	}
	if p.Destinations.Any && len(p.Destinations.Allowed) > 0 {
		return malformed("policy destinations: any with a list")
	}
	for i, a := range p.Destinations.Allowed {
		if !address(a) || (i > 0 && bytes.Compare(p.Destinations.Allowed[i-1], a) >= 0) {
			return malformed("policy destinations: invalid, repeated or out of order")
		}
	}
	for i, a := range p.Assets {
		if err := asset(a.Policy, a.Name); err != nil {
			return err
		}
		if i > 0 && assetOrder(p.Assets[i-1].Policy, p.Assets[i-1].Name, a.Policy, a.Name) >= 0 {
			return malformed("policy assets: repeated or out of order")
		}
	}
	return nil
}

// Template is the policy and mode given to the wallets the agent creates
// (section 3.7).
type Template struct {
	Mode   string `cbor:"mode"`
	Policy Policy `cbor:"policy"`
}

// Validate implements Body.
func (t *Template) Validate() error {
	if !walletMode(t.Mode) {
		return malformed("template mode")
	}
	return t.Policy.Validate()
}

func asset(policy, name []byte) error {
	if len(policy) != model.PolicyIDSize || len(name) > model.MaxAssetNameSize {
		return malformed("asset id")
	}
	return nil
}

// assetOrder orders assets by policy and then by name, as model.AssetID does.
func assetOrder(p1, n1, p2, n2 []byte) int {
	if c := bytes.Compare(p1, p2); c != 0 {
		return c
	}
	return bytes.Compare(n1, n2)
}

// Spend is what the wallet counts as spent by a transaction (section 8.5):
// lovelace, and units of each token that leaves, sorted by asset.
type Spend struct {
	Lovelace uint64        `cbor:"lovelace"`
	Assets   []AssetAmount `cbor:"assets,omitempty"`
}

// AssetAmount is a positive quantity of a token.
type AssetAmount struct {
	Policy   []byte `cbor:"policy"`
	Name     []byte `cbor:"name"`
	Quantity uint64 `cbor:"quantity"`
}

// SpendFrom converts a value, leaving out zero quantities.
func SpendFrom(v model.Value) Spend {
	s := Spend{Lovelace: v.Lovelace}
	ids := make([]model.AssetID, 0, len(v.Assets))
	for a, q := range v.Assets {
		if q != 0 {
			ids = append(ids, a)
		}
	}
	slices.SortFunc(ids, model.AssetID.Compare)
	for _, a := range ids {
		s.Assets = append(s.Assets, AssetAmount{Policy: a.Policy[:], Name: []byte(a.Name), Quantity: v.Assets[a]})
	}
	return s
}

// Value converts s back. It expects a validated spend.
func (s Spend) Value() model.Value {
	v := model.Value{Lovelace: s.Lovelace}
	if len(s.Assets) > 0 {
		v.Assets = make(map[model.AssetID]uint64, len(s.Assets))
	}
	for _, a := range s.Assets {
		id, _ := model.NewAssetID(a.Policy, a.Name)
		v.Assets[id] = a.Quantity
	}
	return v
}

// Validate implements Body.
func (s *Spend) Validate() error {
	for i, a := range s.Assets {
		if err := asset(a.Policy, a.Name); err != nil {
			return err
		}
		if a.Quantity == 0 {
			return malformed("spend: zero quantity")
		}
		if i > 0 && assetOrder(s.Assets[i-1].Policy, s.Assets[i-1].Name, a.Policy, a.Name) >= 0 {
			return malformed("spend assets: repeated or out of order")
		}
	}
	return nil
}

// Witness is a key witness: the verification key and its signature of the
// transaction id.
type Witness struct {
	VKey      []byte `cbor:"vkey"`
	Signature []byte `cbor:"signature"`
}

func witnesses(ws []Witness) error {
	if len(ws) == 0 || len(ws) > MaxWitnesses {
		return malformed("1 to %d witnesses", MaxWitnesses)
	}
	for _, w := range ws {
		if len(w.VKey) != VKeySize || len(w.Signature) != SignatureSize {
			return malformed("witness sizes")
		}
	}
	return nil
}

// ResolvedInput is an input of a transaction with the output it spends,
// as the server sees it. The wallet only shows it, marked as the server's
// word (section 5.3).
type ResolvedInput struct {
	TxID   []byte `cbor:"tx_id"`
	Index  uint64 `cbor:"index"`
	Output []byte `cbor:"output"` // the output's CBOR
}

func (r ResolvedInput) validate() error {
	if len(r.TxID) != HashSize || r.Index > 0xffff || len(r.Output) == 0 || len(r.Output) > MaxTxSize {
		return malformed("resolved input")
	}
	return nil
}

func hash(b []byte, what string) error {
	if len(b) != HashSize {
		return malformed("%s has %d bytes, want %d", what, len(b), HashSize)
	}
	return nil
}

func walletID(s string) error {
	if model.WalletID(s).Validate() != nil {
		return malformed("wallet id")
	}
	return nil
}

func approvalID(s string) error {
	if model.ApprovalID(s).Validate() != nil {
		return malformed("approval id")
	}
	return nil
}

func secret(s model.Secret, what string) error {
	if len(s) == 0 || len(s) > MaxSecret {
		return malformed("%s: 1 to %d bytes", what, MaxSecret)
	}
	return nil
}

func summary(lines []string) error {
	if len(lines) == 0 || len(lines) > MaxSummaryLines {
		return malformed("summary: 1 to %d lines", MaxSummaryLines)
	}
	for n, l := range lines {
		if !text(l, MaxSummaryLine) {
			return malformed("summary line %d", n)
		}
	}
	return nil
}

func oneOf(s, what string, allowed ...string) error {
	if !slices.Contains(allowed, s) {
		return malformed("unknown %s", what)
	}
	return nil
}
