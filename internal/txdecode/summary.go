// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package txdecode

import (
	"encoding/hex"
	"maps"
	"math/big"
	"slices"
	"strconv"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/sanitize"
)

// Length limits for text from the chain (paper, section 7.1). On the chain a
// name holds at most 32 bytes and a metadata string at most 64, and each
// neutralized byte may become three, so these limits cut only text that the
// ledger would not have accepted.
const (
	MaxNameBytes        = 96
	MaxMessageLineBytes = 192
	MaxMessageLines     = 16
)

// Summary is what the agent and the person read about a transaction
// (section 4.4). Amounts are decimal strings (section 4.1); net effect and
// mint quantities carry a sign. Text from the chain is neutralized and sits
// in fields ending in _unverified. Fields the MVP never builds are shown only
// when present, so nothing in the body goes unseen.
type Summary struct {
	TxID              string   `json:"tx_id"`
	Inputs            int      `json:"inputs"`
	Outputs           []Output `json:"outputs"`
	Fee               string   `json:"fee"`
	NetEffect         *Effect  `json:"net_effect,omitempty"`
	TTLSlot           string   `json:"ttl_slot,omitempty"`
	ValidityStartSlot string   `json:"validity_start_slot,omitempty"`

	Certificates      []string     `json:"certificates,omitempty"`
	Withdrawals       []Withdrawal `json:"withdrawals,omitempty"`
	Mint              []Asset      `json:"mint,omitempty"`
	MessageUnverified []string     `json:"message_unverified,omitempty"`
	MetadataLabels    []string     `json:"metadata_labels,omitempty"`

	NetworkID        *uint8   `json:"network_id,omitempty"`
	CollateralInputs int      `json:"collateral_inputs,omitempty"`
	CollateralReturn bool     `json:"collateral_return,omitempty"`
	TotalCollateral  string   `json:"total_collateral,omitempty"`
	ReferenceInputs  int      `json:"reference_inputs,omitempty"`
	RequiredSigners  []string `json:"required_signers,omitempty"`
	ScriptData       bool     `json:"script_data,omitempty"`
	Votes            int      `json:"votes,omitempty"`
	Proposals        int      `json:"proposals,omitempty"`
	Donation         string   `json:"donation,omitempty"`
}

// Output is one output of the summary. Own is present only when the summary
// was made for a wallet.
type Output struct {
	Address         string  `json:"address"`
	Own             *bool   `json:"own,omitempty"`
	Lovelace        string  `json:"lovelace"`
	Assets          []Asset `json:"assets,omitempty"`
	Datum           bool    `json:"datum,omitempty"`
	ReferenceScript bool    `json:"reference_script,omitempty"`
}

// Asset is a quantity of a token. The asset id and the CIP-14 fingerprint
// identify it; the name is only a label anyone can copy (paper, section 7.2).
type Asset struct {
	Asset          string `json:"asset"`
	Fingerprint    string `json:"fingerprint"`
	NameUnverified string `json:"name_unverified,omitempty"`
	Quantity       string `json:"quantity"`
}

// Effect is the net change of a wallet's holdings: what the transaction
// leaves at the wallet's address minus what it takes from it.
type Effect struct {
	Lovelace string  `json:"lovelace"`
	Assets   []Asset `json:"assets,omitempty"`
}

// Withdrawal is a reward withdrawal.
type Withdrawal struct {
	Account  string `json:"account"`
	Lovelace string `json:"lovelace"`
}

// Options say what the summary knows besides the transaction.
type Options struct {
	// Wallet marks the outputs that are own. Nil when there is no wallet,
	// as in decode_transaction.
	Wallet *model.Address
	// Spent are the outputs the inputs consume. With a wallet and every
	// input among them, the summary has a net effect.
	Spent []chain.UTxO
}

// Summary describes the transaction.
func (t *Tx) Summary(o Options) (Summary, error) {
	d, v := t.d, t.d.View
	s := Summary{
		TxID:             hex.EncodeToString(d.ID[:]),
		Inputs:           len(d.Inputs),
		Fee:              model.FormatAmount(v.Fee),
		NetworkID:        v.NetworkID,
		CollateralInputs: v.Collateral,
		CollateralReturn: v.CollateralReturn,
		ReferenceInputs:  v.ReferenceInputs,
		ScriptData:       v.ScriptDataHash,
		Votes:            v.Votes,
		Proposals:        v.Proposals,
	}
	if v.TTL != nil {
		s.TTLSlot = model.FormatAmount(*v.TTL)
	}
	if v.ValidityStart != nil {
		s.ValidityStartSlot = model.FormatAmount(*v.ValidityStart)
	}
	if v.TotalCollateral != nil {
		s.TotalCollateral = model.FormatAmount(*v.TotalCollateral)
	}
	if v.Donation != 0 {
		s.Donation = model.FormatAmount(v.Donation)
	}
	for _, h := range v.RequiredSigners {
		s.RequiredSigners = append(s.RequiredSigners, hex.EncodeToString(h[:]))
	}

	for _, out := range v.Outputs {
		addr, err := chain.AddressText(out.Address)
		if err != nil {
			return Summary{}, err
		}
		so := Output{
			Address:         addr,
			Lovelace:        model.FormatAmount(out.Value.Lovelace),
			Assets:          assets(out.Value.Assets, model.FormatAmount),
			Datum:           out.HasDatum,
			ReferenceScript: out.HasScript,
		}
		if o.Wallet != nil {
			own := out.Address.Equal(*o.Wallet)
			so.Own = &own
		}
		s.Outputs = append(s.Outputs, so)
	}

	for _, c := range v.Certificates {
		s.Certificates = append(s.Certificates, c.Kind)
	}
	for i, w := range v.Withdrawals {
		s.Withdrawals = append(s.Withdrawals, Withdrawal{Account: d.Accounts[i], Lovelace: model.FormatAmount(w.Amount)})
	}
	s.Mint = assets(v.Mint, func(q int64) string { return strconv.FormatInt(q, 10) })

	for _, l := range d.MetadataLabels {
		s.MetadataLabels = append(s.MetadataLabels, strconv.FormatUint(l, 10))
	}
	s.MessageUnverified = message(d.Message)

	if o.Wallet != nil {
		s.NetEffect = netEffect(d, *o.Wallet, o.Spent)
	}
	return s, nil
}

// assets lists a token map in the fixed order of section 8.2.
func assets[Q uint64 | int64](m map[model.AssetID]Q, format func(Q) string) []Asset {
	ids := slices.SortedFunc(maps.Keys(m), model.AssetID.Compare)
	var out []Asset
	for _, id := range ids {
		if m[id] == 0 {
			continue
		}
		out = append(out, asset(id, format(m[id])))
	}
	return out
}

func asset(id model.AssetID, quantity string) Asset {
	return Asset{
		Asset:          id.String(),
		Fingerprint:    chain.Fingerprint(id),
		NameUnverified: sanitize.Name([]byte(id.Name), MaxNameBytes),
		Quantity:       quantity,
	}
}

// message neutralizes the strings of a CIP-20 message and keeps at most
// MaxMessageLines of them; an ellipsis line says there were more.
func message(lines []string) []string {
	if len(lines) == 0 {
		return nil
	}
	n := min(len(lines), MaxMessageLines)
	out := make([]string, 0, n+1)
	for _, l := range lines[:n] {
		out = append(out, sanitize.Text(l, MaxMessageLineBytes))
	}
	if len(lines) > n {
		out = append(out, sanitize.Ellipsis)
	}
	return out
}

// netEffect is what the outputs leave at the wallet's address minus what the
// inputs take from it. It is nil unless every input is among spent.
func netEffect(d *chain.DecodedTx, wallet model.Address, spent []chain.UTxO) *Effect {
	if len(d.Inputs) == 0 {
		return nil
	}
	byIn := make(map[chain.TxIn]chain.UTxO, len(spent))
	for _, u := range spent {
		byIn[u.In] = u
	}
	lovelace := new(big.Int)
	tokens := map[model.AssetID]*big.Int{}
	add := func(v model.Value, sign int64) {
		lovelace.Add(lovelace, new(big.Int).Mul(new(big.Int).SetUint64(v.Lovelace), big.NewInt(sign)))
		for a, q := range v.Assets {
			if tokens[a] == nil {
				tokens[a] = new(big.Int)
			}
			tokens[a].Add(tokens[a], new(big.Int).Mul(new(big.Int).SetUint64(q), big.NewInt(sign)))
		}
	}
	for _, in := range d.Inputs {
		u, ok := byIn[in]
		if !ok {
			return nil
		}
		if u.Address.Equal(wallet) {
			add(u.Value, -1)
		}
	}
	for _, out := range d.View.Outputs {
		if out.Address.Equal(wallet) {
			add(out.Value, 1)
		}
	}
	e := &Effect{Lovelace: lovelace.String()}
	for _, id := range slices.SortedFunc(maps.Keys(tokens), model.AssetID.Compare) {
		if q := tokens[id]; q.Sign() != 0 {
			e.Assets = append(e.Assets, asset(id, q.String()))
		}
	}
	return e
}
