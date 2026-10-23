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

// Limits per response, since flooding the context is an attack too (paper,
// section 7.1). A summary shows at most MaxInputs inputs, MaxOutputs outputs
// and MaxTokens tokens in all; a list that is cut says how long it was.
const (
	MaxInputs  = 100
	MaxOutputs = 100
	MaxTokens  = 100
)

// Budget is what a response may still show of the tokens, and which tokens
// it marks as verified.
type Budget struct {
	left     int
	verified func(model.AssetID) bool
}

// NewBudget returns a budget of n tokens. verified says which tokens the
// person listed in the policy of a wallet; nil marks none.
func NewBudget(n int, verified func(model.AssetID) bool) *Budget {
	return &Budget{left: n, verified: verified}
}

// Tokens lists the tokens of a value in the fixed order of section 8.2, as
// far as the budget allows. If it cuts the list, count is how many there are.
func Tokens(b *Budget, m map[model.AssetID]uint64) (list []Asset, count int) {
	return assets(b, m, model.FormatAmount)
}

// Summary is what the agent and the person read about a transaction
// (section 4.4). Amounts are decimal strings (section 4.1); net effect and
// mint quantities carry a sign. Text from the chain is neutralized and sits
// in fields ending in _unverified. Fields the MVP never builds are shown only
// when present, so nothing in the body goes unseen.
type Summary struct {
	TxID              string   `json:"tx_id"`
	Inputs            []Input  `json:"inputs"`
	InputsCount       int      `json:"inputs_count,omitempty"` // only when the list is cut
	Outputs           []Output `json:"outputs"`
	OutputsCount      int      `json:"outputs_count,omitempty"` // only when the list is cut
	Fee               string   `json:"fee"`
	NetEffect         *Effect  `json:"net_effect,omitempty"`
	TTLSlot           string   `json:"ttl_slot,omitempty"`
	ValidityStartSlot string   `json:"validity_start_slot,omitempty"`

	Certificates      []string     `json:"certificates,omitempty"`
	Withdrawals       []Withdrawal `json:"withdrawals,omitempty"`
	Mint              []Asset      `json:"mint,omitempty"`
	MintCount         int          `json:"mint_count,omitempty"`
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

// Input is one input of the summary: the output it spends, by transaction id
// and index. Own and the value are present only when the summary knows that
// output, as for a draft, whose inputs the server chose; they are what the
// data source says.
type Input struct {
	Ref         string  `json:"ref"`
	Own         *bool   `json:"own,omitempty"`
	Lovelace    string  `json:"lovelace,omitempty"`
	Assets      []Asset `json:"assets,omitempty"`
	AssetsCount int     `json:"assets_count,omitempty"` // only when the list is cut
}

// Output is one output of the summary. Own is present only when the summary
// was made for a wallet.
type Output struct {
	Address         string  `json:"address"`
	Own             *bool   `json:"own,omitempty"`
	Lovelace        string  `json:"lovelace"`
	Assets          []Asset `json:"assets,omitempty"`
	AssetsCount     int     `json:"assets_count,omitempty"` // only when the list is cut
	Datum           bool    `json:"datum,omitempty"`
	ReferenceScript bool    `json:"reference_script,omitempty"`
}

// Asset is a quantity of a token. The asset id and the CIP-14 fingerprint
// identify it; the name is only a label anyone can copy (paper, section 7.2).
// Verified says whether the person listed the token in the policy of a
// wallet: a token nobody listed may be anyone's (decision 84).
type Asset struct {
	Asset          string `json:"asset"`
	Fingerprint    string `json:"fingerprint"`
	NameUnverified string `json:"name_unverified,omitempty"`
	Quantity       string `json:"quantity"`
	Verified       bool   `json:"verified" jsonschema:"True only when the person listed this token in the policy of a wallet. Anyone can mint a token with any name and metadata and send it to any address."`
}

// Effect is the net change of a wallet's holdings: what the transaction
// leaves at the wallet's address minus what it takes from it.
type Effect struct {
	Lovelace    string  `json:"lovelace"`
	Assets      []Asset `json:"assets,omitempty"`
	AssetsCount int     `json:"assets_count,omitempty"`
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
	// input among them, the summary has a net effect. Each input among them
	// shows its value.
	Spent []chain.UTxO
	// Verified marks the tokens the person listed in the policy of a wallet.
	Verified func(model.AssetID) bool
}

// Summary describes the transaction, within the limits of a response.
func (t *Tx) Summary(o Options) (Summary, error) {
	budget := NewBudget(MaxTokens, o.Verified)
	d, v := t.d, t.d.View
	s := Summary{
		TxID:             hex.EncodeToString(d.ID[:]),
		Inputs:           []Input{},
		Outputs:          []Output{},
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

	// The net effect goes first: it is what the person most needs to see.
	spent := byInput(o.Spent)
	if o.Wallet != nil {
		s.NetEffect = netEffect(d, *o.Wallet, spent, budget)
	}
	outs := v.Outputs
	if len(outs) > MaxOutputs {
		s.OutputsCount, outs = len(outs), outs[:MaxOutputs]
	}
	for _, out := range outs {
		addr, err := chain.AddressText(out.Address)
		if err != nil {
			return Summary{}, err
		}
		so := Output{
			Address:         addr,
			Lovelace:        model.FormatAmount(out.Value.Lovelace),
			Datum:           out.HasDatum,
			ReferenceScript: out.HasScript,
		}
		so.Assets, so.AssetsCount = Tokens(budget, out.Value.Assets)
		if o.Wallet != nil {
			own := out.Address.Equal(*o.Wallet)
			so.Own = &own
		}
		s.Outputs = append(s.Outputs, so)
	}
	// The inputs go after the outputs, which take the tokens first.
	s.Inputs, s.InputsCount = inputs(d.Inputs, o.Wallet, spent, budget)

	for _, c := range v.Certificates {
		s.Certificates = append(s.Certificates, c.Kind)
	}
	for i, w := range v.Withdrawals {
		s.Withdrawals = append(s.Withdrawals, Withdrawal{Account: d.Accounts[i], Lovelace: model.FormatAmount(w.Amount)})
	}
	s.Mint, s.MintCount = assets(budget, v.Mint, func(q int64) string { return strconv.FormatInt(q, 10) })

	for _, l := range d.MetadataLabels {
		s.MetadataLabels = append(s.MetadataLabels, strconv.FormatUint(l, 10))
	}
	s.MessageUnverified = message(d.Message)
	return s, nil
}

// byInput indexes the outputs the inputs consume.
func byInput(spent []chain.UTxO) map[chain.TxIn]chain.UTxO {
	m := make(map[chain.TxIn]chain.UTxO, len(spent))
	for _, u := range spent {
		m[u.In] = u
	}
	return m
}

// inputs lists the inputs in body order, at most MaxInputs of them, with the
// value of those whose output the summary knows. If it cuts the list, count
// is how many there are.
func inputs(ins []chain.TxIn, wallet *model.Address, spent map[chain.TxIn]chain.UTxO, b *Budget) (list []Input, count int) {
	if len(ins) > MaxInputs {
		count, ins = len(ins), ins[:MaxInputs]
	}
	list = make([]Input, 0, len(ins))
	for _, in := range ins {
		i := Input{Ref: in.String()}
		if u, ok := spent[in]; ok {
			i.Lovelace = model.FormatAmount(u.Value.Lovelace)
			i.Assets, i.AssetsCount = Tokens(b, u.Value.Assets)
			if wallet != nil {
				own := u.Address.Equal(*wallet)
				i.Own = &own
			}
		}
		list = append(list, i)
	}
	return list, count
}

// assets lists a token map in the fixed order of section 8.2, as far as the
// budget allows, and the number of tokens if the list is cut.
func assets[Q uint64 | int64 | string](b *Budget, m map[model.AssetID]Q, format func(Q) string) ([]Asset, int) {
	var zero Q
	ids := slices.SortedFunc(maps.Keys(m), model.AssetID.Compare)
	ids = slices.DeleteFunc(ids, func(id model.AssetID) bool { return m[id] == zero })
	n := min(len(ids), b.left)
	b.left -= n
	var out []Asset
	for _, id := range ids[:n] {
		a := asset(id, format(m[id]))
		a.Verified = b.verified != nil && b.verified(id)
		out = append(out, a)
	}
	if n < len(ids) {
		return out, len(ids)
	}
	return out, 0
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
func netEffect(d *chain.DecodedTx, wallet model.Address, spent map[chain.TxIn]chain.UTxO, b *Budget) *Effect {
	if len(d.Inputs) == 0 {
		return nil
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
		u, ok := spent[in]
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
	signed := map[model.AssetID]string{}
	for id, q := range tokens {
		if q.Sign() != 0 {
			signed[id] = q.String()
		}
	}
	e := &Effect{Lovelace: lovelace.String()}
	e.Assets, e.AssetsCount = assets(b, signed, func(q string) string { return q })
	return e
}

// MetadataUnverified returns the whole metadata of the transaction,
// neutralized and cut like any text from the chain, or nil if it has none.
func (t *Tx) MetadataUnverified() any {
	if t.d.Metadata == nil {
		return nil
	}
	return sanitize.Value(t.d.Metadata)
}

// Metadata returns the whole metadata as decoded, for tests and the audit
// log; anything shown to the agent goes through MetadataUnverified.
func (t *Tx) Metadata() map[string]any { return t.d.Metadata }
