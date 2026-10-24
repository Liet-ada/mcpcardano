// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package mcp

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/datasource"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/sanitize"
	"github.com/Liet-ada/mcpcardano/internal/txdecode"
)

func (s *Server) registerLookups() error {
	for _, err := range []error{
		addTool(s, tool{name: "get_address_info", readOnly: true, openWorld: true,
			description: "Any payment address: its kind, stake address, balance, tokens by pages of at most 100 with a cursor, and the delegation of its stake account to a pool and a DRep. Amounts are lovelace or token units as decimal strings."},
			s.addressInfo),
		addTool(s, tool{name: "get_asset_info", readOnly: true, openWorld: true,
			description: "A native token, by asset_id (<policy_hex>.<name_hex>) or CIP-14 fingerprint: its identity, total supply, standard (CIP-25 or CIP-68), metadata and whether a wallet's policy lists it. The identity of a token is its policy and name, never its displayed name, which anyone can copy."},
			s.assetInfo),
		addTool(s, tool{name: "get_transaction", readOnly: true, openWorld: true,
			description: "A transaction in the chain: whether it is there, its block and confirmations, and its summary decoded from its own bytes, with inputs, outputs, fee and metadata. Amounts are lovelace as decimal strings."},
			s.transaction),
	} {
		if err != nil {
			return err
		}
	}
	return nil
}

type addressArg struct {
	Address string `json:"address" jsonschema:"A payment address in bech32."`
	Cursor  string `json:"cursor,omitempty" jsonschema:"next_cursor of the previous page of tokens."`
	Limit   int    `json:"limit,omitempty" jsonschema:"Tokens per page, 1 to 100; 50 by default."`
}

type kindView struct {
	Type    string `json:"type"`    // base, pointer or enterprise
	Payment string `json:"payment"` // key or script
	Stake   string `json:"stake"`   // key, script, pointer or none
}

type delegationView struct {
	Registered       bool   `json:"registered"`
	Pool             string `json:"pool,omitempty"`
	DRep             string `json:"drep,omitempty"`
	RewardsAvailable string `json:"rewards_available"`
}

type addressInfo struct {
	Network      string           `json:"network"`
	Address      string           `json:"address"`
	WalletID     string           `json:"wallet_id,omitempty"` // when the address is a configured wallet's
	Kind         kindView         `json:"kind"`
	StakeAddress string           `json:"stake_address,omitempty"`
	Lovelace     string           `json:"lovelace"`
	UTxOs        int              `json:"utxos"`
	Assets       []txdecode.Asset `json:"assets"`
	AssetsCount  int              `json:"assets_count"`
	NextCursor   string           `json:"next_cursor,omitempty"`
	Delegation   *delegationView  `json:"delegation,omitempty"`
}

func kindOf(a model.Address) kindView {
	k := kindView{Payment: "key", Stake: "none"}
	if a.Payment.Kind == model.ScriptHash {
		k.Payment = "script"
	}
	switch {
	case a.Type <= 3:
		k.Type = "base"
	case a.Type <= 5:
		k.Type, k.Stake = "pointer", "pointer"
	default:
		k.Type = "enterprise"
	}
	if a.Stake != nil {
		k.Stake = "key"
		if a.Stake.Kind == model.ScriptHash {
			k.Stake = "script"
		}
	}
	return k
}

func (s *Server) addressInfo(ctx context.Context, a addressArg) (addressInfo, error) {
	limit := a.Limit
	switch {
	case limit == 0:
		limit = defaultPage
	case limit < 1 || limit > maxPage:
		return addressInfo{}, invalid("limit must be between 1 and %d", maxPage)
	}
	addr, err := chain.ParseAddress(s.d.Network, a.Address)
	if err != nil {
		return addressInfo{}, err
	}
	var after *model.AssetID
	if a.Cursor != "" {
		id, err := model.ParseAssetID(a.Cursor)
		if err != nil {
			return addressInfo{}, invalid("cursor %q is not an asset id", a.Cursor)
		}
		after = &id
	}
	utxos, err := s.d.Source.UTxOs(ctx, addr)
	if err != nil {
		return addressInfo{}, err
	}
	var total model.Value
	for _, u := range utxos {
		if total, err = total.Add(u.Value); err != nil {
			return addressInfo{}, err
		}
	}
	text, err := chain.FormatAddress(addr)
	if err != nil {
		return addressInfo{}, err
	}
	out := addressInfo{
		Network: string(s.d.Network), Address: text, Kind: kindOf(addr),
		Lovelace: model.FormatAmount(total.Lovelace), UTxOs: len(utxos),
		Assets: []txdecode.Asset{}, AssetsCount: len(total.Assets),
	}
	for _, w := range s.d.Wallets {
		if w.Address.Equal(addr) {
			out.WalletID = string(w.ID)
		}
	}
	ids := sortedAssets(total.Assets)
	if after != nil {
		ids = slices.DeleteFunc(ids, func(id model.AssetID) bool { return id.Compare(*after) <= 0 })
	}
	page := map[model.AssetID]uint64{}
	for _, id := range ids[:min(limit, len(ids))] {
		page[id] = total.Assets[id]
	}
	out.Assets, _ = txdecode.Tokens(txdecode.NewBudget(limit, s.verified), page)
	if out.Assets == nil {
		out.Assets = []txdecode.Asset{}
	}
	if len(ids) > limit {
		out.NextCursor = ids[limit-1].String()
	}
	if addr.Stake != nil {
		if out.StakeAddress, err = chain.StakeAddress(s.d.Network, *addr.Stake); err != nil {
			return addressInfo{}, err
		}
		acc, err := s.d.Source.Account(ctx, out.StakeAddress)
		switch {
		case errors.Is(err, datasource.ErrNotFound):
			out.Delegation = &delegationView{RewardsAvailable: "0"}
		case err != nil:
			return addressInfo{}, err
		default:
			out.Delegation = &delegationView{Registered: acc.Registered, Pool: acc.Pool, DRep: acc.DRep, RewardsAvailable: model.FormatAmount(acc.Rewards)}
		}
	}
	return out, nil
}

type assetQuery struct {
	AssetID     string `json:"asset_id,omitempty" jsonschema:"<policy_hex>.<name_hex>. Give this or fingerprint."`
	Fingerprint string `json:"fingerprint,omitempty" jsonschema:"The CIP-14 fingerprint, asset1... Give this or asset_id."`
}

type assetInfo struct {
	Network        string `json:"network"`
	Asset          string `json:"asset"`
	PolicyID       string `json:"policy_id"`
	NameHex        string `json:"name_hex"`
	NameUnverified string `json:"name_unverified,omitempty"`
	Fingerprint    string `json:"fingerprint"`
	TotalSupply    string `json:"total_supply"`
	Standard       string `json:"standard"` // cip25, cip68 or none
	// MetadataUnverified is the token's metadata, neutralized: the entry of
	// this token under label 721 for CIP-25, or the fields of the reference
	// datum for CIP-68.
	MetadataUnverified any `json:"metadata_unverified,omitempty"`
	// Verified says whether the policy of a wallet lists the token.
	Verified bool `json:"verified" jsonschema:"True only when the person listed this token in the policy of a wallet. Anyone can mint a token with any name and metadata and send it to any address."`
}

// cip67Labels are the asset name prefixes of CIP-68 tokens (CIP-67): the
// reference token and the NFT, FT and RFT user tokens.
var cip67Labels = []string{"000643b0", "000de140", "0014df10", "001bc280"}

func (s *Server) assetInfo(ctx context.Context, a assetQuery) (assetInfo, error) {
	var id model.AssetID
	var err error
	switch {
	case (a.AssetID == "") == (a.Fingerprint == ""):
		return assetInfo{}, invalid("give asset_id or fingerprint, not both")
	case a.AssetID != "":
		if id, err = model.ParseAssetID(a.AssetID); err != nil {
			return assetInfo{}, invalid("asset_id %q is not <policy_hex>.<name_hex>", a.AssetID)
		}
	default:
		id, err = s.d.Source.AssetByFingerprint(ctx, a.Fingerprint)
		if errors.Is(err, datasource.ErrNotFound) {
			return assetInfo{}, invalid("no token on %s has fingerprint %s", s.d.Network, a.Fingerprint)
		}
		if errors.Is(err, datasource.ErrUnsupported) {
			return assetInfo{}, invalid("the data source cannot look a token up by its fingerprint: give asset_id")
		}
		if err != nil {
			return assetInfo{}, err
		}
	}
	x, err := s.d.Source.Asset(ctx, id)
	if errors.Is(err, datasource.ErrNotFound) {
		return assetInfo{}, invalid("no token %s on %s", id, s.d.Network)
	}
	if err != nil {
		return assetInfo{}, err
	}
	nameHex := hex.EncodeToString([]byte(id.Name))
	out := assetInfo{
		Network: string(s.d.Network), Asset: id.String(), PolicyID: hex.EncodeToString(id.Policy[:]), NameHex: nameHex,
		Fingerprint: chain.Fingerprint(id), TotalSupply: x.Supply, Standard: "none",
		NameUnverified: sanitize.Name([]byte(id.Name), txdecode.MaxNameBytes), Verified: s.verified(id),
	}
	labelled := len(nameHex) >= 8 && slices.Contains(cip67Labels, nameHex[:8])
	if labelled {
		out.NameUnverified = sanitize.Name([]byte(id.Name[4:]), txdecode.MaxNameBytes)
	}
	switch {
	case x.Standard == datasource.CIP68 || labelled:
		out.Standard = "cip68"
		if x.Standard == datasource.CIP68 && x.Metadata != nil {
			out.MetadataUnverified = sanitize.Value(x.Metadata)
		}
	case x.Standard == datasource.CIP25:
		out.Standard = "cip25"
		out.MetadataUnverified = sanitize.Value(x.Metadata)
	}
	return out, nil
}

type txQuery struct {
	TxID string `json:"tx_id" jsonschema:"The transaction id, 64 hex characters."`
}

type blockView struct {
	Height string `json:"height"`
	Hash   string `json:"hash"`
	Time   string `json:"time"`
}

type transactionView struct {
	Network            string            `json:"network"`
	TxID               string            `json:"tx_id"`
	Status             string            `json:"status"` // confirmed or unknown
	Block              *blockView        `json:"block,omitempty"`
	Confirmations      uint64            `json:"confirmations,omitempty"`
	Summary            *txdecode.Summary `json:"summary,omitempty"`
	MetadataUnverified any               `json:"metadata_unverified,omitempty"`
}

func (s *Server) transaction(ctx context.Context, a txQuery) (transactionView, error) {
	b, err := hex.DecodeString(a.TxID)
	if err != nil || len(b) != 32 || strings.ToLower(a.TxID) != a.TxID {
		return transactionView{}, invalid("tx_id must be 64 lowercase hex characters")
	}
	out := transactionView{Network: string(s.d.Network), TxID: a.TxID, Status: "unknown"}
	t, err := s.d.Source.Transaction(ctx, [32]byte(b))
	if errors.Is(err, datasource.ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return transactionView{}, err
	}
	tx, err := txdecode.Decode(t.CBOR, MaxDecodeBytes)
	if err != nil || tx.ID() != [32]byte(b) {
		// The source sent something that is not the transaction asked for.
		return transactionView{}, datasource.ErrInvalidResponse
	}
	tip, err := s.d.Source.Tip(ctx)
	if err != nil {
		return transactionView{}, err
	}
	summary, err := tx.Summary(txdecode.Options{Verified: s.verified})
	if err != nil {
		return transactionView{}, err
	}
	out.Status = "confirmed"
	out.Block = &blockView{
		Height: model.FormatAmount(t.BlockHeight), Hash: hex.EncodeToString(t.BlockHash[:]),
		Time: t.BlockTime.UTC().Format(time.RFC3339),
	}
	if tip.Height >= t.BlockHeight {
		out.Confirmations = tip.Height - t.BlockHeight + 1
	}
	out.Summary = &summary
	out.MetadataUnverified = tx.MetadataUnverified()
	return out, nil
}
