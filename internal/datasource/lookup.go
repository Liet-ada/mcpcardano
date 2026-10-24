// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package datasource

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// ErrNotFound reports something the chain does not have: a stake account it
// has never seen, an asset never minted or an unknown transaction.
var ErrNotFound = errors.New("datasource: not found")

// Account is the state of a stake account.
type Account struct {
	Registered bool
	Pool       string // bech32 pool id, empty if it delegates to none
	DRep       string // drep1..., drep_script1..., drep_always_abstain or drep_always_no_confidence; empty if none
	Rewards    uint64 // available to withdraw
}

// Asset is what the source knows of a native token.
type Asset struct {
	ID     model.AssetID
	Supply string // decimal; a total supply may pass 64 bits
	// Standard is CIP25 or CIP68 when the source has the token's metadata,
	// and empty otherwise. Metadata is that metadata as plain JSON values,
	// numbers as json.Number: for CIP-25, the token's entry under label 721
	// of its last mint; for CIP-68, the fields of its reference datum and
	// its version. Every source gives the same shape. It is text from the
	// chain: whoever shows it must neutralize it.
	Standard string
	Metadata any
}

// The metadata standards of a token.
const (
	CIP25 = "cip25"
	CIP68 = "cip68"
)

// Transaction is a transaction in the chain and the block that holds it.
type Transaction struct {
	CBOR        []byte
	BlockHeight uint64
	BlockHash   [32]byte
	BlockTime   time.Time
}

// maxMetadataBytes bounds the metadata of one asset.
const maxMetadataBytes = 64 << 10

// Account implements Source. stake is a reward address in bech32.
func (k *Koios) Account(ctx context.Context, stake string) (Account, error) {
	var rows []struct {
		StakeAddress *string `json:"stake_address"`
		Status       *string `json:"status"`
		Pool         *string `json:"delegated_pool"`
		DRep         *string `json:"delegated_drep"`
		Rewards      *string `json:"rewards_available"`
	}
	q := url.Values{"select": {"stake_address,status,delegated_pool,delegated_drep,rewards_available"}}
	if err := k.call(ctx, "/account_info", q, map[string]any{"_stake_addresses": []string{stake}}, &rows); err != nil {
		return Account{}, err
	}
	switch len(rows) {
	case 0:
		return Account{}, ErrNotFound
	case 1:
	default:
		return Account{}, fmt.Errorf("%w: account_info has %d rows", ErrInvalidResponse, len(rows))
	}
	r := rows[0]
	if r.StakeAddress == nil || *r.StakeAddress != stake || r.Status == nil || r.Rewards == nil {
		return Account{}, fmt.Errorf("%w: account_info is not about %s", ErrInvalidResponse, stake)
	}
	a := Account{Registered: *r.Status == "registered"}
	if !a.Registered && *r.Status != "not registered" {
		return Account{}, fmt.Errorf("%w: account status %q", ErrInvalidResponse, *r.Status)
	}
	var err error
	if a.Rewards, err = model.ParseAmount(*r.Rewards); err != nil {
		return Account{}, fmt.Errorf("%w: rewards %q", ErrInvalidResponse, *r.Rewards)
	}
	if r.Pool != nil {
		if !bech32Like(*r.Pool, "pool1") {
			return Account{}, fmt.Errorf("%w: pool %q", ErrInvalidResponse, *r.Pool)
		}
		a.Pool = *r.Pool
	}
	if r.DRep != nil {
		d := *r.DRep
		if d != "drep_always_abstain" && d != "drep_always_no_confidence" && !bech32Like(d, "drep1") && !bech32Like(d, "drep_script1") {
			return Account{}, fmt.Errorf("%w: drep %q", ErrInvalidResponse, d)
		}
		a.DRep = d
	}
	return a, nil
}

// bech32Like checks the shape of an identifier the server only shows: its
// prefix and the bech32 alphabet, within a sane length.
func bech32Like(s, prefix string) bool {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok || len(rest) < 8 || len(s) > 120 {
		return false
	}
	for _, c := range rest {
		if !strings.ContainsRune("qpzry9x8gf2tvdw0s3jn54khce6mua7l", c) {
			return false
		}
	}
	return true
}

// Asset implements Source.
func (k *Koios) Asset(ctx context.Context, id model.AssetID) (Asset, error) {
	var rows []struct {
		PolicyID *string         `json:"policy_id"`
		Name     *string         `json:"asset_name"`
		Supply   *string         `json:"total_supply"`
		CIP25    json.RawMessage `json:"minting_tx_metadata"`
		CIP68    json.RawMessage `json:"cip68_metadata"`
	}
	policy, name, _ := strings.Cut(id.String(), ".")
	q := url.Values{"select": {"policy_id,asset_name,total_supply,minting_tx_metadata,cip68_metadata"}}
	if err := k.call(ctx, "/asset_info", q, map[string]any{"_asset_list": [][]string{{policy, name}}}, &rows); err != nil {
		return Asset{}, err
	}
	switch len(rows) {
	case 0:
		return Asset{}, ErrNotFound
	case 1:
	default:
		return Asset{}, fmt.Errorf("%w: asset_info has %d rows", ErrInvalidResponse, len(rows))
	}
	r := rows[0]
	if r.PolicyID == nil || *r.PolicyID != policy || r.Name == nil || *r.Name != name || r.Supply == nil {
		return Asset{}, fmt.Errorf("%w: asset_info is not about %s", ErrInvalidResponse, id)
	}
	if !digits(*r.Supply) {
		return Asset{}, fmt.Errorf("%w: supply %q", ErrInvalidResponse, *r.Supply)
	}
	for _, raw := range []json.RawMessage{r.CIP25, r.CIP68} {
		if present(raw) && (len(raw) > maxMetadataBytes || raw[0] != '{') {
			return Asset{}, fmt.Errorf("%w: metadata of %s", ErrInvalidResponse, id)
		}
	}
	a := Asset{ID: id, Supply: *r.Supply}
	switch {
	case present(r.CIP68):
		a.Standard, a.Metadata = CIP68, cip68Fields(r.CIP68)
	case present(r.CIP25):
		if m := cip25Entry(r.CIP25, id); m != nil {
			a.Standard, a.Metadata = CIP25, m
		}
	}
	return a, nil
}

func digits(s string) bool {
	if s == "" || len(s) > 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// AssetByFingerprint implements Source. The fingerprint is checked against
// the asset the source names, so a lying source cannot swap it.
func (k *Koios) AssetByFingerprint(ctx context.Context, fingerprint string) (model.AssetID, error) {
	if !bech32Like(fingerprint, "asset1") {
		return model.AssetID{}, fmt.Errorf("%w: %q is not a fingerprint", model.ErrInvalidAsset, fingerprint)
	}
	var rows []struct {
		PolicyID *string `json:"policy_id"`
		Name     *string `json:"asset_name"`
	}
	q := url.Values{"fingerprint": {"eq." + fingerprint}, "select": {"policy_id,asset_name"}, "limit": {"2"}}
	if err := k.call(ctx, "/asset_list", q, nil, &rows); err != nil {
		return model.AssetID{}, err
	}
	switch len(rows) {
	case 0:
		return model.AssetID{}, ErrNotFound
	case 1:
	default:
		return model.AssetID{}, fmt.Errorf("%w: %d assets for one fingerprint", ErrInvalidResponse, len(rows))
	}
	r := rows[0]
	if r.PolicyID == nil || r.Name == nil {
		return model.AssetID{}, fmt.Errorf("%w: asset_list is missing fields", ErrInvalidResponse)
	}
	id, err := model.ParseAssetID(*r.PolicyID + "." + *r.Name)
	if err != nil || chain.Fingerprint(id) != fingerprint {
		return model.AssetID{}, fmt.Errorf("%w: the asset does not have fingerprint %s", ErrInvalidResponse, fingerprint)
	}
	return id, nil
}

// Transaction implements Source. The caller decodes the CBOR and checks it
// hashes to the id asked for.
func (k *Koios) Transaction(ctx context.Context, id [32]byte) (Transaction, error) {
	want := hex.EncodeToString(id[:])
	var rows []struct {
		TxHash    *string `json:"tx_hash"`
		BlockHash *string `json:"block_hash"`
		Height    *uint64 `json:"block_height"`
		Time      *uint64 `json:"tx_timestamp"`
		CBOR      *string `json:"cbor"`
	}
	q := url.Values{"select": {"tx_hash,block_hash,block_height,tx_timestamp,cbor"}}
	if err := k.call(ctx, "/tx_cbor", q, map[string]any{"_tx_hashes": []string{want}}, &rows); err != nil {
		return Transaction{}, err
	}
	switch len(rows) {
	case 0:
		return Transaction{}, ErrNotFound
	case 1:
	default:
		return Transaction{}, fmt.Errorf("%w: tx_cbor has %d rows", ErrInvalidResponse, len(rows))
	}
	r := rows[0]
	if r.TxHash == nil || *r.TxHash != want || r.BlockHash == nil || r.Height == nil || r.Time == nil || r.CBOR == nil {
		return Transaction{}, fmt.Errorf("%w: tx_cbor is not about %s", ErrInvalidResponse, want)
	}
	t := Transaction{BlockHeight: *r.Height, BlockTime: time.Unix(int64(*r.Time), 0).UTC()}
	var err error
	if t.BlockHash, err = hash32(*r.BlockHash); err != nil {
		return Transaction{}, fmt.Errorf("%w: block hash: %v", ErrInvalidResponse, err)
	}
	if t.CBOR, err = hex.DecodeString(*r.CBOR); err != nil {
		return Transaction{}, fmt.Errorf("%w: cbor is not hex", ErrInvalidResponse)
	}
	return t, nil
}
