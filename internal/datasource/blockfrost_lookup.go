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
	"net/http"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Account implements Source. stake is a reward address in bech32.
func (b *Blockfrost) Account(ctx context.Context, stake string) (Account, error) {
	// It goes in the path of the URL.
	if !bech32Like(stake, "stake1") && !bech32Like(stake, "stake_test1") {
		return Account{}, fmt.Errorf("datasource: %q is not a stake address", stake)
	}
	var r struct {
		StakeAddress *string `json:"stake_address"`
		Registered   *bool   `json:"registered"`
		Pool         *string `json:"pool_id"`
		DRep         *string `json:"drep_id"`
		Rewards      *string `json:"withdrawable_amount"`
	}
	if err := b.call(ctx, "/accounts/"+stake, nil, &r); err != nil {
		return Account{}, err
	}
	if r.StakeAddress == nil || *r.StakeAddress != stake || r.Registered == nil || r.Rewards == nil {
		return Account{}, fmt.Errorf("%w: account is not about %s", ErrInvalidResponse, stake)
	}
	a := Account{Registered: *r.Registered}
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

// Asset implements Source. Blockfrost gives a token's metadata already read:
// the token's entry for CIP-25, the fields of the reference datum for
// CIP-68, and which one it is.
func (b *Blockfrost) Asset(ctx context.Context, id model.AssetID) (Asset, error) {
	policy, name, _ := strings.Cut(id.String(), ".")
	var r struct {
		Asset    *string         `json:"asset"`
		PolicyID *string         `json:"policy_id"`
		Name     *string         `json:"asset_name"`
		Quantity *string         `json:"quantity"`
		Metadata json.RawMessage `json:"onchain_metadata"`
		Standard *string         `json:"onchain_metadata_standard"`
	}
	if err := b.call(ctx, "/assets/"+policy+name, nil, &r); err != nil {
		return Asset{}, err
	}
	gotName := ""
	if r.Name != nil {
		gotName = *r.Name
	}
	if r.Asset == nil || *r.Asset != policy+name || r.PolicyID == nil || *r.PolicyID != policy || gotName != name || r.Quantity == nil {
		return Asset{}, fmt.Errorf("%w: asset is not about %s", ErrInvalidResponse, id)
	}
	if !digits(*r.Quantity) {
		return Asset{}, fmt.Errorf("%w: supply %q", ErrInvalidResponse, *r.Quantity)
	}
	a := Asset{ID: id, Supply: *r.Quantity}
	if !present(r.Metadata) {
		return a, nil
	}
	if len(r.Metadata) > maxMetadataBytes || r.Metadata[0] != '{' {
		return Asset{}, fmt.Errorf("%w: metadata of %s", ErrInvalidResponse, id)
	}
	md, ok := decodeJSON(r.Metadata).(map[string]any)
	if !ok {
		return Asset{}, fmt.Errorf("%w: metadata of %s", ErrInvalidResponse, id)
	}
	version, cip68 := "", false
	if r.Standard != nil {
		version, cip68 = strings.CutPrefix(*r.Standard, "CIP68v")
	}
	switch {
	case cip68:
		if !digits(version) || len(version) > 3 {
			return Asset{}, fmt.Errorf("%w: metadata standard %q", ErrInvalidResponse, *r.Standard)
		}
		md["version"] = json.Number(version) // as the Koios client sets it, from the datum
		a.Standard, a.Metadata = CIP68, md
	default:
		a.Standard, a.Metadata = CIP25, md
	}
	return a, nil
}

// AssetByFingerprint implements Source. Blockfrost has no way to find a
// token by its fingerprint, which is a hash of its identity.
func (b *Blockfrost) AssetByFingerprint(ctx context.Context, fingerprint string) (model.AssetID, error) {
	if !bech32Like(fingerprint, "asset1") {
		return model.AssetID{}, fmt.Errorf("%w: %q is not a fingerprint", model.ErrInvalidAsset, fingerprint)
	}
	return model.AssetID{}, fmt.Errorf("%w: Blockfrost does not look tokens up by fingerprint", ErrUnsupported)
}

// blockfrostTx is the part of a transaction's description the client reads.
type blockfrostTx struct {
	Hash   *string `json:"hash"`
	Block  *string `json:"block"`
	Height *uint64 `json:"block_height"`
	Time   *uint64 `json:"block_time"`
}

// tx reads where a transaction is in the chain, or ErrNotFound.
func (b *Blockfrost) tx(ctx context.Context, id [32]byte) (blockfrostTx, error) {
	want := hex.EncodeToString(id[:])
	var r blockfrostTx
	if err := b.call(ctx, "/txs/"+want, nil, &r); err != nil {
		return r, err
	}
	if r.Hash == nil || *r.Hash != want || r.Block == nil || r.Height == nil || r.Time == nil {
		return r, fmt.Errorf("%w: transaction is not about %s", ErrInvalidResponse, want)
	}
	return r, nil
}

// Transaction implements Source, with two requests: where the transaction
// is, and its CBOR. The caller decodes the CBOR and checks it hashes to the
// id asked for.
func (b *Blockfrost) Transaction(ctx context.Context, id [32]byte) (Transaction, error) {
	r, err := b.tx(ctx, id)
	if err != nil {
		return Transaction{}, err
	}
	t := Transaction{BlockHeight: *r.Height, BlockTime: time.Unix(int64(*r.Time), 0).UTC()}
	if t.BlockHash, err = hash32(*r.Block); err != nil {
		return Transaction{}, fmt.Errorf("%w: block hash: %v", ErrInvalidResponse, err)
	}
	var c struct {
		CBOR *string `json:"cbor"`
	}
	if err := b.call(ctx, "/txs/"+hex.EncodeToString(id[:])+"/cbor", nil, &c); err != nil {
		return Transaction{}, err
	}
	if c.CBOR == nil {
		return Transaction{}, fmt.Errorf("%w: transaction without cbor", ErrInvalidResponse)
	}
	if t.CBOR, err = hex.DecodeString(*c.CBOR); err != nil {
		return Transaction{}, fmt.Errorf("%w: cbor is not hex", ErrInvalidResponse)
	}
	return t, nil
}

// Submit implements Source. It sends once and never retries (section 9.6),
// as Koios does.
func (b *Blockfrost) Submit(ctx context.Context, tx []byte, id [32]byte) error {
	u := *b.base
	u.Path += "/tx/submit"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(tx))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mcpcardano")
	b.auth(req.Header)
	resp, err := b.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("%w: reading the answer: %v", ErrUnavailable, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		var got string
		if json.Unmarshal(body, &got) != nil || got != hex.EncodeToString(id[:]) {
			return fmt.Errorf("%w: the node answered with another transaction id", ErrInvalidResponse)
		}
		return nil
	case http.StatusBadRequest:
		var e struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &e) == nil && e.Message != "" {
			body = []byte(e.Message)
		}
		return fmt.Errorf("%w: %s", ErrRejected, rejection(body))
	}
	err = blockfrostStatus(resp.StatusCode)
	if errors.Is(err, ErrNotFound) {
		err = fmt.Errorf("%w: HTTP 404", ErrUnavailable)
	}
	return err
}

// Confirmations implements Source. Blockfrost has no request for many
// transactions at once, so it reads the tip and then each transaction.
func (b *Blockfrost) Confirmations(ctx context.Context, ids [][32]byte) (map[[32]byte]uint64, error) {
	tip, err := b.Tip(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[[32]byte]uint64, len(ids))
	for _, id := range ids {
		r, err := b.tx(ctx, id)
		switch {
		case errors.Is(err, ErrNotFound):
			out[id] = 0
			continue
		case err != nil:
			return nil, err
		}
		switch h := *r.Height; {
		case h <= tip.Height:
			out[id] = tip.Height - h + 1
		case h <= tip.Height+maxTipLag:
			// A block came after the tip was read.
			out[id] = 1
		default:
			return nil, fmt.Errorf("%w: transaction in block %d, past the tip at %d", ErrInvalidResponse, h, tip.Height)
		}
	}
	return out, nil
}

// maxTipLag is how many blocks past the tip a transaction's block may be:
// the blocks made while the client asks about the transactions one by one.
const maxTipLag = 5
