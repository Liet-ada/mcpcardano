// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package datasource

import (
	"context"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// unavailable is a configured source that cannot work, such as Blockfrost
// without its project id: it answers every call with why, as a source that
// is down, so that the server starts with the others (decision 138).
type unavailable struct {
	name    string
	network model.Network
	err     error
}

// NewUnavailable returns a source that always fails with err, which wraps
// ErrUnavailable.
func NewUnavailable(name string, n model.Network, err error) Source {
	return &unavailable{name: name, network: n, err: err}
}

func (u *unavailable) Name() string                       { return u.name }
func (u *unavailable) Network() model.Network             { return u.network }
func (u *unavailable) CheckNetwork(context.Context) error { return u.err }
func (u *unavailable) Tip(context.Context) (Tip, error)   { return Tip{}, u.err }
func (u *unavailable) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{}, u.err
}
func (u *unavailable) UTxOs(context.Context, model.Address) ([]chain.UTxO, error) { return nil, u.err }
func (u *unavailable) Account(context.Context, string) (Account, error)           { return Account{}, u.err }
func (u *unavailable) Asset(context.Context, model.AssetID) (Asset, error)        { return Asset{}, u.err }
func (u *unavailable) AssetByFingerprint(context.Context, string) (model.AssetID, error) {
	return model.AssetID{}, u.err
}
func (u *unavailable) Transaction(context.Context, [32]byte) (Transaction, error) {
	return Transaction{}, u.err
}
func (u *unavailable) Submit(context.Context, []byte, [32]byte) error { return u.err }
func (u *unavailable) Confirmations(context.Context, [][32]byte) (map[[32]byte]uint64, error) {
	return nil, u.err
}
