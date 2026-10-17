// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package datasource is the common interface to the chain data the server
// reads, and its clients: Koios now, then Blockfrost and the person's own
// node (paper, section 6.5). The rest of the server does not know which one
// it talks to.
//
// Every source is only semi-trusted. Clients check the shape and range of
// what they receive and reject a response that is malformed or does not
// answer the question asked; they cannot detect a source that lies within
// those bounds, which is why the wallet and the hardware wallet never rely on
// it (paper, section 6.5).
package datasource

import (
	"context"
	"errors"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Source is a chain data source for one network.
type Source interface {
	// Name identifies the source for get_network_status, for example "koios".
	Name() string
	// Network is the network the source was configured for.
	Network() model.Network
	// CheckNetwork asks the source which network it serves and fails with
	// ErrNetworkMismatch if it is not Network(). The server calls it at
	// start-up.
	CheckNetwork(ctx context.Context) error
	// Tip returns the latest block.
	Tip(ctx context.Context) (Tip, error)
	// ProtocolParameters returns the parameters of the current epoch.
	ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error)
	// UTxOs returns the unspent outputs at a payment address, ordered by
	// reference.
	UTxOs(ctx context.Context, addr model.Address) ([]chain.UTxO, error)
	// Account returns the state of a stake account, given by its reward
	// address in bech32, or ErrNotFound if the chain has never seen it.
	Account(ctx context.Context, stake string) (Account, error)
	// Asset returns what the source knows of a token, or ErrNotFound.
	Asset(ctx context.Context, id model.AssetID) (Asset, error)
	// AssetByFingerprint returns the token with a CIP-14 fingerprint, or
	// ErrNotFound.
	AssetByFingerprint(ctx context.Context, fingerprint string) (model.AssetID, error)
	// Transaction returns a transaction in the chain with its block, or
	// ErrNotFound.
	Transaction(ctx context.Context, id [32]byte) (Transaction, error)
	// Submit sends a signed transaction to the network, once. ErrRejected
	// means the node refused it; ErrUnavailable means nobody knows whether
	// it arrived.
	Submit(ctx context.Context, tx []byte, id [32]byte) error
	// Confirmations says, for each transaction, how many blocks contain or
	// follow it; zero if it is not in the chain.
	Confirmations(ctx context.Context, ids [][32]byte) (map[[32]byte]uint64, error)
}

// Tip is the latest block a source knows.
type Tip struct {
	Slot   uint64
	Height uint64
	Epoch  uint64
	Hash   [32]byte
	Time   time.Time
}

var (
	// ErrUnavailable reports a source that could not answer: network errors,
	// time-outs, rate limits or server errors, after retrying. The agent sees
	// DATASOURCE_UNAVAILABLE (section 9.6).
	ErrUnavailable = errors.New("datasource: unavailable")
	// ErrInvalidResponse reports an answer that is malformed, out of range or
	// about something other than what was asked.
	ErrInvalidResponse = errors.New("datasource: invalid response")
	// ErrNetworkMismatch reports a source that serves another network.
	ErrNetworkMismatch = errors.New("datasource: source serves another network")
	// ErrTooManyUTxOs reports an address with more UTxOs than the server
	// reads; the person should consolidate.
	ErrTooManyUTxOs = errors.New("datasource: too many UTxOs at the address")
)

// MaxUTxOs is the most UTxOs read for one address.
const MaxUTxOs = 10_000
