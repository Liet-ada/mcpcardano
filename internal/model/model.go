// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package model holds the data types of section 3 of the specification:
// identifiers, amounts, assets, values, wallets, intents, the transaction
// view and policies. It has no I/O and no behaviour beyond validation and
// checked arithmetic, so the server and the wallet share it unchanged.
package model

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Network is a Cardano network.
type Network string

const (
	Mainnet Network = "mainnet"
	Preprod Network = "preprod"
	Preview Network = "preview"
)

// Valid reports whether n is one of the supported networks.
func (n Network) Valid() bool {
	return n == Mainnet || n == Preprod || n == Preview
}

// AddressID is the network id carried in Shelley address headers and in the
// transaction body: 1 for mainnet, 0 for the test networks.
func (n Network) AddressID() uint8 {
	if n == Mainnet {
		return 1
	}
	return 0
}

// SlotClock converts between slots and time on a network. After the Byron
// era every network uses one-second slots.
type SlotClock struct {
	ShelleySlot uint64 // first slot of the Shelley era
	ShelleyTime int64  // Unix time of that slot
}

// Clock returns the slot clock of n, from its genesis files. The wallet
// computes the current slot with it and its own clock, never with the tip the
// server reports (section 9.3).
func (n Network) Clock() SlotClock {
	switch n {
	case Mainnet:
		return SlotClock{ShelleySlot: 4_492_800, ShelleyTime: 1_596_059_091}
	case Preprod:
		return SlotClock{ShelleySlot: 86_400, ShelleyTime: 1_655_769_600}
	default: // preview has no Byron era
		return SlotClock{ShelleySlot: 0, ShelleyTime: 1_666_656_000}
	}
}

// Time returns the start of a Shelley-era slot.
func (c SlotClock) Time(slot uint64) time.Time {
	return time.Unix(c.ShelleyTime+int64(slot-c.ShelleySlot), 0).UTC()
}

// Slot returns the slot that contains t, which must be in the Shelley era.
func (c SlotClock) Slot(t time.Time) uint64 {
	return c.ShelleySlot + uint64(t.Unix()-c.ShelleyTime)
}

// Mode is how a wallet signs (paper, section 2.3).
type Mode string

const (
	ModeA Mode = "A" // the person signs on a hardware wallet
	ModeB Mode = "B" // the agent's wallet signs below a threshold
	ModeC Mode = "C" // the agent's wallet signs within a budget
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool { return m == ModeA || m == ModeB || m == ModeC }

// CreatedBy says who created a wallet.
type CreatedBy string

const (
	ByPerson CreatedBy = "person"
	ByAgent  CreatedBy = "agent"
)

// Wallet is section 3.2: one base address for receiving and for change.
type Wallet struct {
	ID        WalletID
	Label     string
	Network   Network
	Mode      Mode
	Address   Address
	CreatedBy CreatedBy
}

// Identifiers are a prefix and 16 random bytes in lowercase base32 without
// padding (section 3.1). They are opaque: nothing derives from keys or
// addresses.
type (
	WalletID   string
	DraftID    string
	ApprovalID string
)

const (
	idRandomBytes = 16
	idLen         = 26 // base32 of 16 bytes, without padding
)

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ErrInvalidID reports an identifier with the wrong prefix or body.
var ErrInvalidID = errors.New("model: invalid identifier")

func newID(prefix string, r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	var b [idRandomBytes]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("model: reading randomness: %w", err)
	}
	return prefix + idEncoding.EncodeToString(b[:]), nil
}

func checkID(prefix, s string) error {
	body, ok := strings.CutPrefix(s, prefix)
	if !ok || len(body) != idLen {
		return ErrInvalidID
	}
	b, err := idEncoding.DecodeString(body)
	if err != nil || idEncoding.EncodeToString(b) != body {
		return ErrInvalidID
	}
	return nil
}

// NewWalletID returns a fresh wallet id read from r, or from crypto/rand if r
// is nil. The same holds for the other constructors.
func NewWalletID(r io.Reader) (WalletID, error) {
	s, err := newID("w_", r)
	return WalletID(s), err
}

// NewDraftID returns a fresh draft id.
func NewDraftID(r io.Reader) (DraftID, error) {
	s, err := newID("d_", r)
	return DraftID(s), err
}

// NewApprovalID returns a fresh approval id.
func NewApprovalID(r io.Reader) (ApprovalID, error) {
	s, err := newID("a_", r)
	return ApprovalID(s), err
}

// Validate checks the format of the id.
func (id WalletID) Validate() error { return checkID("w_", string(id)) }

// Validate checks the format of the id.
func (id DraftID) Validate() error { return checkID("d_", string(id)) }

// Validate checks the format of the id.
func (id ApprovalID) Validate() error { return checkID("a_", string(id)) }
