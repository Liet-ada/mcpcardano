// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package model

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"
)

// CredentialKind says whether a credential is a key hash or a script hash.
type CredentialKind uint8

const (
	KeyHash CredentialKind = iota
	ScriptHash
)

// Credential is a payment or stake credential.
type Credential struct {
	Kind CredentialKind
	Hash [28]byte
}

// Address is an address split into its parts (CIP-19). Raw is the whole
// address and is what equality compares; the other fields are filled in by
// whoever decodes it (chain in the server, txcheck in the wallet).
type Address struct {
	Raw       []byte
	Type      uint8 // header type, the high nibble of the first byte
	NetworkID uint8
	Payment   Credential
	Stake     *Credential // nil when the address has no stake credential
}

// Equal reports whether a and b are the same address. Only a complete match
// counts: the same payment credential with another stake credential is a
// different address (section 3.5).
func (a Address) Equal(b Address) bool { return bytes.Equal(a.Raw, b.Raw) }

// IntentKind is the kind of operation the agent asked for (section 3.3).
type IntentKind string

const (
	IntentPayment       IntentKind = "payment"
	IntentConsolidation IntentKind = "consolidation"
)

// Limits of build_payment (section 4.3).
const (
	MaxPaymentOutputs = 50
	MaxMessageBytes   = 256
)

// Intent is what the agent asked for, validated and typed. It is stored with
// the draft so the summary can show it next to the real effect.
type Intent struct {
	Kind    IntentKind
	Payment *Payment // only for IntentPayment
}

// Payment is the parameter set of a payment intent.
type Payment struct {
	Outputs []PaymentOutput
	Message string // CIP-20 message, optional
}

// PaymentOutput is one recipient of a payment.
type PaymentOutput struct {
	Address Address
	Value   Value
}

// ErrInvalidIntent reports an intent that breaks the limits of section 4.3.
var ErrInvalidIntent = errors.New("model: invalid intent")

// Validate checks the shape of the intent, not whether the wallet can pay it.
func (i Intent) Validate() error {
	switch i.Kind {
	case IntentConsolidation:
		if i.Payment != nil {
			return fmt.Errorf("%w: a consolidation has no outputs", ErrInvalidIntent)
		}
		return nil
	case IntentPayment:
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidIntent, i.Kind)
	}
	p := i.Payment
	if p == nil || len(p.Outputs) == 0 || len(p.Outputs) > MaxPaymentOutputs {
		return fmt.Errorf("%w: a payment needs 1 to %d outputs", ErrInvalidIntent, MaxPaymentOutputs)
	}
	if len(p.Message) > MaxMessageBytes || !utf8.ValidString(p.Message) {
		return fmt.Errorf("%w: the message must be valid UTF-8 of at most %d bytes", ErrInvalidIntent, MaxMessageBytes)
	}
	for n, o := range p.Outputs {
		if len(o.Address.Raw) == 0 {
			return fmt.Errorf("%w: output %d has no address", ErrInvalidIntent, n)
		}
		if o.Value.Lovelace == 0 && !o.Value.HasAssets() {
			return fmt.Errorf("%w: output %d sends nothing", ErrInvalidIntent, n)
		}
		for a, q := range o.Value.Assets {
			if q == 0 {
				return fmt.Errorf("%w: output %d sends zero of %s", ErrInvalidIntent, n, a)
			}
		}
	}
	return nil
}

// TxView is the neutral form in which policy sees a transaction (section
// 3.5). The server builds it with gouroboros and the wallet with txcheck;
// differential tests require both to agree.
type TxView struct {
	NetworkID     *uint8 // body field 15, if present
	Outputs       []Output
	Fee           uint64
	TTL           *uint64 // slot
	ValidityStart *uint64 // slot

	Certificates []Certificate
	Withdrawals  []Withdrawal
	Mint         map[AssetID]int64 // positive mints, negative burns

	Collateral       int // number of collateral inputs
	CollateralReturn bool
	TotalCollateral  *uint64

	RequiredSigners [][28]byte
	ReferenceInputs int
	ScriptDataHash  bool

	Votes     int
	Proposals int
	Donation  uint64
}

// Output is a transaction output as policy sees it.
type Output struct {
	Address   Address
	Value     Value
	HasDatum  bool
	HasScript bool // carries a reference script
	Own       bool // Address equals the wallet's address
}

// Certificate is a certificate in the body. The kinds and their deposits
// arrive in phase 2; until then policy only needs to know there is one.
type Certificate struct {
	Kind string
}

// Withdrawal is a reward withdrawal.
type Withdrawal struct {
	Account []byte
	Amount  uint64
}
