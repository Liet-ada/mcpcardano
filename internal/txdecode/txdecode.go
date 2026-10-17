// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package txdecode reads transactions for the server. From the bytes of a
// transaction it gives the view that policy evaluates (section 3.5 of the
// specification), the summary the agent and the person read (section 4.4),
// and the check of a built transaction against its intent (section 8.6).
// The decoding itself is done by chain, the only package that imports
// gouroboros, so the summary always describes the bytes that are signed and
// never what the builder meant to write.
package txdecode

import (
	"errors"
	"fmt"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// ErrTooLarge reports a transaction above the size the caller allows. The size
// bounds the decoding time (decision 39).
var ErrTooLarge = errors.New("txdecode: transaction too large")

// Tx is a decoded transaction.
type Tx struct {
	d *chain.DecodedTx
}

// Decode decodes a whole Conway transaction of at most maxSize bytes.
func Decode(raw []byte, maxSize int) (*Tx, error) {
	if len(raw) > maxSize {
		return nil, fmt.Errorf("%w: %d bytes, the maximum is %d", ErrTooLarge, len(raw), maxSize)
	}
	d, err := chain.DecodeTransaction(raw)
	if err != nil {
		return nil, err
	}
	return &Tx{d: d}, nil
}

// ID returns the transaction id, the hash of its body.
func (t *Tx) ID() [32]byte { return t.d.ID }

// Inputs returns the inputs, in body order.
func (t *Tx) Inputs() []chain.TxIn { return t.d.Inputs }

// View returns the transaction as policy sees it, with the outputs that pay
// exactly the wallet's address marked as own. Only a complete match counts
// (section 3.5).
func (t *Tx) View(wallet model.Address) model.TxView {
	v := t.d.View
	v.Outputs = make([]model.Output, len(t.d.View.Outputs))
	for i, o := range t.d.View.Outputs {
		o.Own = o.Address.Equal(wallet)
		v.Outputs[i] = o
	}
	return v
}
