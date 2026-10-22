// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package txcheck is the wallet's own reading of a transaction (section 8.4
// of the specification). It decodes the body and the auxiliary data that
// SignDraft carries with a minimal decoder of its own, never with gouroboros,
// and gives the view that policy evaluates. Whatever it cannot read exactly
// it rejects: a field it does not know, a field the MVP does not support, a
// form the ledger would not accept or bytes that are not canonical.
//
// Steps 5 (network) and 7 (required signers) of section 8.4 are rules of
// policy, which evaluates the view this package returns, in the wallet as in
// the server. Step 8 belongs to the caller: the view, the wallet's own clock
// and the policy.
package txcheck

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

var (
	// ErrTooLarge reports a body and auxiliary data above the size of a
	// transaction.
	ErrTooLarge = errors.New("txcheck: transaction too large")
	// ErrNotCanonical reports bytes that are not one canonical CBOR item
	// within the limits (TX_NOT_CANONICAL).
	ErrNotCanonical = errors.New("txcheck: not canonical CBOR")
	// ErrUnsupportedField reports a field the wallet does not know or does
	// not support, or one in a form it does not accept
	// (TX_UNSUPPORTED_FIELD).
	ErrUnsupportedField = errors.New("txcheck: unsupported field")
)

// MaxDepth bounds the nesting of the CBOR the wallet decodes, until
// experiment E4 (decision 97). A body of the MVP does not go beyond 6.
const MaxDepth = 16

// setTag marks a CBOR array as a set (Conway).
const setTag = 258

// Keys of the Conway transaction body that the decoder reads.
const (
	keyInputs          = 0
	keyOutputs         = 1
	keyFee             = 2
	keyTTL             = 3
	keyWithdrawals     = 5
	keyAuxDataHash     = 7
	keyValidityStart   = 8
	keyMint            = 9
	keyRequiredSigners = 14
	keyNetworkID       = 15
)

// field is a key of the Conway transaction body, with its name in the CDDL.
type field struct {
	name      string
	supported bool
}

// bodyFields is the closed list of section 8.4, step 3. The MVP always
// rejects the unsupported ones (decision 35), certificates included until
// their deposits count (decision 105). Withdrawals and mint reach policy,
// which allows them only if the wallet's policy does.
var bodyFields = map[uint64]field{
	0:  {"inputs", true},
	1:  {"outputs", true},
	2:  {"fee", true},
	3:  {"ttl", true},
	4:  {"certificates", false},
	5:  {"withdrawals", true},
	7:  {"auxiliary_data_hash", true},
	8:  {"validity_interval_start", true},
	9:  {"mint", true},
	11: {"script_data_hash", false},
	13: {"collateral_inputs", false},
	14: {"required_signers", true},
	15: {"network_id", true},
	16: {"collateral_return", false},
	17: {"total_collateral", false},
	18: {"reference_inputs", false},
	19: {"voting_procedures", false},
	20: {"proposal_procedures", false},
	21: {"current_treasury_value", false},
	22: {"donation", false},
}

var codec = newCodec()

func newCodec() *cborx.Codec {
	c, err := cborx.New(cborx.Limits{
		MaxDepth:         MaxDepth,
		MaxArrayElements: ipc.MaxTxSize,
		MaxMapPairs:      ipc.MaxTxSize,
		AllowTags:        true,
	})
	if err != nil {
		panic(err) // constant limits
	}
	return c
}

// Input is a transaction input: the id of the transaction that created the
// output and the output's index.
type Input struct {
	TxID  [32]byte
	Index uint16
}

// Tx is a transaction as the wallet read it.
type Tx struct {
	// ID is the hash of the body: what the wallet signs.
	ID [32]byte
	// Inputs are in body order. The wallet does not know their value, so the
	// spend never depends on them (M-01).
	Inputs []Input
	// Message holds the lines of the CIP-20 message, nil without one.
	Message []string

	view model.TxView
}

// View returns the transaction as policy sees it, with the outputs that pay
// exactly the wallet's address marked as own. Only a complete match counts
// (section 3.5, M-02).
func (t *Tx) View(wallet model.Address) model.TxView {
	v := t.view
	v.Outputs = make([]model.Output, len(t.view.Outputs))
	for i, o := range t.view.Outputs {
		o.Own = o.Address.Equal(wallet)
		v.Outputs[i] = o
	}
	return v
}

// Decode reads a transaction body and its auxiliary data, empty if there is
// none, as SignDraft carries them (section 5.3), following steps 1 to 6 of
// section 8.4.
func Decode(body, aux []byte) (*Tx, error) {
	// Step 1: the size bounds the decoding time (decision 39).
	if n := len(body) + len(aux); n > ipc.MaxTxSize {
		return nil, fmt.Errorf("%w: %d bytes, the maximum is %d", ErrTooLarge, n, ipc.MaxTxSize)
	}

	// Step 2: one CBOR item within the limits, a map with integer keys.
	var top map[uint64]cborx.Raw
	if err := codec.Unmarshal(body, &top); err != nil {
		return nil, fmt.Errorf("%w: the body is not a map of integer keys within the limits: %v", ErrNotCanonical, err)
	}

	// Step 3: the closed list of fields (M-07). It comes before reading any
	// field, so a field the MVP rejects is rejected for what it is.
	keys := make([]uint64, 0, len(top))
	for k := range top {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		f, ok := bodyFields[k]
		switch {
		case !ok:
			return nil, fmt.Errorf("%w: unknown body field %d", ErrUnsupportedField, k)
		case !f.supported:
			return nil, fmt.Errorf("%w: %s (field %d) is not supported", ErrUnsupportedField, f.name, k)
		}
	}
	for _, k := range []uint64{keyInputs, keyOutputs, keyFee} {
		if _, ok := top[k]; !ok {
			return nil, fmt.Errorf("%w: the body has no %s", ErrUnsupportedField, bodyFields[k].name)
		}
	}

	// Step 4: the bytes are the canonical encoding of what they say (M-08).
	// The map as read must give the body back too: decoding into a map drops
	// a tag around the body or around a key.
	if again, err := codec.Marshal(top); err != nil || !bytes.Equal(again, body) {
		return nil, fmt.Errorf("%w: the body is not a canonical map of integer keys", ErrNotCanonical)
	}
	if err := codec.CheckCanonical(body); err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrNotCanonical, err)
	}

	t := &Tx{ID: blake2b.Sum256(body)}
	var auxHash []byte
	for _, k := range keys {
		var x any
		if err := codec.Unmarshal(top[k], &x); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrNotCanonical, bodyFields[k].name, err)
		}
		if err := t.read(k, x, &auxHash); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrUnsupportedField, bodyFields[k].name, err)
		}
	}

	// Step 6: the auxiliary data.
	msg, err := auxData(aux, auxHash)
	if err != nil {
		return nil, err
	}
	t.Message = msg
	return t, nil
}

// read stores the value of body field k.
func (t *Tx) read(k uint64, x any, auxHash *[]byte) error {
	v := &t.view
	var err error
	switch k {
	case keyInputs:
		t.Inputs, err = inputs(x)
	case keyOutputs:
		v.Outputs, err = outputs(x)
	case keyFee:
		v.Fee, err = unsigned(x)
	case keyTTL:
		v.TTL, err = slot(x)
	case keyWithdrawals:
		v.Withdrawals, err = withdrawals(x)
	case keyAuxDataHash:
		*auxHash, err = hash(x, 32)
	case keyValidityStart:
		v.ValidityStart, err = slot(x)
	case keyMint:
		v.Mint, err = multiasset(x, nonZero)
	case keyRequiredSigners:
		v.RequiredSigners, err = signers(x)
	case keyNetworkID:
		v.NetworkID, err = networkID(x)
	}
	return err
}

// cip20Label is the metadata label of transaction messages (CIP-20).
const cip20Label = 674

// maxMetadataText is the longest text string metadata accepts.
const maxMetadataText = 64

// auxData checks the auxiliary data against the hash in the body and reads
// the only form the MVP accepts, a CIP-20 message: {674: {"msg": [+ text]}}
// (M-12).
func auxData(aux, hash []byte) ([]string, error) {
	switch {
	case len(aux) == 0 && hash == nil:
		return nil, nil
	case len(aux) == 0:
		return nil, fmt.Errorf("%w: auxiliary_data_hash without auxiliary data", ErrUnsupportedField)
	case hash == nil:
		return nil, fmt.Errorf("%w: auxiliary data without auxiliary_data_hash", ErrUnsupportedField)
	}
	if h := blake2b.Sum256(aux); !bytes.Equal(h[:], hash) {
		return nil, fmt.Errorf("%w: the auxiliary data do not match auxiliary_data_hash", ErrUnsupportedField)
	}
	if err := codec.CheckCanonical(aux); err != nil {
		return nil, fmt.Errorf("%w: auxiliary data: %v", ErrNotCanonical, err)
	}
	var x any
	if err := codec.Unmarshal(aux, &x); err != nil {
		return nil, fmt.Errorf("%w: auxiliary data: %v", ErrNotCanonical, err)
	}
	msg, err := message(x)
	if err != nil {
		return nil, fmt.Errorf("%w: auxiliary data: %v", ErrUnsupportedField, err)
	}
	return msg, nil
}

func message(x any) ([]string, error) {
	labels, ok := x.(map[any]any)
	if !ok || len(labels) != 1 {
		return nil, errors.New("only a CIP-20 message is supported")
	}
	m, ok := labels[uint64(cip20Label)].(map[any]any)
	if !ok || len(m) != 1 {
		return nil, errors.New("only a CIP-20 message is supported")
	}
	lines, ok := m["msg"].([]any)
	if !ok || len(lines) == 0 {
		return nil, errors.New("the CIP-20 message is not a list of strings")
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		s, ok := l.(string)
		if !ok || len(s) > maxMetadataText {
			return nil, fmt.Errorf("line %d of the message is not a string of at most %d bytes", i, maxMetadataText)
		}
		out[i] = s
	}
	return out, nil
}
