// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package cborx wraps fxamacker/cbor with the decoding limits and the
// canonical encoding used by every CBOR format of the project: the messages
// between processes (section 5 of the specification) and the persistent
// records (section 7). It is the only package that imports the CBOR library.
package cborx

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

// Raw is an already encoded CBOR item. It is written as is, so it must be
// canonical itself; CheckCanonical verifies that.
type Raw = cbor.RawMessage

// Tag is a CBOR tag (major type 6), such as 258 for the sets of Cardano
// transactions. Encoding it needs a codec with AllowTags.
type Tag = cbor.Tag

// ByteString is a byte string that can be a map key, such as an asset name.
// Canonical encoding orders such keys by length and then bytewise.
type ByteString = cbor.ByteString

// ErrNotCanonical reports input that decodes but does not re-encode to the
// same bytes under the canonical rules.
var ErrNotCanonical = errors.New("cborx: input is not canonical CBOR")

// Limits bound the work a decoder does on untrusted input.
type Limits struct {
	MaxDepth         int  // nested arrays, maps and tags
	MaxArrayElements int  // per array
	MaxMapPairs      int  // per map
	AllowTags        bool // CBOR tags (major type 6); Cardano transactions need them
}

// RecordLimits are the limits for the project's own formats: messages between
// processes and records on disk. None of them nests deeply or uses tags.
func RecordLimits() Limits {
	return Limits{MaxDepth: 16, MaxArrayElements: 4096, MaxMapPairs: 4096}
}

// Codec encodes canonically and decodes strictly within its limits.
// It is safe for concurrent use.
type Codec struct {
	enc cbor.EncMode
	dec cbor.DecMode
}

// New returns a codec with the given limits.
//
// Encoding follows the canonical form of RFC 7049, section 3.9, which is the
// one CIP-21 requires: definite lengths, shortest integers and map keys
// sorted by length and then bytewise.
//
// Decoding rejects duplicate map keys, indefinite lengths, invalid UTF-8,
// trailing bytes and, when decoding into a struct, unknown fields. Field
// names match case-sensitively.
func New(l Limits) (*Codec, error) {
	tags := cbor.TagsForbidden
	if l.AllowTags {
		tags = cbor.TagsAllowed
	}

	eo := cbor.CanonicalEncOptions()
	eo.TagsMd = tags
	enc, err := eo.EncMode()
	if err != nil {
		return nil, fmt.Errorf("cborx: encoder options: %w", err)
	}

	dec, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            tags,
		MaxNestedLevels:   l.MaxDepth,
		MaxArrayElements:  l.MaxArrayElements,
		MaxMapPairs:       l.MaxMapPairs,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
		MapKeyByteString:  cbor.MapKeyByteStringAllowed,
		DefaultMapType:    reflect.TypeOf(map[any]any(nil)),
	}.DecMode()
	if err != nil {
		return nil, fmt.Errorf("cborx: decoder options: %w", err)
	}
	return &Codec{enc: enc, dec: dec}, nil
}

// Marshal encodes v canonically.
func (c *Codec) Marshal(v any) ([]byte, error) {
	b, err := c.enc.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("cborx: encode: %w", err)
	}
	return b, nil
}

// Unmarshal decodes exactly one CBOR item from data into v.
func (c *Codec) Unmarshal(data []byte, v any) error {
	if err := c.dec.Unmarshal(data, v); err != nil {
		return fmt.Errorf("cborx: decode: %w", err)
	}
	return nil
}

// CheckCanonical decodes data and fails with ErrNotCanonical unless encoding
// the result gives back exactly the same bytes.
func (c *Codec) CheckCanonical(data []byte) error {
	var v any
	if err := c.Unmarshal(data, &v); err != nil {
		return err
	}
	b, err := c.Marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, data) {
		return ErrNotCanonical
	}
	return nil
}
