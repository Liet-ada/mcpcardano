// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package chain is the only package that imports gouroboros (rule 4 of
// section 2.3 of the specification). It turns the ledger's types into the
// project's: addresses into model.Address, and defines the UTxO and protocol
// parameter types the rest of the server uses. Later steps add the phase-1
// rules and the node protocols here.
package chain

import (
	"sync"

	gcbor "github.com/blinklabs-io/gouroboros/cbor"
)

// MaxNestedLevels is the nesting limit for decoding chain data. It follows
// from the size of a transaction, so the server keeps gouroboros's value
// rather than lowering it (paper, section 4.1).
const MaxNestedLevels = 16384

var configureOnce sync.Once

// Configure fixes gouroboros's decoding limits. gouroboros caches its decoders
// on first use, so the server calls Configure at start-up before decoding
// anything. These variables are the one exception to the rule against global
// state (section 1.2).
func Configure() {
	configureOnce.Do(func() {
		gcbor.MaxNestedLevels = MaxNestedLevels
		gcbor.MaxUntrustedNestedLevels = MaxNestedLevels
	})
}
