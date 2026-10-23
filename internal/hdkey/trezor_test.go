// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package hdkey

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestTrezor checks hdkey against the Trezor emulator, the hardware side of
// the cross vectors (testdata/trezor.json, which test/trezor/record.go
// writes from the phrases of testdata/cardano_cli.json of 12, 18 and 24 words,
// the only ones a Trezor takes).
//
// With the derivation ICARUS, the one of CIP-3 that hdkey implements, every
// key and every signature must match. ICARUS_TREZOR, the Trezor's default,
// matches too for 12 and 18 words; for 24 it gives other keys, since Trezor
// once fed the entropy with its checksum to PBKDF2 (CIP-3, Icarus.md). A
// phrase from wallet backup, 24 words, restores on a Trezor with ICARUS.
func TestTrezor(t *testing.T) {
	b, err := os.ReadFile("testdata/trezor.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		TxBodyHash string `json:"tx_body_hash"`
		Phrases    []struct {
			Phrase string `json:"phrase"`
			Keys   []struct {
				Derivation string `json:"derivation"`
				Account    uint32 `json:"account"`
				Role       uint32 `json:"role"`
				Index      uint32 `json:"index"`
				XPub       string `json:"xpub"`
				Signature  string `json:"signature"`
			} `json:"keys"`
		} `json:"phrases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	msg := unhex(f.TxBodyHash)
	var signed, differ int
	for _, p := range f.Phrases {
		words := len(strings.Fields(p.Phrase))
		e, err := Entropy([]byte(p.Phrase))
		if err != nil {
			t.Fatalf("%q: %v", p.Phrase, err)
		}
		root, err := Root(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range p.Keys {
			x := root.Derive(purpose, coinType, k.Account|Hardened, k.Role, k.Index)
			xpub := hex.EncodeToString(x.PublicKey()) + hex.EncodeToString(x.key().cc[:])
			same := xpub == k.XPub
			switch {
			case k.Derivation == "ICARUS" && !same,
				k.Derivation == "ICARUS_TREZOR" && words < 24 && !same:
				t.Errorf("%.20s… %s %d'/%d/%d: the key differs", p.Phrase, k.Derivation, k.Account, k.Role, k.Index)
			case k.Derivation == "ICARUS_TREZOR" && words == 24 && same:
				t.Errorf("%.20s… ICARUS_TREZOR with 24 words gives the Icarus key", p.Phrase)
			case k.Derivation == "ICARUS_TREZOR" && words == 24:
				differ++
			}
			if k.Signature != "" {
				signed++
				if sig := hex.EncodeToString(x.Sign(msg)); sig != k.Signature {
					t.Errorf("%.20s… %d'/%d/%d: the signature differs", p.Phrase, k.Account, k.Role, k.Index)
				}
			}
		}
	}
	// A fixture cut short would pass with nothing checked.
	if len(f.Phrases) < 10 || signed < 40 || differ == 0 {
		t.Errorf("%d phrases, %d signatures, %d keys of 24 words with ICARUS_TREZOR: the fixture is incomplete", len(f.Phrases), signed, differ)
	}
}
