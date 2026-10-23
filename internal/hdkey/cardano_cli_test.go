// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package hdkey

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// TestCardanoCLI checks hdkey against cardano-cli, whose Icarus and
// BIP32-Ed25519 are an implementation apart (testdata/cardano_cli.json, which
// test/cardano-cli/record.go writes). For each phrase: the extended keys of
// several paths, byte by byte, each one's signature of a transaction body,
// and the base addresses of account 0 on preprod and mainnet.
func TestCardanoCLI(t *testing.T) {
	b, err := os.ReadFile("testdata/cardano_cli.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		TxBodyHash string `json:"tx_body_hash"`
		Phrases    []struct {
			Phrase string `json:"phrase"`
			Keys   []struct {
				Account   uint32 `json:"account"`
				Role      uint32 `json:"role"`
				Index     uint32 `json:"index"`
				XPrv      string `json:"xprv"`
				Signature string `json:"signature"`
			} `json:"keys"`
			AddressPreprod string `json:"address_preprod"`
			AddressMainnet string `json:"address_mainnet"`
		} `json:"phrases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	words := map[int]bool{}
	msg := unhex(f.TxBodyHash)
	for _, p := range f.Phrases {
		words[len(strings.Fields(p.Phrase))] = true
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
			// cardano-cli writes kL, kR, the verification key and the chain code.
			xk := x.key()
			got := hex.EncodeToString(xk.kl[:]) + hex.EncodeToString(xk.kr[:]) +
				hex.EncodeToString(x.PublicKey()) + hex.EncodeToString(xk.cc[:])
			if got != k.XPrv {
				t.Errorf("%.20s… %d'/%d/%d: the key differs", p.Phrase, k.Account, k.Role, k.Index)
			}
			if sig := hex.EncodeToString(x.Sign(msg)); sig != k.Signature {
				t.Errorf("%.20s… %d'/%d/%d: the signature differs", p.Phrase, k.Account, k.Role, k.Index)
			}
		}
		keys, err := WalletKeys(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range []struct {
			net       model.Network
			hrp, want string
		}{{model.Preprod, "addr_test", p.AddressPreprod}, {model.Mainnet, "addr", p.AddressMainnet}} {
			a := BaseAddress(n.net, keys.Payment.PublicKey(), keys.Stake.PublicKey())
			if got := bech32(n.hrp, a.Raw); got != n.want {
				t.Errorf("%.20s… on %s: %s", p.Phrase, n.net, got)
			}
		}
	}
	// A fixture cut short would pass with nothing checked.
	if len(f.Phrases) < 15 || len(words) != 5 || len(f.Phrases[0].Keys) < 6 {
		t.Errorf("%d phrases of %d lengths: the fixture is incomplete", len(f.Phrases), len(words))
	}
}
