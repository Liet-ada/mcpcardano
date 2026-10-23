// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build ignore

// Command record derives keys, addresses and signatures from test phrases
// with cardano-cli, whose Icarus and BIP32-Ed25519 are an implementation apart
// from hdkey's (Haskell, over cardano-crypto), and writes them as the fixture
// of hdkey's cross vectors, internal/hdkey/testdata/cardano_cli.json (step 3
// of H-3). It needs cardano-cli 11 or later, which derives from a phrase:
//
//	go run test/cardano-cli/record.go -cli /path/to/cardano-cli
//
// The phrases are published test vectors and phrases that cardano-cli
// generates on the spot. None holds funds, and the keys are written to a
// temporary directory that is removed at the end.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/hdkey"
)

// Phrase is a test phrase and what cardano-cli derives from it.
type Phrase struct {
	Phrase string `json:"phrase"`
	Source string `json:"source"`
	Keys   []Key  `json:"keys"`
	// The base addresses of account 0: payment key 0 and stake key 0.
	AddressPreprod string `json:"address_preprod"`
	AddressMainnet string `json:"address_mainnet"`
}

// Key is the key of m/1852'/1815'/account'/role/index.
type Key struct {
	Account uint32 `json:"account"`
	Role    uint32 `json:"role"`
	Index   uint32 `json:"index"`
	// XPrv is cardano-cli's extended signing key: kL, kR, the verification
	// key and the chain code, 32 bytes each.
	XPrv string `json:"xprv"`
	// Signature is its witness of the transaction body.
	Signature string `json:"signature"`
}

// File is the fixture.
type File struct {
	Tool       string   `json:"tool"`
	Recorded   string   `json:"recorded"`
	TxBody     string   `json:"tx_body"`
	TxBodyHash string   `json:"tx_body_hash"`
	Phrases    []Phrase `json:"phrases"`
}

// paths are the keys derived from each phrase: those of a wallet, another
// address and another account, and the largest indices cardano-cli takes.
var paths = []struct{ account, role, index uint32 }{
	{0, 0, 0}, {0, 2, 0}, {0, 0, 1}, {7, 0, 19}, {1<<31 - 1, 0, 1<<31 - 1}, {1<<31 - 1, 2, 0},
}

// published are test phrases of CIP-3, cardano-serialization-lib and BIP-39.
var published = []struct{ phrase, source string }{
	{"eight country switch draw meat scout mystery blade tip drift useless good keep usage title", "CIP-3 (Icarus.md)"},
	{"test walk nut penalty hip pave soap entry language right filter choice", "cardano-serialization-lib"},
	{"art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy", "cardano-serialization-lib"},
	{"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "BIP-39 (trezor/python-mnemonic)"},
	{"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always", "BIP-39 (trezor/python-mnemonic)"},
	{"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote", "BIP-39 (trezor/python-mnemonic)"},
}

func main() {
	cli := flag.String("cli", "cardano-cli", "path to cardano-cli")
	out := flag.String("out", "internal/hdkey/testdata/cardano_cli.json", "fixture to write")
	flag.Parse()
	if err := record(*cli, *out); err != nil {
		fmt.Fprintln(os.Stderr, "record:", err)
		os.Exit(1)
	}
}

func record(cli, out string) error {
	dir, err := os.MkdirTemp("", "hdkey-vectors-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	c := cmd{cli: cli, dir: dir}

	version, err := c.run("--version")
	if err != nil {
		return err
	}
	f := File{Tool: strings.Join(strings.Fields(version), " "), Recorded: time.Now().UTC().Format(time.DateOnly)}

	// csl's 24-word phrase is published as its entropy.
	e, _ := hex.DecodeString("4e828f9a67ddcff0e6391ad4f26ddb7579f59ba14b6dd4baf63dcfdb9d2420da")
	p24, err := hdkey.Phrase(e)
	if err != nil {
		return err
	}
	phrases := append(published[:3:3], struct{ phrase, source string }{string(p24), "cardano-serialization-lib"})
	phrases = append(phrases, published[3:]...)
	for _, size := range []int{12, 15, 18, 21, 24, 12, 15, 18, 21, 24} {
		m, err := c.run("conway", "key", "generate-mnemonic", "--size", fmt.Sprint(size))
		if err != nil {
			return err
		}
		phrases = append(phrases, struct{ phrase, source string }{strings.Join(strings.Fields(m), " "), "cardano-cli generate-mnemonic"})
	}

	for i, ph := range phrases {
		p, err := c.derive(i, ph.phrase)
		if err != nil {
			return fmt.Errorf("phrase %d: %w", i, err)
		}
		p.Source = ph.source
		f.Phrases = append(f.Phrases, p)
	}

	// One transaction body, which every key signs: it pays the first
	// phrase's preprod address from a made-up input.
	body := filepath.Join(dir, "tx.raw")
	if _, err := c.run("conway", "transaction", "build-raw",
		"--tx-in", strings.Repeat("0", 64)+"#0", "--tx-out", f.Phrases[0].AddressPreprod+"+1000000",
		"--fee", "200000", "--out-file", body); err != nil {
		return err
	}
	if f.TxBody, err = envelope(body); err != nil {
		return err
	}
	txid, err := c.run("conway", "transaction", "txid", "--tx-body-file", body)
	if err != nil {
		return err
	}
	var id struct {
		TxHash string `json:"txhash"`
	}
	if err := json.Unmarshal([]byte(txid), &id); err != nil || len(id.TxHash) != 64 {
		return fmt.Errorf("txid: %q", txid)
	}
	f.TxBodyHash = id.TxHash
	for i := range f.Phrases {
		for j := range f.Phrases[i].Keys {
			k := &f.Phrases[i].Keys[j]
			w := filepath.Join(dir, "w.json")
			if _, err := c.run("conway", "transaction", "witness", "--tx-body-file", body,
				"--signing-key-file", c.skey(i, k.Account, k.Role, k.Index), "--out-file", w); err != nil {
				return err
			}
			if k.Signature, err = signature(w, k.XPrv[128:192]); err != nil {
				return err
			}
		}
	}

	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, append(b, '\n'), 0o644)
}

type cmd struct{ cli, dir string }

func (c cmd) run(args ...string) (string, error) {
	var stderr strings.Builder
	x := exec.Command(c.cli, args...)
	x.Stderr = &stderr
	b, err := x.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", c.cli, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(b), nil
}

func (c cmd) skey(i int, account, role, index uint32) string {
	return filepath.Join(c.dir, fmt.Sprintf("p%d-%d-%d-%d.skey", i, account, role, index))
}

// derive derives every path of the phrase, and the base addresses of
// account 0.
func (c cmd) derive(i int, phrase string) (Phrase, error) {
	p := Phrase{Phrase: phrase}
	m := filepath.Join(c.dir, fmt.Sprintf("p%d.txt", i))
	if err := os.WriteFile(m, []byte(phrase+"\n"), 0o600); err != nil {
		return p, err
	}
	for _, d := range paths {
		kind := "--payment-key-with-number"
		if d.role == 2 {
			kind = "--stake-key-with-number"
		}
		skey := c.skey(i, d.account, d.role, d.index)
		if _, err := c.run("conway", "key", "derive-from-mnemonic", "--key-output-text-envelope",
			kind, fmt.Sprint(d.index), "--account-number", fmt.Sprint(d.account),
			"--mnemonic-from-file", m, "--signing-key-file", skey); err != nil {
			return p, err
		}
		x, err := envelope(skey)
		if err != nil {
			return p, err
		}
		if x, err = byteString(x, 128); err != nil {
			return p, err
		}
		p.Keys = append(p.Keys, Key{Account: d.account, Role: d.role, Index: d.index, XPrv: x})
	}
	// address build takes the stake key, and so the payment key, without
	// the chain code.
	var vkeys [2]string
	for j, role := range []uint32{0, 2} {
		ext, vkey := filepath.Join(c.dir, "ext.vkey"), filepath.Join(c.dir, fmt.Sprintf("p%d-%d.vkey", i, role))
		if _, err := c.run("conway", "key", "verification-key", "--signing-key-file", c.skey(i, 0, role, 0),
			"--verification-key-file", ext); err != nil {
			return p, err
		}
		if _, err := c.run("conway", "key", "non-extended-key", "--extended-verification-key-file", ext,
			"--verification-key-file", vkey); err != nil {
			return p, err
		}
		vkeys[j] = vkey
	}
	for _, n := range []struct {
		net  []string
		dest *string
	}{{[]string{"--testnet-magic", "1"}, &p.AddressPreprod}, {[]string{"--mainnet"}, &p.AddressMainnet}} {
		a, err := c.run(append([]string{"conway", "address", "build",
			"--payment-verification-key-file", vkeys[0], "--stake-verification-key-file", vkeys[1]}, n.net...)...)
		if err != nil {
			return p, err
		}
		*n.dest = strings.TrimSpace(a)
	}
	return p, nil
}

// envelope reads the cborHex of a text envelope.
func envelope(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var e struct {
		CBORHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(b, &e); err != nil || e.CBORHex == "" {
		return "", fmt.Errorf("%s is not a text envelope", path)
	}
	return e.CBORHex, nil
}

// byteString strips the header of a CBOR byte string of n bytes, 24 to 255,
// written in hex.
func byteString(h string, n int) (string, error) {
	want := fmt.Sprintf("58%02x", n)
	if !strings.HasPrefix(h, want) || len(h) != 4+2*n {
		return "", fmt.Errorf("not a byte string of %d bytes: %.12s…", n, h)
	}
	return h[4:], nil
}

// signature reads the signature of a key witness, [vkey, signature], and
// checks that its verification key is vkey.
func signature(path, vkey string) (string, error) {
	h, err := envelope(path)
	if err != nil {
		return "", err
	}
	want := "825820" + vkey + "5840"
	if !strings.HasPrefix(h, want) || len(h) != len(want)+128 {
		return "", fmt.Errorf("%s is not a key witness of %.8s…", path, vkey)
	}
	return h[len(want):], nil
}
