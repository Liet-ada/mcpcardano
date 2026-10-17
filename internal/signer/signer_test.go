// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// TestBaseAddress checks the address encoding against bytes decoded by an
// independent bech32 implementation.
func TestBaseAddress(t *testing.T) {
	cases := []struct{ address, hex string }{
		{"addr_test1qrkk3gdqruhhn9ya44xcgqrkpe9fp737e7c9hgs06xturtqpkdqaf773t2wv0v2fdhxlequtxwq7gm66sfg5u630nvyq8l53zd",
			"00ed68a1a01f2f79949dad4d8400760e4a90fa3ecfb05ba20fd197c1ac01b341d4fbd15a9cc7b1496dcdfc838b3381e46f5a82514e6a2f9b08"},
		{"addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x",
			"019493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e337b62cfff6403a06a3acbc34f8c46003c69fe79a3628cefa9c47251"},
	}
	for _, c := range cases {
		raw, _ := hex.DecodeString(c.hex)
		hrp := "addr_test"
		if raw[0]&0x0f == 1 {
			hrp = "addr"
		}
		if got := bech32(hrp, raw); got != c.address {
			t.Errorf("got %s, want %s", got, c.address)
		}
	}
	key := bytes.Repeat([]byte{1}, 32)
	a, err := BaseAddress(model.Preprod, key, key)
	if err != nil || !strings.HasPrefix(a, "addr_test1q") {
		t.Errorf("BaseAddress: %s, %v", a, err)
	}
	if _, err := BaseAddress(model.Preprod, key[:31], key); err == nil {
		t.Error("a short key was accepted")
	}
}

// softDevice signs with a key held in memory, standing in for the hardware
// wallet. reject makes the person say no.
type softDevice struct {
	key    ed25519.PrivateKey
	reject bool
	other  bool // sign another transaction
	seen   []byte
}

func (d *softDevice) KeyGen(_ context.Context, dir string) error {
	pub := d.key.Public().(ed25519.PublicKey)
	for _, name := range []string{"payment", "stake"} {
		raw, _ := codec().Marshal(append([]byte(pub), make([]byte, 32)...)) // key and chain code
		b, _ := json.Marshal(envelope{Type: "PaymentExtendedVerificationKeyShelley_ed25519_bip32", CBORHex: hex.EncodeToString(raw)})
		os.WriteFile(filepath.Join(dir, name+".vkey"), b, 0o600)
		os.WriteFile(filepath.Join(dir, name+".hwsfile"), []byte(`{"path":"`+name+`"}`), 0o600)
	}
	return nil
}

func (d *softDevice) ShowAddress(context.Context, string) error { return nil }

func (d *softDevice) Witness(_ context.Context, _ model.Network, tx []byte, _ string) ([]byte, []byte, error) {
	d.seen = tx
	if d.reject {
		return nil, nil, fmt.Errorf("%w: Action cancelled by user", ErrRejected)
	}
	id, err := bodyHash(tx)
	if err != nil {
		return nil, nil, err
	}
	if d.other {
		id[0] ^= 1
	}
	return d.key.Public().(ed25519.PublicKey), ed25519.Sign(d.key, id[:]), nil
}

// fakeServer answers the tools the signer calls.
type fakeServer struct {
	tx        []byte
	state     string
	address   string
	calls     []string
	witnesses string
	reason    string
}

func (f *fakeServer) Call(_ context.Context, tool string, args, out any) error {
	f.calls = append(f.calls, tool)
	a := args.(map[string]any)
	var answer any
	switch tool {
	case "get_draft":
		id := blake2b.Sum256(mustBody(f.tx))
		answer = map[string]any{"draft_id": a["draft_id"], "wallet_id": "w_1", "state": f.state, "tx_cbor": hex.EncodeToString(f.tx),
			"summary": map[string]any{"tx_id": hex.EncodeToString(id[:]), "fee": "180000", "outputs": []any{
				map[string]any{"address": "addr_test1shop", "own": false, "lovelace": "5000000"}}}}
	case "list_wallets":
		answer = map[string]any{"wallets": []any{map[string]any{"wallet_id": "w_1", "network": "preprod", "address": f.address, "mode": "A"}}}
	case "submit_signed_transaction":
		f.witnesses = a["witness_set"].(string)
		answer = map[string]any{"draft_id": a["draft_id"], "state": "submitted"}
	case "cancel_draft":
		f.reason = a["reason"].(string)
		answer = map[string]any{"draft_id": a["draft_id"], "state": "rejected"}
	default:
		return fmt.Errorf("unexpected tool %s", tool)
	}
	b, _ := json.Marshal(answer)
	return json.Unmarshal(b, out)
}

func mustBody(tx []byte) []byte {
	var parts []cborx.Raw
	c, _ := cborx.New(cborx.Limits{MaxDepth: 64, MaxArrayElements: 1 << 16, MaxMapPairs: 1 << 16, AllowTags: true})
	c.Unmarshal(tx, &parts)
	return parts[0]
}

// unsignedTx is a small transaction as the server sends it to sign.
func unsignedTx(t *testing.T) []byte {
	c := codec()
	body, _ := c.Marshal(map[uint64]any{0: cborx.Tag{Number: 258, Content: []any{[]any{make([]byte, 32), uint64(0)}}}, 1: []any{}, 2: uint64(180000)})
	tx, err := c.Marshal([]any{cborx.Raw(body), map[uint64]any{}, true, nil})
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func setup(t *testing.T) (*Signer, *softDevice, *fakeServer) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	dev := &softDevice{key: key}
	keys := t.TempDir()
	s := &Signer{Device: dev, KeysDir: keys}
	address, err := s.Init(t.Context(), model.Preprod)
	if err != nil {
		t.Fatal(err)
	}
	srv := &fakeServer{tx: unsignedTx(t), state: "pending_approval", address: address}
	s.Client = srv
	return s, dev, srv
}

func TestInit(t *testing.T) {
	s, dev, _ := setup(t)
	pub := dev.key.Public().(ed25519.PublicKey)
	want, _ := BaseAddress(model.Preprod, pub, pub)
	for _, f := range []string{"payment.vkey", "stake.vkey", "payment.hwsfile", "stake.hwsfile"} {
		info, err := os.Stat(filepath.Join(s.KeysDir, want, f))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestSign(t *testing.T) {
	s, dev, srv := setup(t)
	var shown string
	r, err := s.Sign(t.Context(), "d_1", func(line string) { shown = line })
	if err != nil || r.State != "submitted" {
		t.Fatalf("sign: %+v, %v", r, err)
	}
	if !bytes.Equal(dev.seen, srv.tx) || !strings.Contains(shown, "5000000 lovelace to addr_test1shop") {
		t.Errorf("the device saw another transaction, or the person read %q", shown)
	}
	raw, _ := hex.DecodeString(srv.witnesses)
	var set map[uint64]cborx.Tag
	if err := codec().Unmarshal(raw, &set); err != nil || set[0].Number != 258 {
		t.Errorf("witness set %x: %v", raw, err)
	}
}

func TestSignRejected(t *testing.T) {
	s, dev, srv := setup(t)
	dev.reject = true
	r, err := s.Sign(t.Context(), "d_1", nil)
	if !errors.Is(err, ErrRejected) || r.State != "rejected" || srv.reason != "hw_rejected" {
		t.Fatalf("got %+v, %v, reason %q", r, err, srv.reason)
	}
}

func TestSignRefuses(t *testing.T) {
	s, dev, srv := setup(t)
	dev.other = true
	if _, err := s.Sign(t.Context(), "d_1", nil); err == nil || srv.witnesses != "" {
		t.Errorf("a signature for another transaction was sent: %v", err)
	}
	dev.other = false
	srv.state = "draft"
	if _, err := s.Sign(t.Context(), "d_1", nil); err == nil {
		t.Error("signed a draft nobody authorized")
	}
	srv.state = "pending_approval"
	srv.address = "addr_test1unknown"
	if _, err := s.Sign(t.Context(), "d_1", nil); err == nil || !strings.Contains(err.Error(), "signer init") {
		t.Errorf("a wallet without signing files: %v", err)
	}
}

// TestHWCLI runs the adapter against a stand-in cardano-hw-cli that checks
// its arguments and answers as the real one does.
func TestHWCLI(t *testing.T) {
	dir := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	tx := unsignedTx(t)
	id := blake2b.Sum256(mustBody(tx))
	w, _ := codec().Marshal([]any{uint64(0), []any{[]byte(key.Public().(ed25519.PublicKey)), ed25519.Sign(key, id[:])}})
	witness, _ := json.Marshal(envelope{Type: "TxWitness ConwayEra", Description: "Key Witness ShelleyEra", CBORHex: hex.EncodeToString(w)})
	os.WriteFile(filepath.Join(dir, "witness.json"), witness, 0o600)
	script := filepath.Join(dir, "cardano-hw-cli")
	os.WriteFile(script, []byte(`#!/bin/sh
echo "$@" > "`+dir+`/args"
if [ -f "`+dir+`/fail" ]; then cat "`+dir+`/fail" >&2; exit 1; fi
while [ $# -gt 0 ]; do
  if [ "$1" = "--out-file" ]; then cp "`+dir+`/witness.json" "$2"; fi
  if [ "$1" = "--tx-file" ]; then cp "$2" "`+dir+`/tx.json"; fi
  shift
done
`), 0o700)
	h := HWCLI{Path: script}
	vkey, sig, err := h.Witness(t.Context(), model.Preprod, tx, "/keys")
	if err != nil || !ed25519.Verify(vkey, id[:], sig) {
		t.Fatalf("witness: %v", err)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	for _, want := range []string{"transaction witness --testnet-magic 1", "--hw-signing-file /keys/payment.hwsfile",
		"--change-output-key-file /keys/payment.hwsfile --change-output-key-file /keys/stake.hwsfile"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("arguments %q lack %q", args, want)
		}
	}
	txFile, _ := os.ReadFile(filepath.Join(dir, "tx.json"))
	var e envelope
	if json.Unmarshal(txFile, &e) != nil || e.Type != "Unwitnessed Tx ConwayEra" || e.CBORHex != hex.EncodeToString(tx) {
		t.Errorf("tx file %s", txFile)
	}
	// The failures, as cardano-hw-cli 1.19.1 prints them.
	for _, c := range []struct {
		name, out string
		want      error
		has       string
	}{
		{"a rejection on the device", "Error: Failure_ActionCancelled: Action cancelled by user\n", ErrRejected, ""},
		{"no device", "Error: Error occurred while trying to find hw transport, make sure Ledger or Trezor or Keystone is connected to your computer\n", ErrNoDevice, ""},
		{"a Trezor Safe 7, taken as a Keystone", `Error: releaseInterface error: invalid state
    at WebUSBDevice._releaseInterface (/snapshot/cardano-hw-cli/node_modules/usb/dist/webusb/webusb-device.js:400:19)
    at Generator.next (<anonymous>)
Error: The requested operation failed. Check that your Keystone device is connected.
Details: Error: open error: Error: LIBUSB_ERROR_NO_DEVICE
`, ErrNoDevice, ""},
		{"a Ledger without the Cardano app", `Error: The requested operation failed. Check that your Ledger device is connected, unlocked and with Cardano app running.
Details: TransportStatusError: Ledger device: CLA_NOT_SUPPORTED (0x6e00)
`, nil, "Error: The requested operation failed. Check that your Ledger device is connected, unlocked and with Cardano app running. Details: TransportStatusError: Ledger device: CLA_NOT_SUPPORTED (0x6e00)"},
	} {
		os.WriteFile(filepath.Join(dir, "fail"), []byte(c.out), 0o600)
		_, _, err := h.Witness(t.Context(), model.Preprod, tx, "/keys")
		switch {
		case err == nil:
			t.Errorf("%s: no error", c.name)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		case c.has != "" && (!strings.HasSuffix(err.Error(), c.has) || errors.Is(err, ErrNoDevice) || errors.Is(err, ErrRejected)):
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
