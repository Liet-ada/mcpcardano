// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package signer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// ErrRejected reports that the person rejected the action on the device.
var ErrRejected = errors.New("signer: rejected on the hardware wallet")

// ErrNoDevice reports that cardano-hw-go found no hardware wallet.
var ErrNoDevice = errors.New("signer: no hardware wallet found; connect and unlock a Ledger with the Cardano app open, or a Trezor")

// deviceTimeout bounds one action on the device, which waits for the person.
const deviceTimeout = 5 * time.Minute

// Device is a hardware wallet. Keys live on it: the signer only ever holds
// signing files, which name a derivation path and a public key.
type Device interface {
	// KeyGen exports the public keys of PaymentPath and StakePath into dir:
	// payment.vkey, stake.vkey and their signing files.
	KeyGen(ctx context.Context, dir string) error
	// ShowAddress shows the wallet's address on the device, for the person to
	// compare with the one on the screen.
	ShowAddress(ctx context.Context, address string) error
	// Witness asks the device to sign an unsigned transaction with the keys
	// in dir and returns the payment key's witness.
	Witness(ctx context.Context, n model.Network, tx []byte, dir string) (vkey, signature []byte, err error)
	// Version names the device and the version of its firmware or Cardano
	// app. It may ask the person to confirm on the device, or, the first
	// time with a Trezor that uses THP, for a pairing code on the terminal.
	Version(ctx context.Context) (string, error)
}

// envelope is the JSON text envelope of cardano-cli files.
type envelope struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CBORHex     string `json:"cborHex"`
}

// HWCLI drives a hardware wallet through cardano-hw-go (section 6.6), or
// through cardano-hw-cli, which takes the same arguments.
type HWCLI struct {
	Path string // the cardano-hw-go executable
}

func (h HWCLI) run(ctx context.Context, args ...string) error {
	_, err := h.output(ctx, args...)
	return err
}

// output runs the program and returns what it printed, on stdout and
// stderr.
func (h HWCLI) output(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, deviceTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.Path, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		text := strings.TrimSpace(out.String())
		low := strings.ToLower(text)
		if strings.Contains(low, "reject") || strings.Contains(low, "cancel") || strings.Contains(low, "denied by user") {
			return "", fmt.Errorf("%w: %s", ErrRejected, lastError(text))
		}
		// No device. cardano-hw-cli may instead fall back to its Keystone
		// transport, which takes any device with the USB vendor ID Keystone
		// shares with Trezor (0x1209) when Trezor Connect fails, as it does
		// with the Safe 7. Its error then names a Keystone.
		if strings.Contains(low, "find hw transport") || strings.Contains(low, "check that your keystone device is connected") {
			return "", ErrNoDevice
		}
		return "", fmt.Errorf("signer: %s %s: %v: %s", filepath.Base(h.Path), args[0]+" "+args[1], err, lastError(text))
	}
	return strings.TrimSpace(out.String()), nil
}

// Version implements Device: the last line the program prints, after
// any request to confirm on the device.
func (h HWCLI) Version(ctx context.Context) (string, error) {
	out, err := h.output(ctx, "device", "version")
	if err != nil {
		return "", err
	}
	return out[strings.LastIndexByte(out, '\n')+1:], nil
}

// lastError returns the program's last error in one line: from its last
// line that starts with "Error:" to the end, without stack frames.
func lastError(s string) string {
	lines := strings.Split(s, "\n")
	start := len(lines) - 1
	for i := start; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "Error:") {
			start = i
			break
		}
	}
	var msg []string
	for _, l := range lines[start:] {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "at ") {
			msg = append(msg, l)
		}
	}
	s = strings.Join(msg, " ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// KeyGen implements Device.
func (h HWCLI) KeyGen(ctx context.Context, dir string) error {
	return h.run(ctx, "address", "key-gen",
		"--path", PaymentPath, "--path", StakePath,
		"--verification-key-file", filepath.Join(dir, "payment.vkey"),
		"--verification-key-file", filepath.Join(dir, "stake.vkey"),
		"--hw-signing-file", filepath.Join(dir, "payment.hwsfile"),
		"--hw-signing-file", filepath.Join(dir, "stake.hwsfile"))
}

// ShowAddress implements Device.
func (h HWCLI) ShowAddress(ctx context.Context, address string) error {
	dir, err := os.MkdirTemp("", "mcpcardano-addr")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "payment.addr")
	if err := os.WriteFile(file, []byte(address), 0o600); err != nil {
		return err
	}
	return h.run(ctx, "address", "show", "--payment-path", PaymentPath, "--staking-path", StakePath, "--address-file", file)
}

// Witness implements Device. The stake key goes in as a change output key,
// so the device recognizes the change to the wallet's own address.
func (h HWCLI) Witness(ctx context.Context, n model.Network, tx []byte, dir string) ([]byte, []byte, error) {
	work, err := os.MkdirTemp("", "mcpcardano-sign")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(work)
	txFile, witnessFile := filepath.Join(work, "tx.json"), filepath.Join(work, "payment.witness")
	b, _ := json.Marshal(envelope{Type: "Unwitnessed Tx ConwayEra", Description: "Ledger Cddl Format", CBORHex: hex.EncodeToString(tx)})
	if err := os.WriteFile(txFile, b, 0o600); err != nil {
		return nil, nil, err
	}
	payment, stake := filepath.Join(dir, "payment.hwsfile"), filepath.Join(dir, "stake.hwsfile")
	args := append([]string{"transaction", "witness"}, networkArgs(n)...)
	args = append(args, "--tx-file", txFile, "--hw-signing-file", payment,
		"--change-output-key-file", payment, "--change-output-key-file", stake, "--out-file", witnessFile)
	if err := h.run(ctx, args...); err != nil {
		return nil, nil, err
	}
	return readWitness(witnessFile)
}

func networkArgs(n model.Network) []string {
	switch n {
	case model.Mainnet:
		return []string{"--mainnet"}
	case model.Preview:
		return []string{"--testnet-magic", "2"}
	default:
		return []string{"--testnet-magic", "1"}
	}
}

func codec() *cborx.Codec {
	c, err := cborx.New(cborx.Limits{MaxDepth: 8, MaxArrayElements: 16, MaxMapPairs: 16, AllowTags: true})
	if err != nil {
		panic(err) // constant limits
	}
	return c
}

func readEnvelope(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("signer: %s: %w", filepath.Base(path), err)
	}
	return hex.DecodeString(e.CBORHex)
}

// readWitness reads a key witness, [0, [vkey, signature]] in its envelope.
func readWitness(path string) ([]byte, []byte, error) {
	raw, err := readEnvelope(path)
	if err != nil {
		return nil, nil, err
	}
	var w struct {
		_           struct{} `cbor:",toarray"`
		Kind        uint64
		VKeyWitness struct {
			_         struct{} `cbor:",toarray"`
			VKey      []byte
			Signature []byte
		}
	}
	if err := codec().Unmarshal(raw, &w); err != nil || w.Kind != 0 || len(w.VKeyWitness.VKey) != 32 || len(w.VKeyWitness.Signature) != 64 {
		return nil, nil, fmt.Errorf("signer: the device's witness is not a key witness")
	}
	return w.VKeyWitness.VKey, w.VKeyWitness.Signature, nil
}

// ReadVKey reads a verification key file: a byte string of the key, or of
// the key and its chain code.
func ReadVKey(path string) ([]byte, error) {
	raw, err := readEnvelope(path)
	if err != nil {
		return nil, err
	}
	var key []byte
	if err := codec().Unmarshal(raw, &key); err != nil || (len(key) != 32 && len(key) != 64) {
		return nil, fmt.Errorf("signer: %s is not a verification key", filepath.Base(path))
	}
	return key[:32], nil
}
