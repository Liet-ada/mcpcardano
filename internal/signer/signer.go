// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package signer is the mode A signer (section 6.6 of the specification). It
// finds the drafts that wait for the person, takes each to the hardware
// wallet through cardano-hw-cli and hands the signature to the server, which
// checks it belongs exactly to the draft. The device's screen is the check
// that counts: it shows destinations, amounts and fee.
//
// For each wallet the signer keeps only cardano-hw-cli's signing files,
// which name a derivation path and a public key; never a private key.
package signer

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/mcpclient"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Caller is the part of the MCP client the signer uses.
type Caller interface {
	Call(ctx context.Context, tool string, args, out any) error
}

// Signer signs the drafts of mode A wallets on a hardware wallet.
type Signer struct {
	Client Caller
	Device Device
	// KeysDir holds a directory per wallet address with its signing files.
	KeysDir string
	// Notify tells the person; nil means no notifications.
	Notify func(title, text string)
	Logger *slog.Logger
}

// DefaultKeysDir is where the signing files live: the person's
// configuration directory.
func DefaultKeysDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "mcpcardano", "hw"), nil
}

// draft is the part of the server's draft view the signer reads.
type draft struct {
	DraftID  string `json:"draft_id"`
	WalletID string `json:"wallet_id"`
	State    string `json:"state"`
	TxCBOR   string `json:"tx_cbor"`
	Summary  struct {
		TxID    string `json:"tx_id"`
		Fee     string `json:"fee"`
		Outputs []struct {
			Address  string `json:"address"`
			Own      *bool  `json:"own"`
			Lovelace string `json:"lovelace"`
			Assets   []any  `json:"assets"`
		} `json:"outputs"`
	} `json:"summary"`
}

// Describe says in one line what the person is about to confirm.
func (d draft) Describe() string {
	var parts []string
	for _, o := range d.Summary.Outputs {
		if o.Own != nil && *o.Own {
			continue
		}
		p := o.Lovelace + " lovelace to " + o.Address
		if len(o.Assets) > 0 {
			p += fmt.Sprintf(" with %d tokens", len(o.Assets))
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		parts = append(parts, "back to the wallet")
	}
	return fmt.Sprintf("Draft %s: %s; fee %s lovelace", d.DraftID, strings.Join(parts, "; "), d.Summary.Fee)
}

// Result is what came of one draft.
type Result struct {
	DraftID string
	State   string // the draft's state after the signer's work
}

// Sign takes one draft to the hardware wallet and hands its signature to the
// server. If the person rejects it on the device, the draft is cancelled
// with the reason hw_rejected (section 6.6) and Sign returns ErrRejected.
// show, if not nil, receives the line to confirm before the device asks.
func (s *Signer) Sign(ctx context.Context, id string, show func(string)) (Result, error) {
	var d draft
	if err := s.Client.Call(ctx, "get_draft", map[string]any{"draft_id": id, "include_tx": true}, &d); err != nil {
		return Result{}, err
	}
	if d.State != "pending_approval" {
		return Result{}, fmt.Errorf("signer: draft %s is %s, not waiting for a signature", id, d.State)
	}
	network, address, err := s.walletAddress(ctx, d.WalletID)
	if err != nil {
		return Result{}, err
	}
	dir := filepath.Join(s.KeysDir, address)
	if _, err := os.Stat(filepath.Join(dir, "payment.hwsfile")); err != nil {
		return Result{}, fmt.Errorf("signer: no signing files for %s; run `mcpcardano signer init`", address)
	}
	tx, err := hex.DecodeString(d.TxCBOR)
	if err != nil {
		return Result{}, fmt.Errorf("signer: the draft's transaction is not hex")
	}
	txID, err := bodyHash(tx)
	if err != nil || hex.EncodeToString(txID[:]) != d.Summary.TxID {
		return Result{}, fmt.Errorf("signer: the transaction is not the one the summary describes")
	}
	if show != nil {
		show(d.Describe())
	}
	vkey, sig, err := s.Device.Witness(ctx, network, tx, dir)
	if errors.Is(err, ErrRejected) {
		var after draft
		if cerr := s.Client.Call(ctx, "cancel_draft", map[string]any{"draft_id": id, "reason": "hw_rejected"}, &after); cerr != nil {
			return Result{}, fmt.Errorf("%w; cancelling the draft: %v", err, cerr)
		}
		return Result{DraftID: id, State: after.State}, err
	}
	if err != nil {
		return Result{}, err
	}
	if !ed25519.Verify(vkey, txID[:], sig) {
		return Result{}, errors.New("signer: the device's signature is not for this transaction")
	}
	witnesses, err := codec().Marshal(map[uint64]any{0: cborx.Tag{Number: 258, Content: []any{[]any{vkey, sig}}}})
	if err != nil {
		return Result{}, err
	}
	var after draft
	if err := s.Client.Call(ctx, "submit_signed_transaction", map[string]any{"draft_id": id, "witness_set": hex.EncodeToString(witnesses)}, &after); err != nil {
		return Result{}, err
	}
	return Result{DraftID: id, State: after.State}, nil
}

// bodyHash returns the id of a transaction: the hash of its body.
func bodyHash(tx []byte) ([32]byte, error) {
	c, err := cborx.New(cborx.Limits{MaxDepth: 64, MaxArrayElements: 1 << 16, MaxMapPairs: 1 << 16, AllowTags: true})
	if err != nil {
		return [32]byte{}, err
	}
	var parts []cborx.Raw
	if err := c.Unmarshal(tx, &parts); err != nil || len(parts) != 4 {
		return [32]byte{}, errors.New("signer: not a transaction")
	}
	return blake2b.Sum256(parts[0]), nil
}

func (s *Signer) walletAddress(ctx context.Context, walletID string) (model.Network, string, error) {
	var list struct {
		Wallets []struct {
			WalletID string `json:"wallet_id"`
			Network  string `json:"network"`
			Address  string `json:"address"`
			Mode     string `json:"mode"`
		} `json:"wallets"`
	}
	if err := s.Client.Call(ctx, "list_wallets", map[string]any{}, &list); err != nil {
		return "", "", err
	}
	for _, w := range list.Wallets {
		if w.WalletID == walletID {
			if w.Mode != string(model.ModeA) {
				return "", "", fmt.Errorf("signer: wallet %s is not in mode A", walletID)
			}
			return model.Network(w.Network), w.Address, nil
		}
	}
	return "", "", fmt.Errorf("signer: the server has no wallet %s", walletID)
}

// CheckDevice asks the hardware wallet for its version, so that the person
// meets what it asks for, a confirmation or a pairing code, at the start
// and at the terminal, not in the middle of a payment. It logs the outcome;
// a failure does not stop the signer, which tries the device again with
// each draft.
func (s *Signer) CheckDevice(ctx context.Context) error {
	s.log().Info("checking the hardware wallet; confirm on it if it asks")
	v, err := s.Device.Version(ctx)
	if err != nil {
		s.log().Warn("hardware wallet not ready", "err", err)
		return err
	}
	s.log().Info("hardware wallet ready", "device", v)
	return nil
}

// Run looks for drafts waiting for the person every `every` and signs them
// one at a time, until ctx ends. It takes each draft to the device once; a
// draft whose signing failed waits for `mcpcardano sign`.
func (s *Signer) Run(ctx context.Context, every time.Duration) error {
	tried := map[string]bool{}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		var list struct {
			Drafts []struct {
				DraftID string `json:"draft_id"`
			} `json:"drafts"`
		}
		if err := s.Client.Call(ctx, "list_drafts", map[string]any{"state": "pending_approval"}, &list); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		for _, d := range list.Drafts {
			if tried[d.DraftID] {
				continue
			}
			tried[d.DraftID] = true
			s.signOne(ctx, d.DraftID)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (s *Signer) signOne(ctx context.Context, id string) {
	r, err := s.Sign(ctx, id, func(line string) {
		s.notify("Confirm on your hardware wallet", line)
		s.log().Info("waiting for the hardware wallet", "draft", id, "what", line)
	})
	switch {
	case errors.Is(err, ErrRejected):
		s.notify("Payment rejected", "Draft "+id+" was rejected on the device.")
		s.log().Info("rejected on the device", "draft", id, "state", r.State)
	case err != nil:
		var te *mcpclient.ToolError
		if errors.As(err, &te) {
			err = fmt.Errorf("%s: %s", te.Code, te.Message)
		}
		s.notify("Payment not signed", "Draft "+id+": "+err.Error())
		s.log().Error("signing", "draft", id, "err", err)
	default:
		s.notify("Payment sent", "Draft "+id+" is "+r.State+".")
		s.log().Info("signed and sent", "draft", id, "state", r.State)
	}
}

func (s *Signer) log() *slog.Logger {
	if s.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Logger
}

func (s *Signer) notify(title, text string) {
	if s.Notify != nil {
		s.Notify(title, text)
	}
}

// SystemNotify shows a notification of the operating system: Notification
// Center on macOS, notify-send on Linux. Failures are ignored.
func SystemNotify(title, text string) {
	switch runtime.GOOS {
	case "darwin":
		quote := func(s string) string {
			return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
		}
		exec.Command("osascript", "-e", "display notification "+quote(text)+" with title "+quote("mcpcardano: "+title)).Run()
	default:
		exec.Command("notify-send", "mcpcardano: "+title, text).Run()
	}
}

// Init exports the public keys of the hardware wallet's first address,
// derives the address, keeps the signing files in KeysDir and shows the
// address on the device for the person to compare (section 3.2).
func (s *Signer) Init(ctx context.Context, n model.Network) (string, error) {
	work, err := os.MkdirTemp("", "mcpcardano-init")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	if err := s.Device.KeyGen(ctx, work); err != nil {
		return "", err
	}
	payment, err := ReadVKey(filepath.Join(work, "payment.vkey"))
	if err != nil {
		return "", err
	}
	stake, err := ReadVKey(filepath.Join(work, "stake.vkey"))
	if err != nil {
		return "", err
	}
	address, err := BaseAddress(n, payment, stake)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(s.KeysDir, address)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, f := range []string{"payment.vkey", "stake.vkey", "payment.hwsfile", "stake.hwsfile"} {
		b, err := os.ReadFile(filepath.Join(work, f))
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			return "", err
		}
	}
	if err := s.Device.ShowAddress(ctx, address); err != nil {
		return address, fmt.Errorf("signer: showing the address on the device: %w", err)
	}
	return address, nil
}
