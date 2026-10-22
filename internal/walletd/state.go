// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/policy"
)

// stateVersion is the format of state.cbor.
const stateVersion = 1

// maxWallets bounds the wallets of the wallet process: the agent creates them
// without asking, and state.cbor must stay within the limits of its decoder.
const maxWallets = 1000

// record is a wallet in state.cbor: its data, its policy with its mode, and
// the entry of the spending record after which its budget counts (decision
// 107). The network is the wallet process's.
type record struct {
	ID          string     `cbor:"id"`
	Label       string     `cbor:"label"`
	Mode        string     `cbor:"mode"`
	Address     []byte     `cbor:"address"`
	CreatedBy   string     `cbor:"created_by"`
	Policy      ipc.Policy `cbor:"policy"`
	BudgetSince uint64     `cbor:"budget_since"`
}

// state is state.cbor (section 7.1). Only the person changes it, through the
// admin socket, except for the wallets the agent creates with the template
// and for freezing, which only lowers the risk.
type state struct {
	V        uint64       `cbor:"v"`
	Wallets  []record     `cbor:"wallets"`
	Template ipc.Template `cbor:"template"`
	// Created maps the idempotency key of each CreateWallet to its wallet,
	// so that a repeated request gives back the same one (section 9.4).
	Created map[string]string `cbor:"created"`
}

func newState(n model.Network) state {
	t := policy.DefaultTemplate(n)
	return state{
		V:        stateVersion,
		Wallets:  []record{},
		Template: ipc.Template{Mode: string(t.Mode), Policy: ipc.PolicyFrom(t.Policy)},
		Created:  map[string]string{},
	}
}

func stateCodec() *cborx.Codec {
	c, err := cborx.New(cborx.RecordLimits())
	if err != nil {
		panic(err) // constant limits
	}
	return c
}

// loadState reads state.cbor, or returns a new state with the default
// template if there is none yet.
func loadState(path string, n model.Network) (state, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return newState(n), nil
	}
	if err != nil {
		return state{}, err
	}
	var st state
	if err := stateCodec().Unmarshal(data, &st); err != nil {
		return state{}, fmt.Errorf("walletd: %s: %w", filepath.Base(path), err)
	}
	if err := st.check(n); err != nil {
		return state{}, fmt.Errorf("walletd: %s: %w", filepath.Base(path), err)
	}
	if st.Created == nil {
		st.Created = map[string]string{}
	}
	return st, nil
}

// check validates a state read from disk: a state the wallet would not write
// is not one it starts on.
func (st *state) check(n model.Network) error {
	if st.V != stateVersion {
		return fmt.Errorf("version %d, want %d", st.V, stateVersion)
	}
	if len(st.Wallets) > maxWallets {
		return fmt.Errorf("%d wallets, at most %d", len(st.Wallets), maxWallets)
	}
	if err := st.Template.Validate(); err != nil {
		return fmt.Errorf("template: %v", err)
	}
	seen := map[string]bool{}
	for i := range st.Wallets {
		r := &st.Wallets[i]
		w := r.wire(n)
		if err := w.Validate(); err != nil {
			return fmt.Errorf("wallet %d: %v", i, err)
		}
		if _, err := baseAddress(r.Address); err != nil {
			return fmt.Errorf("wallet %d: %v", i, err)
		}
		if err := r.Policy.Validate(); err != nil {
			return fmt.Errorf("wallet %d: %v", i, err)
		}
		if seen[r.ID] {
			return fmt.Errorf("wallet %s twice", r.ID)
		}
		seen[r.ID] = true
	}
	for key, id := range st.Created {
		if !seen[id] || key == "" {
			return fmt.Errorf("idempotency key of an unknown wallet")
		}
	}
	return nil
}

// save writes state.cbor atomically (section 7.4).
func (st *state) save(path string) error {
	data, err := stateCodec().Marshal(st)
	if err != nil {
		return err
	}
	return writeFile(path, data)
}

// find returns the wallet with this id.
func (st *state) find(id string) *record {
	for i := range st.Wallets {
		if st.Wallets[i].ID == id {
			return &st.Wallets[i]
		}
	}
	return nil
}

// wire returns the wallet as the protocol carries it.
func (r *record) wire(n model.Network) ipc.Wallet {
	return ipc.Wallet{ID: r.ID, Label: r.Label, Network: string(n), Mode: r.Mode,
		Address: r.Address, CreatedBy: r.CreatedBy, Frozen: r.Policy.Frozen}
}

// model returns the wallet and its policy as policy evaluates them.
func (r *record) model(n model.Network) (model.Wallet, model.Policy) {
	addr, _ := baseAddress(r.Address) // checked when it was stored
	w := model.Wallet{ID: model.WalletID(r.ID), Label: r.Label, Network: n, Mode: model.Mode(r.Mode),
		Address: addr, CreatedBy: model.CreatedBy(r.CreatedBy)}
	return w, r.Policy.Model()
}

// baseAddress reads the address of a wallet of the wallet process: always a
// base address with two key credentials (CIP-19, type 0), the one hdkey
// derives (section 3.2).
func baseAddress(raw []byte) (model.Address, error) {
	if len(raw) != 57 || raw[0]>>4 != 0 {
		return model.Address{}, errors.New("not a base address with key credentials")
	}
	stake := model.Credential{Kind: model.KeyHash, Hash: [28]byte(raw[29:57])}
	return model.Address{Raw: raw, Type: 0, NetworkID: raw[0] & 0x0f,
		Payment: model.Credential{Kind: model.KeyHash, Hash: [28]byte(raw[1:29])}, Stake: &stake}, nil
}

// writeFile replaces path atomically (section 7.4): it writes a temporary
// file in the same directory with mode 0600, syncs it, renames it over the
// original and syncs the directory, so the file is either the old one or the
// new one, never half written.
func writeFile(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
