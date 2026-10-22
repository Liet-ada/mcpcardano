// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"bytes"

	"github.com/Liet-ada/mcpcardano/internal/hdkey"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

func (d *Daemon) ping() *ipc.PingResult {
	res := &ipc.PingResult{Slot: d.slot()}
	for _, r := range d.st.Wallets {
		res.AnyFrozen = res.AnyFrozen || r.Policy.Frozen
	}
	return res
}

func (d *Daemon) listWallets() *ipc.WalletList {
	l := &ipc.WalletList{Wallets: []ipc.Wallet{}}
	for i := range d.st.Wallets {
		l.Wallets = append(l.Wallets, d.st.Wallets[i].wire(d.cfg.Network))
	}
	return l
}

// policyStatus is a wallet's mode, its policy and what it has spent (section
// 5.3). Pending lists its signed transactions whose TTL has not passed, for
// the server to follow after a restart (section 9.5).
func (d *Daemon) policyStatus(b *ipc.GetPolicyStatus) (*ipc.PolicyStatus, error) {
	r, err := d.wallet(b.WalletID)
	if err != nil {
		return nil, err
	}
	now := d.now()
	u := d.usage(r, now)
	ps := &ipc.PolicyStatus{Mode: r.Mode, Policy: r.Policy, Session: wireSession(d.openSession(r.ID, now)),
		SpentHour: u.Hour.Lovelace, SpentDay: u.Day.Lovelace, Pending: []ipc.PendingTx{}}
	if b := r.Policy.Limits.Budget; u.BudgetSpent < b {
		ps.BudgetRemaining = b - u.BudgetSpent
	}
	slot := d.slot()
	for _, rec := range d.ledger.Records(model.WalletID(r.ID)) {
		if rec.Signature != nil && !rec.Released && rec.TTL > slot {
			ps.Pending = append(ps.Pending, ipc.PendingTx{TxID: rec.TxID[:], TTL: rec.TTL})
		}
	}
	return ps, nil
}

// createWalletRequest is CreateWallet from the server: a wallet for the
// agent, with the template.
func (d *Daemon) createWalletRequest(b *ipc.CreateWallet) (*ipc.WalletCreated, error) {
	r, err := d.createWallet(b.Label, b.IdempotencyKey, model.ByAgent, nil)
	if err != nil {
		return nil, err
	}
	return &ipc.WalletCreated{Wallet: r.wire(d.cfg.Network), Policy: r.Policy}, nil
}

// createWallet creates a wallet with the template: a new seed, or the
// entropy of a restored phrase. The same idempotency key gives back the same
// wallet, also after a restart (section 9.4). The seed reaches the disk
// before the state names the wallet.
func (d *Daemon) createWallet(label, key string, by model.CreatedBy, entropy model.Secret) (*record, error) {
	if id, ok := d.st.Created[key]; ok && key != "" {
		return d.st.find(id), nil
	}
	if err := d.unlocked(); err != nil {
		return nil, err
	}
	if len(d.st.Wallets) >= maxWallets {
		return nil, fail(ipc.RateLimited, "the wallet keeps at most %d wallets", maxWallets)
	}
	if entropy == nil {
		var err error
		if entropy, err = hdkey.NewEntropy(nil); err != nil {
			return nil, err
		}
		defer clear(entropy)
	}
	addr, err := address(d.cfg.Network, entropy)
	if err != nil {
		return nil, err
	}
	for _, w := range d.st.Wallets {
		if bytes.Equal(w.Address, addr.Raw) {
			return nil, fail(ipc.Malformed, "wallet %s already has this address", w.ID)
		}
	}
	id, err := model.NewWalletID(nil)
	if err != nil {
		return nil, err
	}
	if err := d.store.PutSeed(id, entropy); err != nil {
		return nil, err
	}
	r := record{ID: string(id), Label: label, Mode: d.st.Template.Mode, Address: addr.Raw,
		CreatedBy: string(by), Policy: d.st.Template.Policy, BudgetSince: d.ledger.Seq()}
	err = d.update(func(st *state) error {
		st.Wallets = append(st.Wallets, r)
		if key != "" {
			st.Created[key] = r.ID
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// A wallet with open destinations is marked in the audit (section 3.7).
	d.record("wallet.created", map[string]any{"wallet_id": r.ID, "created_by": r.CreatedBy, "mode": r.Mode,
		"open_destinations": r.Policy.Destinations.Any})
	return d.st.find(r.ID), nil
}

// address is the address of the wallet whose seed is entropy.
func address(n model.Network, entropy []byte) (model.Address, error) {
	keys, err := hdkey.WalletKeys(entropy)
	if err != nil {
		return model.Address{}, err
	}
	defer keys.Wipe()
	return hdkey.BaseAddress(n, keys.Payment.PublicKey(), keys.Stake.PublicKey()), nil
}
