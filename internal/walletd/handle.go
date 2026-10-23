// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/policy"
)

// handle answers one request. Hello needs no lock; every other request takes
// the single lock, so they run one after another (section 9.1).
func (d *Daemon) handle(ctx context.Context, sock ipc.Socket, req ipc.Request) (ipc.Body, error) {
	body := ipc.NewRequest(req.T)
	if err := d.codec.DecodeBody(req.B, body); err != nil {
		return nil, err
	}
	if h, ok := body.(*ipc.Hello); ok {
		return d.hello(h)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch req.T {
	// The service socket (section 5.3).
	case ipc.MsgSignDraft:
		return d.signDraft(ctx, body.(*ipc.SignDraft))
	case ipc.MsgCreateWallet:
		return d.createWalletRequest(body.(*ipc.CreateWallet))
	case ipc.MsgGetApprovalStatus:
		return d.approvalStatus(body.(*ipc.GetApprovalStatus))
	case ipc.MsgGetPolicyStatus:
		return d.policyStatus(body.(*ipc.GetPolicyStatus))
	case ipc.MsgPing:
		return d.ping(), nil
	case ipc.MsgListWallets:
		return d.listWallets(), nil

	// The admin socket (section 6.7).
	case ipc.MsgStatus:
		return d.status()
	case ipc.MsgUnlock:
		return &ipc.Empty{}, d.unlock(body.(*ipc.Unlock))
	case ipc.MsgBeginAuthorization:
		return d.begin(body.(*ipc.BeginAuthorization))
	case ipc.MsgCompleteAuthorization:
		return d.completeAuthorization(ctx, body.(*ipc.CompleteAuthorization))
	case ipc.MsgReject:
		return &ipc.Empty{}, d.reject(body.(*ipc.ApprovalRef))
	case ipc.MsgFreeze:
		return &ipc.Empty{}, d.freeze(body.(*ipc.Freeze))
	case ipc.MsgCloseSession:
		return &ipc.Empty{}, d.closeSession(body.(*ipc.WalletRef))
	case ipc.MsgListExpired:
		return d.listExpired(body.(*ipc.ListExpired))
	case ipc.MsgShowPolicy:
		return d.showPolicy(body.(*ipc.WalletRef))
	case ipc.MsgShowTemplate:
		t := d.st.Template
		return &t, nil
	case ipc.MsgShowAudit:
		return d.showAudit(ctx, body.(*ipc.ShowAudit))
	case ipc.MsgVerifyAudit:
		return d.verifyAudit(ctx)
	}
	return nil, fail(ipc.Malformed, "no handler for %s", req.T)
}

func (d *Daemon) hello(h *ipc.Hello) (ipc.Body, error) {
	if h.Network != string(d.cfg.Network) {
		return nil, fail(ipc.NetworkMismatch, "the wallet serves %s", d.cfg.Network)
	}
	return &ipc.Hello{Software: "mcpcardano-wallet " + d.version, Network: string(d.cfg.Network)}, nil
}

// wallet returns the wallet with this id, or UNKNOWN_WALLET.
func (d *Daemon) wallet(id string) (*record, error) {
	if r := d.st.find(id); r != nil {
		return r, nil
	}
	return nil, fail(ipc.UnknownWallet, "no wallet %s", id)
}

// unlocked returns LOCKED while the key store is locked: what needs a key
// waits until the person unlocks it (decision 110).
func (d *Daemon) unlocked() error {
	if d.store.Locked() {
		return fail(ipc.Locked, "the key store is locked: the person must unlock the wallet")
	}
	return nil
}

// update changes the state on disk and then in memory, so memory never holds
// what the disk does not (section 7.4).
func (d *Daemon) update(change func(st *state) error) error {
	next := d.st
	next.Wallets = slices.Clone(d.st.Wallets)
	next.Created = maps.Clone(d.st.Created)
	next.Keys = slices.Clone(d.st.Keys)
	if err := change(&next); err != nil {
		return err
	}
	if err := next.save(d.cfg.statePath()); err != nil {
		return err
	}
	d.st = next
	return nil
}

// usage is what policy compares a transaction of a wallet with: its record
// and its open session, by the wallet's clock.
func (d *Daemon) usage(r *record, now time.Time) policy.Usage {
	u := d.ledger.Usage(model.WalletID(r.ID), now, r.BudgetSince)
	if s := d.openSession(r.ID, now); s != nil {
		u.Session = &policy.Session{Remaining: s.remaining}
	}
	return u
}

// openSession returns the open session of a wallet, dropping one that ended.
func (d *Daemon) openSession(id string, now time.Time) *session {
	s := d.sessions[id]
	if s != nil && !now.Before(s.expires) {
		delete(d.sessions, id)
		return nil
	}
	return s
}

func wireSession(s *session) *ipc.Session {
	if s == nil {
		return nil
	}
	return &ipc.Session{ExpiresAt: s.expires.Unix(), Remaining: s.remaining}
}

func wireSpend(s policy.Spend) ipc.Spend {
	return ipc.SpendFrom(model.Value{Lovelace: s.Lovelace, Assets: s.Assets})
}
