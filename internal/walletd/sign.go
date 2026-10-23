// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/hdkey"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/ledger"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/policy"
	"github.com/Liet-ada/mcpcardano/internal/txcheck"
)

// maxApprovals bounds the approvals waiting for the person.
const maxApprovals = 32

// keepApprovals is how long a finished approval stays, for the server to
// read its result.
const keepApprovals = 24 * time.Hour

// approval is a transaction of mode B above the threshold, waiting for the
// person (paper, section 5.4). It lives in memory: a restart drops it, which
// is the safe side (section 7.1).
type approval struct {
	id        string
	wallet    string
	tx        *txcheck.Tx
	spend     policy.Spend
	expires   time.Time // when the TTL passes: no approval after that
	status    string    // ipc.ApprovalPending, Approved, Rejected or Expired
	witnesses []ipc.Witness
}

// signDraft follows section 9.1: it reads the transaction with txcheck,
// evaluates it, writes its spend to the record and only then signs.
func (d *Daemon) signDraft(ctx context.Context, b *ipc.SignDraft) (res *ipc.SignDraftResult, err error) {
	defer func() { d.recordSign(b, res, err) }()
	r, err := d.wallet(b.WalletID)
	if err != nil {
		return nil, err
	}
	if err := d.unlocked(); err != nil {
		return nil, err
	}
	tx, err := txcheck.Decode(b.Body, b.AuxData)
	switch {
	case errors.Is(err, txcheck.ErrTooLarge):
		return nil, fail(ipc.TooLarge, "%v", err)
	case errors.Is(err, txcheck.ErrNotCanonical):
		return rejected(ipc.TxNotCanonical, err.Error(), policy.Spend{}), nil
	case err != nil:
		return rejected(ipc.TxUnsupportedField, err.Error(), policy.Spend{}), nil
	}

	// A body seen before gets the same answer and counts once (section 9.4,
	// M-13). A reservation that a crash left unsigned is signed now, without
	// counting it again (section 9.1). A frozen wallet gives no signature,
	// not even one it gave before.
	if rec, ok := d.ledger.Lookup(tx.ID); ok {
		if string(rec.WalletID) != r.ID {
			return nil, fail(ipc.Malformed, "the transaction belongs to another wallet")
		}
		if r.Policy.Frozen {
			return &ipc.SignDraftResult{Status: ipc.Rejected, Spend: recordSpend(rec),
				Rejection: &ipc.Error{Code: ipc.Frozen, Detail: ipc.Detail(string(policy.RuleFrozen) + ": the wallet is frozen")}}, nil
		}
		w, err := d.finish(ctx, r, rec)
		if err != nil {
			return nil, err
		}
		return &ipc.SignDraftResult{Status: ipc.Signed, Witnesses: w, Spend: recordSpend(rec)}, nil
	}
	now := d.now()
	if a := d.pendingApprovalOf(tx.ID, now); a != nil {
		return &ipc.SignDraftResult{Status: ipc.PendingApproval, ApprovalID: a.id, Spend: wireSpend(a.spend)}, nil
	}

	wallet, pol := r.model(d.cfg.Network)
	v := policy.Evaluate(policy.Input{Wallet: wallet, Policy: pol, View: tx.View(wallet.Address),
		CurrentSlot: d.slot(), Usage: d.usage(r, now)})
	switch v.Status {
	case policy.Blocked:
		return rejected(rejectionCode(v.Code), string(v.Rule)+": "+v.Detail, v.Spend), nil
	case policy.NeedsApproval:
		a, err := d.newApproval(r, tx, v.Spend, now)
		if err != nil {
			return nil, err
		}
		return &ipc.SignDraftResult{Status: ipc.PendingApproval, ApprovalID: a.id, Spend: wireSpend(v.Spend)}, nil
	}
	w, err := d.reserveAndSign(ctx, r, tx, v.Spend)
	if err != nil {
		return nil, err
	}
	return &ipc.SignDraftResult{Status: ipc.Signed, Witnesses: w, Spend: wireSpend(v.Spend)}, nil
}

func (d *Daemon) recordSign(b *ipc.SignDraft, res *ipc.SignDraftResult, err error) {
	e := map[string]any{"wallet_id": b.WalletID, "draft_id": b.DraftID}
	switch {
	case err != nil:
		e["error"] = string(d.failureCode(err))
	case res != nil:
		e["status"], e["lovelace"] = res.Status, res.Spend.Lovelace
		if res.Rejection != nil {
			e["code"], e["detail"] = string(res.Rejection.Code), res.Rejection.Detail
		}
		if res.ApprovalID != "" {
			e["approval_id"] = res.ApprovalID
		}
	}
	d.record("sign_draft", e)
}

func (d *Daemon) failureCode(err error) ipc.Code {
	var e *ipc.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ipc.Internal
}

func rejected(code ipc.Code, detail string, s policy.Spend) *ipc.SignDraftResult {
	return &ipc.SignDraftResult{Status: ipc.Rejected, Rejection: &ipc.Error{Code: code, Detail: ipc.Detail(detail)}, Spend: wireSpend(s)}
}

// rejectionCode turns the code of a blocked verdict into a code of SignDraft.
// A transaction for another network is POLICY_BLOCKED with the rule network:
// NETWORK_MISMATCH is the greeting's (decision 110).
func rejectionCode(c policy.Code) ipc.Code {
	switch c {
	case policy.CodeFrozen:
		return ipc.Frozen
	case policy.CodeNeedsSession:
		return ipc.NeedsSession
	case policy.CodeBudgetExceeded:
		return ipc.BudgetExceeded
	case policy.CodeTTLTooLong:
		return ipc.TTLTooLong
	}
	return ipc.PolicyBlocked
}

// reserveAndSign writes the spend, signs and writes the signature: steps 5 to
// 7 of section 9.1. No signature leaves the wallet without its spend on disk.
func (d *Daemon) reserveAndSign(ctx context.Context, r *record, tx *txcheck.Tx, s policy.Spend) ([]ipc.Witness, error) {
	view := tx.View(model.Address{})
	d.crash("before-reserve")
	rec, err := d.ledger.Reserve(ctx, model.WalletID(r.ID), tx.ID, s, view.Fee, *view.TTL)
	if err != nil {
		return nil, err
	}
	d.crash("after-reserve")
	if ses := d.openSession(r.ID, d.now()); ses != nil {
		ses.remaining -= min(ses.remaining, s.Lovelace)
	}
	return d.finish(ctx, r, rec)
}

// finish signs a reservation and writes the signature, or gives back the
// signature written already. Ed25519 is deterministic: the same key and the
// same body give the same signature.
func (d *Daemon) finish(ctx context.Context, r *record, rec ledger.Record) ([]ipc.Witness, error) {
	vkey, sig, err := d.sign(r, rec.TxID)
	if err != nil {
		return nil, err
	}
	if rec.Signature == nil {
		if err := d.ledger.Sign(ctx, rec.TxID, sig); err != nil {
			return nil, err
		}
		d.crash("after-sign")
	} else if !bytes.Equal(rec.Signature, sig) {
		return nil, fmt.Errorf("walletd: the signature of %x differs from the recorded one", rec.TxID)
	}
	return []ipc.Witness{{VKey: vkey, Signature: sig}}, nil
}

// sign signs a transaction id with the wallet's payment key, derived from its
// seed for this signature only. The key must give the wallet's address.
func (d *Daemon) sign(r *record, txID [32]byte) (vkey, sig []byte, err error) {
	entropy, err := d.store.Seed(model.WalletID(r.ID))
	if err != nil {
		return nil, nil, err
	}
	defer clear(entropy)
	keys, err := hdkey.WalletKeys(entropy)
	if err != nil {
		return nil, nil, err
	}
	defer keys.Wipe()
	vkey = keys.Payment.PublicKey()
	if a := hdkey.BaseAddress(d.cfg.Network, vkey, keys.Stake.PublicKey()); !bytes.Equal(a.Raw, r.Address) {
		return nil, nil, fmt.Errorf("walletd: the seed of %s does not give its address", r.ID)
	}
	return vkey, keys.Payment.Sign(txID[:]), nil
}

func recordSpend(rec ledger.Record) ipc.Spend {
	return ipc.SpendFrom(model.Value{Lovelace: rec.Lovelace, Assets: rec.Assets})
}

// newApproval keeps a transaction for the person to approve until its TTL.
func (d *Daemon) newApproval(r *record, tx *txcheck.Tx, s policy.Spend, now time.Time) (*approval, error) {
	pending := 0
	for id, a := range d.approvals {
		d.expire(a, now)
		switch {
		case a.status == ipc.ApprovalPending:
			pending++
		case now.After(a.expires.Add(keepApprovals)):
			delete(d.approvals, id)
		}
	}
	if pending >= maxApprovals {
		return nil, fail(ipc.RateLimited, "%d approvals are waiting for the person", pending)
	}
	id, err := model.NewApprovalID(nil)
	if err != nil {
		return nil, err
	}
	ttl := *tx.View(model.Address{}).TTL
	a := &approval{id: string(id), wallet: r.ID, tx: tx, spend: s, status: ipc.ApprovalPending,
		expires: d.cfg.Network.Clock().Time(ttl)}
	d.approvals[a.id] = a
	return a, nil
}

// expire marks a pending approval whose TTL passed.
func (d *Daemon) expire(a *approval, now time.Time) {
	if a.status == ipc.ApprovalPending && !now.Before(a.expires) {
		a.status = ipc.ApprovalExpired
	}
}

// pendingApprovalOf returns the pending approval of a transaction, if any.
func (d *Daemon) pendingApprovalOf(txID [32]byte, now time.Time) *approval {
	for _, a := range d.approvals {
		d.expire(a, now)
		if a.status == ipc.ApprovalPending && a.tx.ID == txID {
			return a
		}
	}
	return nil
}

func (d *Daemon) approvalStatus(b *ipc.GetApprovalStatus) (*ipc.ApprovalStatus, error) {
	a := d.approvals[b.ApprovalID]
	if a == nil {
		return nil, fail(ipc.NotFound, "no approval %s", b.ApprovalID)
	}
	d.expire(a, d.now())
	return &ipc.ApprovalStatus{Status: a.status, Witnesses: a.witnesses, ExpiresAt: a.expires.Unix()}, nil
}

// approve signs an approved transaction. The person's approval lifts only
// the threshold: every other rule is evaluated again, now, and a transaction
// that no longer passes ends rejected (decision 110).
func (d *Daemon) approve(ctx context.Context, id string) error {
	a, err := d.pendingApproval(id)
	if err != nil {
		return err
	}
	r, err := d.wallet(a.wallet)
	if err != nil {
		return err
	}
	wallet, pol := r.model(d.cfg.Network)
	now := d.now()
	v := policy.Evaluate(policy.Input{Wallet: wallet, Policy: pol, View: a.tx.View(wallet.Address),
		CurrentSlot: d.slot(), Usage: d.usage(r, now)})
	if v.Status == policy.Blocked {
		a.status = ipc.ApprovalRejected
		d.record("approval.rejected", map[string]any{"approval_id": id, "rule": string(v.Rule)})
		return fail(rejectionCode(v.Code), "%s: %s", v.Rule, v.Detail)
	}
	w, err := d.reserveAndSign(ctx, r, a.tx, v.Spend)
	if err != nil {
		return err
	}
	a.status, a.witnesses = ipc.ApprovalApproved, w
	d.record("approval.approved", map[string]any{"approval_id": id, "tx_id": hex.EncodeToString(a.tx.ID[:])})
	return nil
}

// pendingApproval returns an approval that is still pending, or NOT_FOUND.
func (d *Daemon) pendingApproval(id string) (*approval, error) {
	a := d.approvals[id]
	if a == nil {
		return nil, fail(ipc.NotFound, "no approval %s", id)
	}
	d.expire(a, d.now())
	if a.status != ipc.ApprovalPending {
		return nil, fail(ipc.NotFound, "the approval is %s", a.status)
	}
	return a, nil
}

// pendingApprovals lists the approvals waiting for the person, by id.
func (d *Daemon) pendingApprovals() []*approval {
	now := d.now()
	var out []*approval
	for _, a := range d.approvals {
		d.expire(a, now)
		if a.status == ipc.ApprovalPending {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, func(x, y *approval) int { return strings.Compare(x.id, y.id) })
	return out
}
