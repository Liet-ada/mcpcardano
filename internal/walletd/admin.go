// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/authz"
	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/hdkey"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/keystore"
	"github.com/Liet-ada/mcpcardano/internal/ledger"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// status is what `mcpcardano status` shows (section 6.7).
func (d *Daemon) status() *ipc.StatusReport {
	now := d.now()
	rep := &ipc.StatusReport{Unlocked: !d.store.Locked(), Wallets: []ipc.WalletStatus{}, Approvals: []ipc.Approval{}}
	if t := d.ledger.LastTime(); !t.IsZero() {
		rep.LastLedgerEntry = t.Unix()
	}
	for i := range d.st.Wallets {
		r := &d.st.Wallets[i]
		rep.Wallets = append(rep.Wallets, ipc.WalletStatus{Wallet: r.wire(d.cfg.Network),
			Session: wireSession(d.openSession(r.ID, now)), OpenDestinations: r.Policy.Destinations.Any})
	}
	for _, a := range d.pendingApprovals() {
		rep.Approvals = append(rep.Approvals, ipc.Approval{ID: a.id, WalletID: a.wallet, Spend: wireSpend(a.spend), ExpiresAt: a.expires.Unix()})
	}
	return rep
}

// unlock decrypts the key store. Wrong passwords go through the same doubling
// wait as authorizations; once unlocked, Unlock only checks the password.
func (d *Daemon) unlock(b *ipc.Unlock) error {
	defer clear(b.Password)
	err := d.authz.Attempt(func() error {
		if !d.store.Locked() {
			return d.checkPassword(b.Password)
		}
		err := d.store.Unlock(b.Password)
		if errors.Is(err, keystore.ErrWrongPassword) {
			return authz.ErrWrongPassword
		}
		return err
	})
	d.record("unlock", map[string]any{"ok": err == nil})
	return authError(err)
}

func (d *Daemon) checkPassword(password model.Secret) error {
	err := d.store.CheckPassword(password)
	if errors.Is(err, keystore.ErrWrongPassword) {
		return authz.ErrWrongPassword
	}
	return err
}

// authError turns an error of authz into the codes of the admin socket.
func authError(err error) error {
	var wait *authz.WaitError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, authz.ErrWrongPassword):
		return fail(ipc.AuthFailed, "wrong password")
	case errors.Is(err, authz.ErrExpired):
		return fail(ipc.AuthExpired, "the authorization expired or was used")
	case errors.Is(err, authz.ErrTooMany):
		return fail(ipc.RateLimited, "too many authorizations open")
	case errors.As(err, &wait):
		return fail(ipc.RateLimited, "wait %v before trying another password", wait.Wait.Round(time.Second))
	}
	return err
}

// prepared is what BeginAuthorization works out for an action: its wallet,
// the detail of the canonical message (section 6.3) and the summary the
// person reads, computed by the wallet.
type prepared struct {
	wallet  string
	det     any
	summary []string
}

// begin opens an authorization (section 6.2, steps 1 and 2).
func (d *Daemon) begin(b *ipc.BeginAuthorization) (*ipc.Challenge, error) {
	if err := d.unlocked(); err != nil {
		return nil, err
	}
	params, err := d.codec.DecodeParams(b)
	if err != nil {
		return nil, err
	}
	p, err := d.prepare(b.Action, params)
	if err != nil {
		authz.Wipe(params)
		return nil, err
	}
	au, err := d.authz.Begin(b.Action, model.WalletID(p.wallet), p.det, params)
	if err != nil {
		authz.Wipe(params)
		return nil, authError(err)
	}
	d.record("authorization.begun", map[string]any{"action": b.Action, "wallet_id": p.wallet})
	return &ipc.Challenge{AuthID: au.ID[:], Summary: fit(p.summary), Methods: []string{ipc.MethodPassword},
		ExpiresAt: au.Expires.Unix()}, nil
}

func (d *Daemon) prepare(action string, params ipc.Body) (prepared, error) {
	switch p := params.(type) {
	case *ipc.ApproveDraft:
		a, err := d.pendingApproval(p.ApprovalID)
		if err != nil {
			return prepared{}, err
		}
		r, err := d.wallet(a.wallet)
		if err != nil {
			return prepared{}, err
		}
		det := map[string]any{"body_hash": a.tx.ID[:], "spend": wireSpend(a.spend)}
		return prepared{a.wallet, det, d.txSummary(r, a)}, nil
	case *ipc.OpenSession:
		r, err := d.wallet(p.WalletID)
		if err != nil {
			return prepared{}, err
		}
		det := map[string]any{"seconds": p.Seconds, "max_lovelace": p.MaxLovelace}
		return prepared{r.ID, det, []string{fmt.Sprintf("Open a session on wallet %s (%s) for %v, up to %s",
			r.Label, r.ID, time.Duration(p.Seconds)*time.Second, ada(p.MaxLovelace))}}, nil
	case *ipc.WalletPolicy:
		r, err := d.wallet(p.WalletID)
		if err != nil {
			return prepared{}, err
		}
		lines := append([]string{fmt.Sprintf("Change the policy of wallet %s (%s) to:", r.Label, r.ID)}, policyLines(p.Mode, p.Policy)...)
		return prepared{r.ID, map[string]any{"hash": d.hash(p)}, lines}, nil
	case *ipc.Template:
		lines := append([]string{"Set the template of the wallets the agent creates to:"}, policyLines(p.Mode, p.Policy)...)
		return prepared{"", map[string]any{"hash": d.hash(p)}, lines}, nil
	case *ipc.WalletRef:
		r, err := d.wallet(p.WalletID)
		if err != nil {
			return prepared{}, err
		}
		what := "Unfreeze wallet %s (%s)"
		if action == ipc.ActShowRecoveryPhrase {
			what = "Show the recovery phrase of wallet %s (%s) in the terminal"
		}
		return prepared{r.ID, nil, []string{fmt.Sprintf(what, r.Label, r.ID)}}, nil
	case *ipc.ReleaseBudget:
		r, err := d.wallet(p.WalletID)
		if err != nil {
			return prepared{}, err
		}
		recs, sum, err := d.expired(r, p.Entries)
		if err != nil {
			return prepared{}, err
		}
		lines := []string{fmt.Sprintf("Release %s of the budget of wallet %s (%s), spent by %d transactions that expired:",
			ada(sum), r.Label, r.ID, len(recs))}
		for _, rec := range recs {
			lines = append(lines, fmt.Sprintf("  %x: %s, reserved %s, valid until slot %d",
				rec.TxID, ada(rec.Lovelace), rec.Time.UTC().Format(time.RFC3339), rec.TTL))
		}
		return prepared{r.ID, map[string]any{"entries": p.Entries, "lovelace": sum}, lines}, nil
	case *ipc.CreateWallet:
		t := d.st.Template
		lines := append([]string{fmt.Sprintf("Create wallet %s with the template:", p.Label)}, policyLines(t.Mode, t.Policy)...)
		return prepared{"", nil, lines}, nil
	case *ipc.RestoreWallet:
		entropy, err := hdkey.Entropy(p.Phrase)
		if err != nil {
			return prepared{}, fail(ipc.Malformed, "the recovery phrase is not valid")
		}
		defer clear(entropy)
		addr, err := address(d.cfg.Network, entropy)
		if err != nil {
			return prepared{}, err
		}
		return prepared{"", nil, []string{fmt.Sprintf("Restore wallet %s, with the template", p.Label),
			"Address: " + addr.Bech32()}}, nil
	}
	return prepared{}, fail(ipc.Malformed, "unknown action %s", action)
}

// expired returns the reservations a release names: each must be the
// wallet's, unreleased, and past its TTL by the wallet's clock (section 9.2).
func (d *Daemon) expired(r *record, ids [][]byte) ([]ledger.Record, uint64, error) {
	slot := d.slot()
	var recs []ledger.Record
	var sum uint64
	for _, id := range ids {
		rec, ok := d.ledger.Lookup([32]byte(id))
		if !ok || string(rec.WalletID) != r.ID || rec.Released || rec.TTL > slot {
			return nil, 0, fail(ipc.NotFound, "%x is not an expired_unconfirmed entry of %s", id, r.ID)
		}
		var err error
		if sum, err = model.Add(sum, rec.Lovelace); err != nil {
			return nil, 0, err
		}
		recs = append(recs, rec)
	}
	return recs, sum, nil
}

// hash is the hash of a policy with its mode, which the canonical message
// carries and the audit records.
func (d *Daemon) hash(b ipc.Body) []byte {
	raw, _ := d.codec.Encode(b) // a validated body always encodes
	h := sha256.Sum256(raw)
	return h[:]
}

// completeAuthorization checks the password against an open authorization
// and runs its action once (section 6.2, steps 4 and 5).
func (d *Daemon) completeAuthorization(ctx context.Context, b *ipc.CompleteAuthorization) (*ipc.Completed, error) {
	defer clear(b.Password)
	au, err := d.authz.Complete([authz.IDSize]byte(b.AuthID), func() error { return d.checkPassword(b.Password) })
	if err != nil {
		return nil, authError(err)
	}
	result, err := d.run(ctx, au)
	e := map[string]any{"action": au.Action, "wallet_id": string(au.Wallet)}
	if err != nil {
		e["error"] = string(d.failureCode(err))
	}
	d.record("authorization.completed", e)
	if err != nil {
		return nil, err
	}
	raw, err := d.codec.Encode(result)
	if err != nil {
		return nil, err
	}
	return &ipc.Completed{Result: raw}, nil
}

// run carries out an authorized action.
func (d *Daemon) run(ctx context.Context, au *authz.Authorization) (ipc.Body, error) {
	switch p := au.Params.(type) {
	case *ipc.ApproveDraft:
		return &ipc.Empty{}, d.approve(ctx, p.ApprovalID)
	case *ipc.OpenSession:
		r, err := d.wallet(p.WalletID)
		if err != nil {
			return nil, err
		}
		d.sessions[r.ID] = &session{expires: d.now().Add(time.Duration(p.Seconds) * time.Second), remaining: p.MaxLovelace}
		return &ipc.Empty{}, nil
	case *ipc.WalletPolicy:
		since := d.ledger.Seq()
		err := d.update(func(st *state) error {
			r := st.find(p.WalletID)
			if r == nil {
				return fail(ipc.UnknownWallet, "no wallet %s", p.WalletID)
			}
			// A new budget, or a wallet that starts having one, counts from
			// now (section 8.5).
			if p.Policy.Limits.Budget != r.Policy.Limits.Budget || p.Mode != r.Mode {
				r.BudgetSince = since
			}
			r.Mode, r.Policy = p.Mode, p.Policy
			return nil
		})
		if err != nil {
			return nil, err
		}
		h := d.hash(p)
		d.record("policy.changed", map[string]any{"wallet_id": p.WalletID, "hash": hex.EncodeToString(h)})
		return &ipc.PolicyHash{Hash: h}, nil
	case *ipc.Template:
		if err := d.update(func(st *state) error { st.Template = *p; return nil }); err != nil {
			return nil, err
		}
		h := d.hash(p)
		d.record("template.changed", map[string]any{"hash": hex.EncodeToString(h)})
		return &ipc.PolicyHash{Hash: h}, nil
	case *ipc.WalletRef:
		if au.Action == ipc.ActShowRecoveryPhrase {
			return d.recoveryPhrase(p.WalletID)
		}
		err := d.update(func(st *state) error {
			r := st.find(p.WalletID)
			if r == nil {
				return fail(ipc.UnknownWallet, "no wallet %s", p.WalletID)
			}
			r.Policy.Frozen = false
			return nil
		})
		if err == nil {
			d.record("unfrozen", map[string]any{"wallet_id": p.WalletID})
		}
		return &ipc.Empty{}, err
	case *ipc.ReleaseBudget:
		ids := make([][32]byte, len(p.Entries))
		for i, e := range p.Entries {
			ids[i] = [32]byte(e)
		}
		n, err := d.ledger.Release(ctx, model.WalletID(p.WalletID), ids, d.slot())
		if err != nil {
			return nil, fail(ipc.NotFound, "%v", err)
		}
		d.record("budget.released", map[string]any{"wallet_id": p.WalletID, "lovelace": n})
		return &ipc.Released{Lovelace: n}, nil
	case *ipc.CreateWallet:
		r, err := d.createWallet(p.Label, p.IdempotencyKey, model.ByPerson, nil)
		if err != nil {
			return nil, err
		}
		w := r.wire(d.cfg.Network)
		return &w, nil
	case *ipc.RestoreWallet:
		defer clear(p.Phrase)
		entropy, err := hdkey.Entropy(p.Phrase)
		if err != nil {
			return nil, fail(ipc.Malformed, "the recovery phrase is not valid")
		}
		defer clear(entropy)
		r, err := d.createWallet(p.Label, "", model.ByPerson, entropy)
		if err != nil {
			return nil, err
		}
		w := r.wire(d.cfg.Network)
		return &w, nil
	}
	return nil, fail(ipc.Malformed, "unknown action %s", au.Action)
}

func (d *Daemon) recoveryPhrase(id string) (ipc.Body, error) {
	if _, err := d.wallet(id); err != nil {
		return nil, err
	}
	entropy, err := d.store.Seed(model.WalletID(id))
	if err != nil {
		return nil, err
	}
	defer clear(entropy)
	phrase, err := hdkey.Phrase(entropy)
	if err != nil {
		return nil, err
	}
	d.record("recovery_phrase.shown", map[string]any{"wallet_id": id})
	return &ipc.RecoveryPhrase{Phrase: phrase}, nil
}

// reject rejects a pending approval: it lowers the risk, so it needs no
// authorization.
func (d *Daemon) reject(b *ipc.ApprovalRef) error {
	a, err := d.pendingApproval(b.ApprovalID)
	if err != nil {
		return err
	}
	a.status = ipc.ApprovalRejected
	d.record("approval.rejected", map[string]any{"approval_id": a.id, "by": "person"})
	return nil
}

// freeze freezes one wallet, or all of them, at once.
func (d *Daemon) freeze(b *ipc.Freeze) error {
	if b.WalletID != "" {
		if _, err := d.wallet(b.WalletID); err != nil {
			return err
		}
	}
	err := d.update(func(st *state) error {
		for i := range st.Wallets {
			if b.WalletID == "" || st.Wallets[i].ID == b.WalletID {
				st.Wallets[i].Policy.Frozen = true
			}
		}
		return nil
	})
	if err == nil {
		d.record("frozen", map[string]any{"wallet_id": b.WalletID})
	}
	return err
}

func (d *Daemon) closeSession(b *ipc.WalletRef) error {
	if _, err := d.wallet(b.WalletID); err != nil {
		return err
	}
	delete(d.sessions, b.WalletID)
	d.record("session.closed", map[string]any{"wallet_id": b.WalletID})
	return nil
}

// listExpired lists the expired_unconfirmed entries (section 9.2).
func (d *Daemon) listExpired(b *ipc.ListExpired) (*ipc.ExpiredList, error) {
	if b.WalletID != "" {
		if _, err := d.wallet(b.WalletID); err != nil {
			return nil, err
		}
	}
	l := &ipc.ExpiredList{Entries: []ipc.Expired{}}
	slot := d.slot()
	for _, r := range d.st.Wallets {
		if b.WalletID != "" && r.ID != b.WalletID {
			continue
		}
		for _, rec := range d.ledger.Pending(model.WalletID(r.ID), slot) {
			l.Entries = append(l.Entries, ipc.Expired{WalletID: r.ID, BodyHash: rec.TxID[:], Spend: recordSpend(rec),
				TTL: rec.TTL, Time: rec.Time.Unix()})
		}
	}
	return l, nil
}

func (d *Daemon) showPolicy(b *ipc.WalletRef) (*ipc.WalletPolicy, error) {
	r, err := d.wallet(b.WalletID)
	if err != nil {
		return nil, err
	}
	return &ipc.WalletPolicy{WalletID: r.ID, Mode: r.Mode, Policy: r.Policy}, nil
}

// showAudit returns entries of the audit log as written, for the CLI, which
// cannot read the wallet's files (section 6.7).
func (d *Daemon) showAudit(ctx context.Context, b *ipc.ShowAudit) (*ipc.AuditPage, error) {
	entries, _, err := audit.Read(ctx, d.cfg.auditPath(), audit.Options{Kind: "audit"})
	if err != nil {
		return nil, err
	}
	c := stateCodec()
	page := &ipc.AuditPage{Entries: []cborx.Raw{}}
	for _, e := range entries {
		if e.Seq < b.From {
			continue
		}
		if len(page.Entries) == int(b.Limit) {
			page.Next = e.Seq
			break
		}
		raw, err := c.Marshal(e)
		if err != nil {
			return nil, err
		}
		page.Entries = append(page.Entries, raw)
	}
	return page, nil
}

// verifyAudit checks the hash chains of the audit log and the spending
// record.
func (d *Daemon) verifyAudit(ctx context.Context) (*ipc.AuditCheck, error) {
	a, _, err := audit.Read(ctx, d.cfg.auditPath(), audit.Options{Kind: "audit"})
	if err != nil {
		return nil, err
	}
	l, _, err := audit.Read(ctx, d.cfg.ledgerPath(), audit.Options{Kind: ledger.Kind})
	if err != nil {
		return nil, err
	}
	return &ipc.AuditCheck{AuditEntries: uint64(len(a)), LedgerEntries: uint64(len(l))}, nil
}
