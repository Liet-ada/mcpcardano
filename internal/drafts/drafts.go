// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package drafts keeps the server's drafts: their states (section 3.4 of the
// specification), the reservation of their inputs and their expiry. It
// creates a draft in the last step of section 8.1: the transaction comes from
// txbuild, the verdict from policy, and the inputs are reserved in the same
// critical section, so two drafts never take the same UTxO.
//
// Drafts live in memory only and are lost on restart, which is the safe side
// (section 7.1): a lost draft expires and frees its inputs.
package drafts

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/policy"
	"github.com/Liet-ada/mcpcardano/internal/txbuild"
	"github.com/Liet-ada/mcpcardano/internal/txdecode"
)

const (
	// DefaultTTLSeconds is the validity of a draft when the agent gives
	// none, within the policy's maximum. Drafts reserve UTxOs, so it is
	// short (paper, section 7.4).
	DefaultTTLSeconds = 30 * 60
	// Retention is how long a draft stays readable with get_draft after it
	// reaches a final state or is confirmed.
	Retention = 24 * time.Hour
	// MaxWitnessBytes bounds the witness set a signer may submit.
	MaxWitnessBytes = 4096
)

var (
	// ErrNotFound reports an unknown draft id, or one already forgotten.
	ErrNotFound = errors.New("drafts: draft not found")
	// ErrExpired reports a draft whose time ran out.
	ErrExpired = errors.New("drafts: draft expired")
	// ErrTooManyDrafts reports a wallet at the policy's maximum of live
	// drafts; cancelling one frees a place.
	ErrTooManyDrafts = errors.New("drafts: too many live drafts")
	// ErrNoFreeUTxOs reports funds that would suffice if other drafts did
	// not hold them.
	ErrNoFreeUTxOs = errors.New("drafts: the free UTxOs are not enough")
	// ErrMismatch reports a signature that does not belong to the draft.
	ErrMismatch = errors.New("drafts: the signature does not match the draft")
	// ErrModeNotAvailable reports an authorization of the wrong kind for the
	// wallet's mode: the signer of mode A, or the wallet process of B and C.
	ErrModeNotAvailable = errors.New("drafts: mode not available")
)

// BlockedError reports a transaction the policy blocks. No draft is created
// (paper, section 5.1); the verdict names the rule.
type BlockedError struct {
	Verdict policy.Verdict
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("drafts: blocked by %s: %s", e.Verdict.Rule, e.Verdict.Detail)
}

// Draft is a snapshot of a draft. Its slices and the transaction are never
// modified after they are set, so a snapshot is safe to keep.
type Draft struct {
	ID      model.DraftID
	Wallet  model.WalletID
	Network model.Network
	Mode    model.Mode
	Intent  model.Intent

	Tx      *txbuild.Tx // the unsigned transaction, its inputs and its decoding
	Summary txdecode.Summary
	Verdict policy.Verdict

	State      State
	ExpiresAt  time.Time // when the TTL slot begins
	Reason     string    // why it was cancelled, rejected or failed
	Depth      uint32    // confirmations, once confirmed
	Signed     []byte    // the signed transaction, from signed on
	ApprovalID string    // the wallet's approval, in modes B and C

	CreatedAt time.Time
	UpdatedAt time.Time

	params chain.ProtocolParameters // to check the signature
}

// Request is everything a new draft needs. The caller reads the wallet's
// UTxOs, the parameters and the tip from the data source, outside any lock.
type Request struct {
	Wallet model.Wallet
	Policy model.Policy
	Intent model.Intent

	// UTxOs are every UTxO of the wallet; the store takes out the reserved
	// ones. Tokens the policy lets leave count as verified for input
	// selection (section 8.2, step 6).
	UTxOs   []chain.UTxO
	Params  chain.ProtocolParameters
	TipSlot uint64
	// TTLSeconds is what the agent asked for; zero means the default.
	TTLSeconds uint32
	// Verified marks, in the summary, the tokens the person listed in the
	// policy of any wallet (decision 84); nil marks none.
	Verified func(model.AssetID) bool
	// Usage is what the wallet process reports a wallet of mode B or C has
	// spent, for the draft's verdict. The wallet decides again, with its own
	// record, when it is asked to sign.
	Usage policy.Usage
}

// Store holds the drafts of every wallet.
type Store struct {
	now  func() time.Time
	rand io.Reader

	// mu protects drafts and reserved. Building runs under it, so a UTxO is
	// reserved before any other build can see it as free.
	mu       sync.Mutex
	drafts   map[model.DraftID]*Draft
	reserved map[chain.TxIn]model.DraftID
}

// New returns an empty store. now is the server's own clock; rand, if nil,
// is crypto/rand, and feeds the draft ids.
func New(now func() time.Time, random io.Reader) *Store {
	if random == nil {
		random = rand.Reader
	}
	return &Store{now: now, rand: random, drafts: map[model.DraftID]*Draft{}, reserved: map[chain.TxIn]model.DraftID{}}
}

// Create builds, checks and evaluates a transaction for r.Intent, reserves
// its inputs and keeps it as a new draft (section 8.1, step 10). A blocked
// verdict creates nothing and comes back as a *BlockedError.
func (s *Store) Create(r Request) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweep(now)

	live := 0
	for _, d := range s.drafts {
		if d.Wallet == r.Wallet.ID && d.State.Live() {
			live++
		}
	}
	if live >= int(r.Policy.Limits.MaxLiveDrafts) {
		return Draft{}, fmt.Errorf("%w: %d of %d", ErrTooManyDrafts, live, r.Policy.Limits.MaxLiveDrafts)
	}

	in := txbuild.Input{
		Network:  r.Wallet.Network,
		Wallet:   r.Wallet.Address,
		Intent:   r.Intent,
		Params:   r.Params,
		UTxO:     r.Policy.UTxO,
		MaxFee:   r.Policy.Limits.MaxFee,
		TipSlot:  r.TipSlot,
		Verified: func(a model.AssetID) bool { _, ok := r.Policy.Assets[a]; return ok },
	}
	in.TTLSeconds = r.TTLSeconds
	if in.TTLSeconds == 0 {
		in.TTLSeconds = DefaultTTLSeconds
		if m := r.Policy.Limits.MaxTTLSeconds; m > 0 {
			in.TTLSeconds = min(in.TTLSeconds, m)
		}
	}
	for _, u := range r.UTxOs {
		if _, held := s.reserved[u.In]; held {
			if !u.Value.HasAssets() {
				in.ReservedADAOnly++
			}
			continue
		}
		in.Available = append(in.Available, u)
	}
	tx, err := txbuild.Build(in)
	if err != nil {
		if errors.Is(err, txbuild.ErrInsufficientFunds) || errors.Is(err, txbuild.ErrNoFreeUTxOs) {
			// Would the wallet pay it if no draft held its UTxOs?
			all := in
			all.Available, all.ReservedADAOnly = r.UTxOs, 0
			if _, errAll := txbuild.Build(all); errAll == nil {
				return Draft{}, fmt.Errorf("%w: %w", ErrNoFreeUTxOs, err)
			}
		}
		return Draft{}, err
	}

	clock := chain.Clock(r.Wallet.Network)
	verdict := policy.Evaluate(policy.Input{
		Wallet:      r.Wallet,
		Policy:      r.Policy,
		View:        tx.Decoded.View(r.Wallet.Address),
		CurrentSlot: clock.Slot(now),
		Usage:       r.Usage,
	})
	if verdict.Status == policy.Blocked {
		return Draft{}, &BlockedError{Verdict: verdict}
	}
	summary, err := tx.Decoded.Summary(txdecode.Options{Wallet: &r.Wallet.Address, Spent: tx.Inputs, Verified: r.Verified})
	if err != nil {
		return Draft{}, err
	}
	id, err := model.NewDraftID(s.rand)
	if err != nil {
		return Draft{}, err
	}
	d := &Draft{
		ID: id, Wallet: r.Wallet.ID, Network: r.Wallet.Network, Mode: r.Wallet.Mode, Intent: r.Intent,
		Tx: tx, Summary: summary, Verdict: verdict,
		State: StateDraft, ExpiresAt: clock.Time(tx.TTL),
		CreatedAt: now, UpdatedAt: now,
		params: r.Params,
	}
	for _, u := range tx.Inputs {
		s.reserved[u.In] = id
	}
	s.drafts[id] = d
	return *d, nil
}

// Get returns a draft.
func (s *Store) Get(id model.DraftID) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(s.now())
	d, ok := s.drafts[id]
	if !ok {
		return Draft{}, ErrNotFound
	}
	return *d, nil
}

// List returns the live drafts, of one wallet if wallet is not empty and in
// one state if state is not empty, oldest first.
func (s *Store) List(wallet model.WalletID, state State) []Draft {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(s.now())
	var out []Draft
	for _, d := range s.drafts {
		if d.State.Live() && (wallet == "" || d.Wallet == wallet) && (state == "" || d.State == state) {
			out = append(out, *d)
		}
	}
	slices.SortFunc(out, func(a, b Draft) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return compareIDs(a.ID, b.ID)
	})
	return out
}

func compareIDs(a, b model.DraftID) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Watched returns the drafts whose transaction was sent and whose state the
// chain may still change: submitted, confirmed and rolled back.
func (s *Store) Watched() []Draft {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(s.now())
	var out []Draft
	for _, d := range s.drafts {
		if d.State == StateSubmitted || d.State == StateConfirmed || d.State == StateRolledBack {
			out = append(out, *d)
		}
	}
	return out
}

// ByTx returns the draft of a transaction, if the store still has it.
func (s *Store) ByTx(id [32]byte) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(s.now())
	for _, d := range s.drafts {
		if d.Tx.ID == id {
			return *d, nil
		}
	}
	return Draft{}, ErrNotFound
}

// Reserved returns the inputs the drafts of a wallet hold.
func (s *Store) Reserved(wallet model.WalletID) []chain.TxIn {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(s.now())
	var out []chain.TxIn
	for in, id := range s.reserved {
		if s.drafts[id].Wallet == wallet {
			out = append(out, in)
		}
	}
	slices.SortFunc(out, chain.TxIn.Compare)
	return out
}

// Authorize is authorize_draft. In mode A the person signs on the hardware
// wallet, so the draft always waits for approval (section 6.6). Repeating
// it gives the same draft (section 9.4).
func (s *Store) Authorize(id model.DraftID) (Draft, error) {
	return s.apply(id, func(d *Draft) error {
		if d.State != StateDraft {
			if d.State.Final() {
				return finalError(d, EventAuthorize)
			}
			return nil // already authorized
		}
		if d.Mode != model.ModeA {
			return fmt.Errorf("%w: mode %s", ErrModeNotAvailable, d.Mode)
		}
		if err := s.move(d, EventAuthorize); err != nil {
			return err
		}
		return s.move(d, EventAskApproval)
	})
}

// BeginAuthorize is authorize_draft in modes B and C: the draft moves to
// authorizing, and the caller asks the wallet process to sign. A draft that
// is authorizing already stays so, for the caller to ask again; one further
// on comes back as it is (section 9.4).
func (s *Store) BeginAuthorize(id model.DraftID) (Draft, error) {
	return s.apply(id, func(d *Draft) error {
		if d.Mode == model.ModeA {
			return fmt.Errorf("%w: mode A", ErrModeNotAvailable)
		}
		if d.State != StateDraft {
			if d.State.Final() {
				return finalError(d, EventAuthorize)
			}
			return nil
		}
		return s.move(d, EventAuthorize)
	})
}

// AwaitApproval records that the wallet process waits for the person's
// approval of an authorizing draft.
func (s *Store) AwaitApproval(id model.DraftID, approval string) (Draft, error) {
	return s.apply(id, func(d *Draft) error {
		if d.State == StatePendingApproval && d.ApprovalID == approval {
			return nil
		}
		if err := s.move(d, EventAskApproval); err != nil {
			return err
		}
		d.ApprovalID = approval
		return nil
	})
}

// Reject records that the wallet process, or the person, refused a draft.
func (s *Store) Reject(id model.DraftID, reason string) (Draft, error) {
	return s.event(id, EventReject, reason)
}

// Expire records that the wallet process let the approval of a draft expire.
func (s *Store) Expire(id model.DraftID) (Draft, error) {
	return s.event(id, EventExpire, "")
}

// RejectedByHardwareWallet is the reason the mode A signer gives when the
// person rejects on the device.
const RejectedByHardwareWallet = "hw_rejected"

// Cancel is cancel_draft: the draft ends cancelled, or rejected if the person
// rejected it on the hardware wallet, and frees its inputs. Repeating it
// gives the same draft.
func (s *Store) Cancel(id model.DraftID, reason string) (Draft, error) {
	return s.apply(id, func(d *Draft) error {
		e, target := EventCancel, StateCancelled
		if reason == RejectedByHardwareWallet {
			e, target = EventReject, StateRejected
		}
		if d.State == target {
			return nil
		}
		if err := s.move(d, e); err != nil {
			return err
		}
		d.Reason = reason
		return nil
	})
}

// Sign attaches the witness set of a signer, in mode A from the hardware
// wallet, and leaves the draft signed. The signature must belong exactly to
// the draft: the transaction it completes passes every Conway phase-1 rule,
// signatures and required witnesses included, against the outputs the draft
// spends. Otherwise the draft stays as it was and Sign returns ErrMismatch.
func (s *Store) Sign(id model.DraftID, witnesses []byte) (Draft, error) {
	return s.apply(id, func(d *Draft) error {
		if d.State == StateSigned || d.State == StateSubmitted || d.State == StateConfirmed {
			signed, err := d.Tx.Signed(witnesses)
			if err == nil && string(signed) == string(d.Signed) {
				return nil // the same signature again
			}
		}
		if _, ok := next(d.State, EventSign); !ok {
			if d.State.Final() {
				return finalError(d, EventSign)
			}
			return &StateError{State: d.State, Event: EventSign}
		}
		if len(witnesses) > MaxWitnessBytes {
			return fmt.Errorf("%w: %d bytes of witnesses", ErrMismatch, len(witnesses))
		}
		signed, err := d.Tx.Signed(witnesses)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMismatch, err)
		}
		spent, err := d.Tx.Spent()
		if err != nil {
			return err
		}
		slot := chain.Clock(d.Network).Slot(s.now())
		if err := chain.ValidateSigned(d.Network, d.params, slot, signed, spent); err != nil {
			return fmt.Errorf("%w: %v", ErrMismatch, err)
		}
		if err := s.move(d, EventSign); err != nil {
			return err
		}
		d.Signed = signed
		return nil
	})
}

// Submitted records that the server sent the signed transaction.
func (s *Store) Submitted(id model.DraftID) (Draft, error) {
	return s.event(id, EventSubmit, "")
}

// Confirmed records the depth of a transaction in the chain: it confirms a
// submitted draft, or updates the depth of a confirmed one.
func (s *Store) Confirmed(id model.DraftID, depth uint32) (Draft, error) {
	return s.apply(id, func(d *Draft) error {
		if err := s.move(d, EventConfirm); err != nil {
			return err
		}
		d.Depth = depth
		return nil
	})
}

// Failed records that the node rejected the transaction.
func (s *Store) Failed(id model.DraftID, reason string) (Draft, error) {
	return s.event(id, EventFail, reason)
}

// RolledBack records that a reorganization took the transaction out of the
// chain. Its inputs stay reserved: it may enter again.
func (s *Store) RolledBack(id model.DraftID) (Draft, error) {
	return s.apply(id, func(d *Draft) error {
		if err := s.move(d, EventRollBack); err != nil {
			return err
		}
		d.Depth = 0
		return nil
	})
}

// Reentered records that a rolled-back transaction is back.
func (s *Store) Reentered(id model.DraftID) (Draft, error) {
	return s.event(id, EventReenter, "")
}

// Unconfirmed records that the TTL of a submitted or rolled-back transaction
// passed without it entering the chain. Only whoever watches the chain can
// say so; the clock alone expires drafts that were never sent.
func (s *Store) Unconfirmed(id model.DraftID) (Draft, error) {
	return s.event(id, EventExpire, "")
}

func (s *Store) event(id model.DraftID, e Event, reason string) (Draft, error) {
	return s.apply(id, func(d *Draft) error {
		if err := s.move(d, e); err != nil {
			return err
		}
		if reason != "" {
			d.Reason = reason
		}
		return nil
	})
}

// apply runs f on a draft under the lock and returns the result. If f fails,
// the draft keeps the state it had. Every f moves to a final state, which
// frees the inputs, only as its last step, so a failure never has to give
// back a reservation.
func (s *Store) apply(id model.DraftID, f func(*Draft) error) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(s.now())
	d, ok := s.drafts[id]
	if !ok {
		return Draft{}, ErrNotFound
	}
	before := *d
	if err := f(d); err != nil {
		*d = before
		return Draft{}, err
	}
	return *d, nil
}

// move applies an event and frees the inputs if the draft ends without
// success.
func (s *Store) move(d *Draft, e Event) error {
	to, ok := next(d.State, e)
	if !ok {
		return &StateError{State: d.State, Event: e}
	}
	d.State = to
	d.UpdatedAt = s.now()
	if to.Final() {
		s.release(d)
	}
	return nil
}

func (s *Store) release(d *Draft) {
	for _, u := range d.Tx.Inputs {
		if s.reserved[u.In] == d.ID {
			delete(s.reserved, u.In)
		}
	}
}

func finalError(d *Draft, e Event) error {
	if d.State == StateExpired {
		return ErrExpired
	}
	return &StateError{State: d.State, Event: e}
}

// sweep expires the drafts whose TTL has begun and that were never sent, and
// forgets drafts that ended, or were confirmed, more than Retention ago.
func (s *Store) sweep(now time.Time) {
	for id, d := range s.drafts {
		switch d.State {
		case StateDraft, StateAuthorizing, StatePendingApproval, StateSigned:
			if !now.Before(d.ExpiresAt) {
				d.State = StateExpired
				d.UpdatedAt = now
				s.release(d)
			}
		case StateConfirmed, StateCancelled, StateRejected, StateExpired, StateFailed:
			if now.Sub(d.UpdatedAt) > Retention {
				s.release(d)
				delete(s.drafts, id)
			}
		}
	}
}
