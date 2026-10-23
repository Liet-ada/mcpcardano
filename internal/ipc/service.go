// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ipc

import (
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Messages of the service socket (section 5.3). Hello is also the first
// message on the admin socket.
const (
	MsgHello             = "Hello"
	MsgSignDraft         = "SignDraft"
	MsgCreateWallet      = "CreateWallet"
	MsgGetApprovalStatus = "GetApprovalStatus"
	MsgGetPolicyStatus   = "GetPolicyStatus"
	MsgPing              = "Ping"
	MsgListWallets       = "ListWallets"
)

// Hello is the greeting both ends send when a connection opens. The protocol
// version travels in the envelope; a different version or network ends the
// connection with PROTOCOL_MISMATCH or NETWORK_MISMATCH.
type Hello struct {
	Software string `cbor:"software"` // the binary's version
	Network  string `cbor:"network"`
}

// Validate implements Body.
func (h *Hello) Validate() error {
	if !text(h.Software, MaxSoftware) {
		return malformed("software version")
	}
	if !model.Network(h.Network).Valid() {
		return malformed("network")
	}
	return nil
}

// SignDraft asks the wallet to sign a draft (section 9.1).
type SignDraft struct {
	WalletID string          `cbor:"wallet_id"`
	DraftID  string          `cbor:"draft_id"`
	Body     []byte          `cbor:"body"`
	AuxData  []byte          `cbor:"aux_data,omitempty"`
	Inputs   []ResolvedInput `cbor:"inputs"` // only shown, never trusted
}

// Validate implements Body.
func (s *SignDraft) Validate() error {
	if err := walletID(s.WalletID); err != nil {
		return err
	}
	if model.DraftID(s.DraftID).Validate() != nil {
		return malformed("draft id")
	}
	if len(s.Body) == 0 || len(s.Body) > MaxTxSize || len(s.AuxData) > MaxTxSize {
		return malformed("transaction body or auxiliary data size")
	}
	if len(s.Inputs) > MaxInputs {
		return malformed("more than %d inputs", MaxInputs)
	}
	for _, in := range s.Inputs {
		if err := in.validate(); err != nil {
			return err
		}
	}
	return nil
}

// Outcomes of SignDraft.
const (
	Signed          = "signed"
	PendingApproval = "pending_approval"
	Rejected        = "rejected"
)

// SignDraftResult is the answer to SignDraft: the witnesses, an approval to
// wait for, or the rule that rejected it. Spend is always what the wallet
// computed, so the server can compare it with its own.
type SignDraftResult struct {
	Status     string    `cbor:"status"`
	Witnesses  []Witness `cbor:"witnesses,omitempty"`
	ApprovalID string    `cbor:"approval_id,omitempty"`
	Rejection  *Error    `cbor:"rejection,omitempty"`
	Spend      Spend     `cbor:"spend"`
}

// Validate implements Body.
func (r *SignDraftResult) Validate() error {
	if err := r.Spend.Validate(); err != nil {
		return err
	}
	signed, pending, rejected := r.Status == Signed, r.Status == PendingApproval, r.Status == Rejected
	switch {
	case !signed && !pending && !rejected:
		return malformed("unknown status")
	case signed != (r.Witnesses != nil), pending != (r.ApprovalID != ""), rejected != (r.Rejection != nil):
		return malformed("status %s with the fields of another", r.Status)
	case signed:
		return witnesses(r.Witnesses)
	case pending:
		return approvalID(r.ApprovalID)
	}
	if err := r.Rejection.Validate(); err != nil {
		return err
	}
	if !rejectionCodes[r.Rejection.Code] {
		return malformed("%s is not a rejection", r.Rejection.Code)
	}
	return nil
}

// CreateWallet asks the wallet for a new wallet with the template (section
// 3.7). The same idempotency key gives back the same wallet.
type CreateWallet struct {
	Label          string `cbor:"label"`
	IdempotencyKey string `cbor:"idempotency_key,omitempty"`
}

// Validate implements Body.
func (c *CreateWallet) Validate() error {
	if !text(c.Label, MaxLabel) {
		return malformed("label")
	}
	if c.IdempotencyKey != "" && !text(c.IdempotencyKey, MaxLabel) {
		return malformed("idempotency key")
	}
	return nil
}

// WalletCreated is the new wallet and the template it got. Never the
// recovery phrase.
type WalletCreated struct {
	Wallet Wallet `cbor:"wallet"`
	Policy Policy `cbor:"policy"`
}

// Validate implements Body.
func (w *WalletCreated) Validate() error {
	if err := w.Wallet.Validate(); err != nil {
		return err
	}
	return w.Policy.Validate()
}

// GetApprovalStatus asks how an approval stands.
type GetApprovalStatus struct {
	ApprovalID string `cbor:"approval_id"`
}

// Validate implements Body.
func (g *GetApprovalStatus) Validate() error { return approvalID(g.ApprovalID) }

// States of an approval.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalRejected = "rejected"
	ApprovalExpired  = "expired"
)

// ApprovalStatus is how an approval stands; an approved one carries the
// witnesses.
type ApprovalStatus struct {
	Status    string    `cbor:"status"`
	Witnesses []Witness `cbor:"witnesses,omitempty"`
	ExpiresAt int64     `cbor:"expires_at"` // Unix seconds
}

// Validate implements Body.
func (a *ApprovalStatus) Validate() error {
	if err := oneOf(a.Status, "approval status", ApprovalPending, ApprovalApproved, ApprovalRejected, ApprovalExpired); err != nil {
		return err
	}
	if (a.Status == ApprovalApproved) != (a.Witnesses != nil) {
		return malformed("only an approved approval carries witnesses")
	}
	if a.Witnesses != nil {
		return witnesses(a.Witnesses)
	}
	return nil
}

// GetPolicyStatus asks for a wallet's policy and the state of its budget.
// Destinations are those of a draft about to be built, raw and in order: the
// answer says which of them the wallet's record knows, so the server counts
// the new ones as the wallet will.
type GetPolicyStatus struct {
	WalletID     string   `cbor:"wallet_id"`
	Destinations [][]byte `cbor:"destinations,omitempty"`
}

// Validate implements Body.
func (g *GetPolicyStatus) Validate() error {
	if err := walletID(g.WalletID); err != nil {
		return err
	}
	return destinations(g.Destinations, "destinations")
}

// PolicyStatus is a wallet's mode, its whole policy and what it has spent
// (section 3.9): lovelace, transactions and new destinations, counted as the
// wallet counts them when it signs. Known are the destinations of the
// request that its record already holds. Pending lists the transactions it
// signed whose TTL has not passed, for the server to follow after a restart
// (section 9.5).
type PolicyStatus struct {
	Mode                string      `cbor:"mode"`
	Policy              Policy      `cbor:"policy"`
	Session             *Session    `cbor:"session,omitempty"`
	SpentHour           uint64      `cbor:"spent_hour"`
	SpentDay            uint64      `cbor:"spent_day"`
	TxHour              uint32      `cbor:"tx_hour"`
	NewDestinationsHour uint32      `cbor:"new_destinations_hour"`
	NewDestinationsDay  uint32      `cbor:"new_destinations_day"`
	Known               [][]byte    `cbor:"known,omitempty"`
	BudgetRemaining     uint64      `cbor:"budget_remaining"`
	Locked              uint64      `cbor:"locked"`
	Committed           uint64      `cbor:"committed"`
	Pending             []PendingTx `cbor:"pending"`
}

// Session is an open session: when it ends and how much it still allows.
type Session struct {
	ExpiresAt int64  `cbor:"expires_at"` // Unix seconds
	Remaining uint64 `cbor:"remaining"`  // lovelace
}

// PendingTx is a signed transaction that may still reach the chain.
type PendingTx struct {
	TxID []byte `cbor:"tx_id"`
	TTL  uint64 `cbor:"ttl"` // slot
}

// Validate implements Body.
func (p *PolicyStatus) Validate() error {
	if !walletMode(p.Mode) {
		return malformed("mode")
	}
	if err := p.Policy.Validate(); err != nil {
		return err
	}
	if err := destinations(p.Known, "known destinations"); err != nil {
		return err
	}
	for _, t := range p.Pending {
		if err := hash(t.TxID, "pending transaction id"); err != nil {
			return err
		}
	}
	return nil
}

// PingResult says the wallet is alive, whether any wallet is frozen, and the
// slot by the wallet's own clock, so the server can warn of drift (section
// 9.3).
type PingResult struct {
	AnyFrozen bool   `cbor:"any_frozen"`
	Slot      uint64 `cbor:"slot"`
}

// Validate implements Body.
func (*PingResult) Validate() error { return nil }

// WalletList is the answer to ListWallets: every wallet of the wallet
// process, in the order it keeps them.
type WalletList struct {
	Wallets []Wallet `cbor:"wallets"`
}

// Validate implements Body.
func (l *WalletList) Validate() error {
	seen := make(map[string]bool, len(l.Wallets))
	for i := range l.Wallets {
		if err := l.Wallets[i].Validate(); err != nil {
			return err
		}
		if seen[l.Wallets[i].ID] {
			return malformed("repeated wallet id")
		}
		seen[l.Wallets[i].ID] = true
	}
	return nil
}
