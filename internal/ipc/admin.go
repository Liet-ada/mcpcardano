// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ipc

import (
	"bytes"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Messages of the admin socket (section 6). One rule orders them: what lowers
// the risk needs no authorization and has a message of its own; what raises
// the capacity to spend is an action that goes through BeginAuthorization and
// CompleteAuthorization (section 6.2).
const (
	MsgStatus                = "Status"
	MsgUnlock                = "Unlock"
	MsgBeginAuthorization    = "BeginAuthorization"
	MsgCompleteAuthorization = "CompleteAuthorization"
	MsgReject                = "Reject"
	MsgFreeze                = "Freeze"
	MsgCloseSession          = "CloseSession"
	MsgListExpired           = "ListExpired"
	MsgShowPolicy            = "ShowPolicy"
	MsgShowTemplate          = "ShowTemplate"
	MsgShowAudit             = "ShowAudit"
	MsgVerifyAudit           = "VerifyAudit"
)

// Actions that need an authorization (section 6.3). add_key and remove_key
// arrive with the FIDO2 key in H-3.
const (
	ActApproveDraft       = "approve_draft"
	ActOpenSession        = "open_session"
	ActChangePolicy       = "change_policy"
	ActSetTemplate        = "set_template"
	ActUnfreeze           = "unfreeze"
	ActReleaseBudget      = "release_budget"
	ActCreateWallet       = "create_wallet"
	ActRestoreWallet      = "restore_wallet"
	ActShowRecoveryPhrase = "show_recovery_phrase"
)

// actions gives, for each action, the type of its parameters and of the
// result of CompleteAuthorization.
var actions = map[string]struct{ params, result func() Body }{
	ActApproveDraft:       {func() Body { return new(ApproveDraft) }, func() Body { return new(Empty) }},
	ActOpenSession:        {func() Body { return new(OpenSession) }, func() Body { return new(Empty) }},
	ActChangePolicy:       {func() Body { return new(WalletPolicy) }, func() Body { return new(PolicyHash) }},
	ActSetTemplate:        {func() Body { return new(Template) }, func() Body { return new(PolicyHash) }},
	ActUnfreeze:           {func() Body { return new(WalletRef) }, func() Body { return new(Empty) }},
	ActReleaseBudget:      {func() Body { return new(ReleaseBudget) }, func() Body { return new(Released) }},
	ActCreateWallet:       {func() Body { return new(CreateWallet) }, func() Body { return new(Wallet) }},
	ActRestoreWallet:      {func() Body { return new(RestoreWallet) }, func() Body { return new(Wallet) }},
	ActShowRecoveryPhrase: {func() Body { return new(WalletRef) }, func() Body { return new(RecoveryPhrase) }},
}

// NewParams returns an empty parameter body for action, or nil if there is no
// such action.
func NewParams(action string) Body {
	if a, ok := actions[action]; ok {
		return a.params()
	}
	return nil
}

// NewResult returns an empty result body for action, or nil if there is no
// such action.
func NewResult(action string) Body {
	if a, ok := actions[action]; ok {
		return a.result()
	}
	return nil
}

// StatusReport is the answer to Status: what `mcpcardano status` shows
// (section 6.1). LastLedgerEntry is the time of the last entry of the
// spending record, so the person notices a restored copy (section 7.7).
type StatusReport struct {
	Unlocked        bool           `cbor:"unlocked"`
	Wallets         []WalletStatus `cbor:"wallets"`
	Approvals       []Approval     `cbor:"approvals"`
	LastLedgerEntry int64          `cbor:"last_ledger_entry"` // Unix seconds; 0 if none
}

// WalletStatus is one wallet in the status: its session, if open, and
// whether its destinations are open (section 3.7).
type WalletStatus struct {
	Wallet           Wallet   `cbor:"wallet"`
	Session          *Session `cbor:"session,omitempty"`
	OpenDestinations bool     `cbor:"open_destinations"`
}

// Approval is a pending approval.
type Approval struct {
	ID        string `cbor:"id"`
	WalletID  string `cbor:"wallet_id"`
	Spend     Spend  `cbor:"spend"`
	ExpiresAt int64  `cbor:"expires_at"`
}

// Validate implements Body.
func (s *StatusReport) Validate() error {
	for i := range s.Wallets {
		if err := s.Wallets[i].Wallet.Validate(); err != nil {
			return err
		}
	}
	for _, a := range s.Approvals {
		if err := approvalID(a.ID); err != nil {
			return err
		}
		if err := walletID(a.WalletID); err != nil {
			return err
		}
		if err := a.Spend.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Unlock decrypts the key store at start, when it is not unlocked by the
// machine (section 7.2). The password travels over the admin socket, whose
// other end the kernel certifies (section 6.2).
type Unlock struct {
	Password model.Secret `cbor:"password"`
}

// Validate implements Body.
func (u *Unlock) Validate() error { return secret(u.Password, "password") }

// BeginAuthorization starts an action (section 6.2, step 1).
type BeginAuthorization struct {
	Action string    `cbor:"action"`
	Params cborx.Raw `cbor:"params"` // decoded with DecodeParams
}

// Validate implements Body. The parameters are checked by DecodeParams.
func (b *BeginAuthorization) Validate() error {
	if _, ok := actions[b.Action]; !ok {
		return malformed("unknown action")
	}
	return nil
}

// DecodeParams decodes and validates the parameters of an action.
func (c *Codec) DecodeParams(b *BeginAuthorization) (Body, error) {
	p := NewParams(b.Action)
	if p == nil {
		return nil, malformed("unknown action")
	}
	if err := c.DecodeBody(b.Params, p); err != nil {
		return nil, err
	}
	return p, nil
}

// Methods of authorization. In H-2 there is only the password; the FIDO2 key
// arrives in H-3.
const MethodPassword = "password"

// Challenge is the answer to BeginAuthorization (section 6.2, step 2): the
// summary the wallet computed itself, which the CLI shows as is.
type Challenge struct {
	AuthID    []byte   `cbor:"auth_id"`
	Summary   []string `cbor:"summary"`
	Methods   []string `cbor:"methods"`
	ExpiresAt int64    `cbor:"expires_at"` // Unix seconds
}

// AuthIDSize is the size of an authorization id.
const AuthIDSize = 16

// Validate implements Body.
func (c *Challenge) Validate() error {
	if len(c.AuthID) != AuthIDSize {
		return malformed("authorization id")
	}
	if err := summary(c.Summary); err != nil {
		return err
	}
	if len(c.Methods) != 1 || c.Methods[0] != MethodPassword {
		return malformed("methods")
	}
	return nil
}

// CompleteAuthorization confirms an action (section 6.2, step 4).
type CompleteAuthorization struct {
	AuthID   []byte       `cbor:"auth_id"`
	Password model.Secret `cbor:"password"`
}

// Validate implements Body.
func (c *CompleteAuthorization) Validate() error {
	if len(c.AuthID) != AuthIDSize {
		return malformed("authorization id")
	}
	return secret(c.Password, "password")
}

// Completed is the answer to CompleteAuthorization: the result of the action,
// decoded with the body that NewResult gives for it.
type Completed struct {
	Result cborx.Raw `cbor:"result"`
}

// Validate implements Body.
func (*Completed) Validate() error { return nil }

// ApproveDraft is the parameter of approve_draft.
type ApproveDraft struct {
	ApprovalID string `cbor:"approval_id"`
}

// Validate implements Body.
func (a *ApproveDraft) Validate() error { return approvalID(a.ApprovalID) }

// OpenSession is the parameter of open_session: a window of time and amount.
type OpenSession struct {
	WalletID    string `cbor:"wallet_id"`
	Seconds     uint32 `cbor:"seconds"`
	MaxLovelace uint64 `cbor:"max_lovelace"`
}

// Validate implements Body.
func (o *OpenSession) Validate() error {
	if err := walletID(o.WalletID); err != nil {
		return err
	}
	if o.Seconds == 0 || o.MaxLovelace == 0 {
		return malformed("a session needs a duration and an amount")
	}
	return nil
}

// WalletPolicy is a wallet's policy with its mode: the parameter of
// change_policy, whose signed message covers both together (decision 41),
// and the answer to ShowPolicy.
type WalletPolicy struct {
	WalletID string `cbor:"wallet_id"`
	Mode     string `cbor:"mode"`
	Policy   Policy `cbor:"policy"`
}

// Validate implements Body.
func (c *WalletPolicy) Validate() error {
	if err := walletID(c.WalletID); err != nil {
		return err
	}
	if !walletMode(c.Mode) {
		return malformed("mode")
	}
	return c.Policy.Validate()
}

// PolicyHash is the result of change_policy and set_template: the hash of
// the new policy with its mode, the one the audit records.
type PolicyHash struct {
	Hash []byte `cbor:"hash"`
}

// Validate implements Body.
func (p *PolicyHash) Validate() error { return hash(p.Hash, "policy hash") }

// WalletRef names a wallet.
type WalletRef struct {
	WalletID string `cbor:"wallet_id"`
}

// Validate implements Body.
func (w *WalletRef) Validate() error { return walletID(w.WalletID) }

// ReleaseBudget is the parameter of release_budget: the expired_unconfirmed
// entries to release, by the hash of their transaction body, sorted (section
// 9.2).
type ReleaseBudget struct {
	WalletID string   `cbor:"wallet_id"`
	Entries  [][]byte `cbor:"entries"`
}

// Validate implements Body.
func (r *ReleaseBudget) Validate() error {
	if err := walletID(r.WalletID); err != nil {
		return err
	}
	if len(r.Entries) == 0 {
		return malformed("nothing to release")
	}
	for i, e := range r.Entries {
		if err := hash(e, "entry"); err != nil {
			return err
		}
		if i > 0 && bytes.Compare(r.Entries[i-1], e) >= 0 {
			return malformed("entries repeated or out of order")
		}
	}
	return nil
}

// Released is the result of release_budget.
type Released struct {
	Lovelace uint64 `cbor:"lovelace"`
}

// Validate implements Body.
func (*Released) Validate() error { return nil }

// RestoreWallet is the parameter of restore_wallet. The phrase goes in the
// parameters so that the summary can show the address it derives.
type RestoreWallet struct {
	Label  string       `cbor:"label"`
	Phrase model.Secret `cbor:"phrase"`
}

// Validate implements Body.
func (r *RestoreWallet) Validate() error {
	if !text(r.Label, MaxLabel) {
		return malformed("label")
	}
	return secret(r.Phrase, "recovery phrase")
}

// Wipe overwrites the phrase with zeros, for an authorization that will not
// run.
func (r *RestoreWallet) Wipe() { r.Phrase.Wipe() }

// RecoveryPhrase is the result of show_recovery_phrase.
type RecoveryPhrase struct {
	Phrase model.Secret `cbor:"phrase"`
}

// Validate implements Body.
func (r *RecoveryPhrase) Validate() error { return secret(r.Phrase, "recovery phrase") }

// ApprovalRef names an approval, for Reject.
type ApprovalRef struct {
	ApprovalID string `cbor:"approval_id"`
}

// Validate implements Body.
func (a *ApprovalRef) Validate() error { return approvalID(a.ApprovalID) }

// Freeze freezes one wallet at once, or all of them if WalletID is empty.
type Freeze struct {
	WalletID string `cbor:"wallet_id,omitempty"`
}

// Validate implements Body.
func (f *Freeze) Validate() error {
	if f.WalletID == "" {
		return nil
	}
	return walletID(f.WalletID)
}

// ListExpired lists the expired_unconfirmed entries of one wallet, or of all
// of them if WalletID is empty (section 9.2).
type ListExpired struct {
	WalletID string `cbor:"wallet_id,omitempty"`
}

// Validate implements Body.
func (l *ListExpired) Validate() error {
	if l.WalletID == "" {
		return nil
	}
	return walletID(l.WalletID)
}

// ExpiredList is the answer to ListExpired.
type ExpiredList struct {
	Entries []Expired `cbor:"entries"`
}

// Expired is a signed transaction whose TTL passed by the wallet's clock and
// that still counts as spent until the person releases it.
type Expired struct {
	WalletID string `cbor:"wallet_id"`
	BodyHash []byte `cbor:"body_hash"`
	Spend    Spend  `cbor:"spend"`
	TTL      uint64 `cbor:"ttl"`  // slot
	Time     int64  `cbor:"time"` // when it was signed, Unix seconds
}

// Validate implements Body.
func (l *ExpiredList) Validate() error {
	for _, e := range l.Entries {
		if err := walletID(e.WalletID); err != nil {
			return err
		}
		if err := hash(e.BodyHash, "body hash"); err != nil {
			return err
		}
		if err := e.Spend.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ShowAudit asks for up to Limit audit entries from sequence number From.
type ShowAudit struct {
	From  uint64 `cbor:"from"`
	Limit uint32 `cbor:"limit"`
}

// MaxAuditPage bounds the entries of one ShowAudit.
const MaxAuditPage = 100

// Validate implements Body.
func (s *ShowAudit) Validate() error {
	if s.Limit == 0 || s.Limit > MaxAuditPage {
		return malformed("limit: 1 to %d", MaxAuditPage)
	}
	return nil
}

// AuditPage is a page of audit entries, each as written in the log, and the
// sequence number to ask for next; 0 when there are no more.
type AuditPage struct {
	Entries []cborx.Raw `cbor:"entries"`
	Next    uint64      `cbor:"next"`
}

// Validate implements Body.
func (a *AuditPage) Validate() error {
	if len(a.Entries) > MaxAuditPage {
		return malformed("more than %d entries", MaxAuditPage)
	}
	return nil
}

// AuditCheck is the answer to VerifyAudit: both hash chains held, over this
// many entries.
type AuditCheck struct {
	AuditEntries  uint64 `cbor:"audit_entries"`
	LedgerEntries uint64 `cbor:"ledger_entries"`
}

// Validate implements Body.
func (*AuditCheck) Validate() error { return nil }
