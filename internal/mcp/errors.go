// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package mcp

import (
	"errors"
	"fmt"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/datasource"
	"github.com/Liet-ada/mcpcardano/internal/drafts"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/policy"
	"github.com/Liet-ada/mcpcardano/internal/txbuild"
	"github.com/Liet-ada/mcpcardano/internal/txdecode"
)

// Codes are the stable error codes the agent sees (section 4.5).
const (
	CodeInvalidParams         = "INVALID_PARAMS"
	CodeUnknownWallet         = "UNKNOWN_WALLET"
	CodeDraftNotFound         = "DRAFT_NOT_FOUND"
	CodeNetworkMismatch       = "NETWORK_MISMATCH"
	CodeInsufficientFunds     = "INSUFFICIENT_FUNDS"
	CodeInsufficientFreeUTxOs = "INSUFFICIENT_FREE_UTXOS"
	CodeTooManyUTxOs          = "TOO_MANY_UTXOS"
	CodeTxTooLarge            = "TX_TOO_LARGE"
	CodeUTxOContention        = "UTXO_CONTENTION"
	CodeDraftExpired          = "DRAFT_EXPIRED"
	CodeDraftMismatch         = "DRAFT_MISMATCH"
	CodePolicyBlocked         = "POLICY_BLOCKED"
	CodeBudgetExceeded        = "BUDGET_EXCEEDED"
	CodeWalletFrozen          = "WALLET_FROZEN"
	CodeNeedsSession          = "NEEDS_SESSION"
	CodeWalletUnavailable     = "WALLET_UNAVAILABLE"
	CodeRateLimited           = "RATE_LIMITED"
	CodeDatasourceUnavailable = "DATASOURCE_UNAVAILABLE"
	CodeInternal              = "INTERNAL"
)

// hints tell the agent what to do next (section 4.5).
var hints = map[string]string{
	CodeInvalidParams:         "Fix the parameters that the message points out.",
	CodeUnknownWallet:         "Use list_wallets to see the wallets.",
	CodeDraftNotFound:         "Use list_drafts, or build a new draft.",
	CodeNetworkMismatch:       "The address is for another network; ask the person for a correct one.",
	CodeInsufficientFunds:     "The balance is not enough; check get_wallet_overview.",
	CodeInsufficientFreeUTxOs: "Other drafts hold the UTxOs this needs; wait for them, or cancel drafts with cancel_draft.",
	CodeTooManyUTxOs:          "The wallet has more UTxOs than the server reads; do not retry; ask the person to consolidate it with another tool.",
	CodeTxTooLarge:            "Consolidate with build_consolidation, or split the payment.",
	CodeUTxOContention:        "An input was already spent; build the draft again.",
	CodeDraftExpired:          "Build a new draft.",
	CodeDraftMismatch:         "Build a new draft; the signature does not belong to this one.",
	CodePolicyBlocked:         "The policy does not allow this; do not retry; tell the person.",
	CodeBudgetExceeded:        "The policy does not allow this; do not retry; tell the person.",
	CodeWalletFrozen:          "The person must unfreeze the wallet; do not retry.",
	CodeNeedsSession:          "The person must open a session for the wallet; do not retry.",
	CodeWalletUnavailable:     "The wallet process is locked or not running; tell the person, and call authorize_draft again once they unlock it.",
	CodeRateLimited:           "Wait before retrying.",
	CodeDatasourceUnavailable: "Retry later.",
	CodeInternal:              "Tell the person.",
}

// ruleLiveDrafts names the limit of live drafts (decision 68).
const ruleLiveDrafts = "limits.live_drafts"

// Error is what a failed tool call returns: a stable code, a message and a
// hint (section 4.1). The message never carries text from the chain.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func newError(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Hint: hints[code]}
}

// invalid reports parameters the agent must fix.
func invalid(format string, args ...any) *Error {
	return newError(CodeInvalidParams, format, args...)
}

// translate turns an error from the packages below into the agent's codes.
// Anything it does not recognize is INTERNAL, and its detail stays in the
// audit log, not in the message.
func translate(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	var blocked *drafts.BlockedError
	if errors.As(err, &blocked) {
		return verdictError(blocked.Verdict)
	}
	var below *txbuild.BelowMinimumError
	if errors.As(err, &below) {
		return invalid("output %d needs at least %d lovelace", below.Index, below.Minimum)
	}
	switch {
	case errors.Is(err, chain.ErrNetworkMismatch):
		return newError(CodeNetworkMismatch, "%s", err)
	case errors.Is(err, chain.ErrInvalidTransaction):
		// The decoder's message may quote the bytes, which may come from
		// anyone: it stays out of the answer.
		return invalid("cbor_hex is not a Conway transaction")
	case errors.Is(err, chain.ErrInvalidAddress), errors.Is(err, model.ErrInvalidAsset),
		errors.Is(err, model.ErrInvalidAmount), errors.Is(err, model.ErrInvalidIntent),
		errors.Is(err, txbuild.ErrInvalidOutput), errors.Is(err, txdecode.ErrTooLarge):
		return invalid("%s", err)
	case errors.Is(err, drafts.ErrNotFound):
		return newError(CodeDraftNotFound, "no such draft")
	case errors.Is(err, drafts.ErrExpired):
		return newError(CodeDraftExpired, "the draft expired")
	case errors.Is(err, drafts.ErrMismatch):
		return newError(CodeDraftMismatch, "the signature does not match the draft")
	case errors.Is(err, drafts.ErrNoFreeUTxOs):
		return newError(CodeInsufficientFreeUTxOs, "the free UTxOs are not enough")
	case errors.Is(err, drafts.ErrTooManyDrafts):
		e := newError(CodePolicyBlocked, "%s: the wallet has its maximum of live drafts", ruleLiveDrafts)
		e.Hint = "Cancel a draft you no longer need with cancel_draft, or tell the person."
		return e
	case errors.Is(err, txbuild.ErrInsufficientFunds), errors.Is(err, txbuild.ErrNoFreeUTxOs):
		return newError(CodeInsufficientFunds, "the wallet cannot pay the outputs, the fee and the change")
	case errors.Is(err, txbuild.ErrTooLarge):
		return newError(CodeTxTooLarge, "the transaction would be larger than the maximum size")
	case errors.Is(err, datasource.ErrTooManyUTxOs):
		return newError(CodeTooManyUTxOs, "the address has more than %d UTxOs", datasource.MaxUTxOs)
	case errors.Is(err, datasource.ErrUnavailable), errors.Is(err, datasource.ErrInvalidResponse):
		return newError(CodeDatasourceUnavailable, "the data source did not answer correctly")
	case errors.Is(err, ErrWalletUnavailable):
		return newError(CodeWalletUnavailable, "the wallet process does not answer")
	}
	var we *ipc.Error
	if errors.As(err, &we) {
		return walletFailure(we)
	}
	var se *drafts.StateError
	if errors.As(err, &se) {
		return invalid("a %s draft does not accept this", se.State)
	}
	return newError(CodeInternal, "internal error")
}

// walletFailure translates a failed answer of the wallet process (section
// 5.6). What only a bug explains is INTERNAL, its detail kept in the audit
// log.
func walletFailure(e *ipc.Error) *Error {
	switch e.Code {
	case ipc.Locked:
		return newError(CodeWalletUnavailable, "the wallet process is locked: the person must unlock it")
	case ipc.UnknownWallet:
		return newError(CodeUnknownWallet, "the wallet process has no such wallet")
	case ipc.RateLimited:
		return newError(CodeRateLimited, "the wallet process has too many requests waiting")
	case ipc.NotFound:
		return newError(CodeDraftNotFound, "the wallet process no longer has this approval")
	}
	return newError(CodeInternal, "internal error")
}

// rejectionError translates the wallet's refusal to sign: the rule and its
// detail, as the wallet computed them (section 5.3). A body the wallet cannot
// read is a bug of the server's builder.
func rejectionError(r *ipc.Error) *Error {
	switch r.Code {
	case ipc.Frozen:
		return newError(CodeWalletFrozen, "the wallet is frozen")
	case ipc.NeedsSession:
		return newError(CodeNeedsSession, "%s", r.Detail)
	case ipc.BudgetExceeded:
		return newError(CodeBudgetExceeded, "%s", r.Detail)
	case ipc.TTLTooLong:
		return invalid("%s; build the draft again with a shorter ttl_seconds", r.Detail)
	case ipc.PolicyBlocked:
		return newError(CodePolicyBlocked, "%s", r.Detail)
	}
	return newError(CodeInternal, "the wallet process cannot read the transaction")
}

// verdictError translates a blocked verdict. A TTL the policy does not allow
// is something the agent can fix, so it is INVALID_PARAMS (decision 71).
func verdictError(v policy.Verdict) *Error {
	var e *Error
	switch v.Code {
	case policy.CodeFrozen:
		e = newError(CodeWalletFrozen, "the wallet is frozen")
	case policy.CodeNeedsSession:
		e = newError(CodeNeedsSession, "%s: %s", v.Rule, v.Detail)
	case policy.CodeNetworkMismatch:
		e = newError(CodeNetworkMismatch, "%s: %s", v.Rule, v.Detail)
	case policy.CodeBudgetExceeded:
		e = newError(CodeBudgetExceeded, "%s: %s", v.Rule, v.Detail)
	case policy.CodeTTLTooLong:
		e = invalid("%s: %s; ask for a shorter ttl_seconds", v.Rule, v.Detail)
	default:
		e = newError(CodePolicyBlocked, "%s: %s", v.Rule, v.Detail)
	}
	return e
}
