// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package mcp

import (
	"errors"
	"fmt"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/datasource"
	"github.com/Liet-ada/mcpcardano/internal/drafts"
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
	CodeDraftExpired          = "DRAFT_EXPIRED"
	CodeDraftMismatch         = "DRAFT_MISMATCH"
	CodePolicyBlocked         = "POLICY_BLOCKED"
	CodeBudgetExceeded        = "BUDGET_EXCEEDED"
	CodeWalletFrozen          = "WALLET_FROZEN"
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
	CodeDraftExpired:          "Build a new draft.",
	CodeDraftMismatch:         "Build a new draft; the signature does not belong to this one.",
	CodePolicyBlocked:         "The policy does not allow this; do not retry; tell the person.",
	CodeBudgetExceeded:        "The policy does not allow this; do not retry; tell the person.",
	CodeWalletFrozen:          "The person must unfreeze the wallet; do not retry.",
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
	}
	var se *drafts.StateError
	if errors.As(err, &se) {
		return invalid("a %s draft does not accept this", se.State)
	}
	return newError(CodeInternal, "internal error")
}

// verdictError translates a blocked verdict. A TTL the policy does not allow
// is something the agent can fix, so it is INVALID_PARAMS (decision 71).
func verdictError(v policy.Verdict) *Error {
	var e *Error
	switch v.Code {
	case policy.CodeFrozen:
		e = newError(CodeWalletFrozen, "the wallet is frozen")
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
