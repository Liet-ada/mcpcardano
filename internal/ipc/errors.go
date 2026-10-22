// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ipc

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

// Code is an error code of the wallet (section 5.6). Codes are never renamed
// or reused.
type Code string

const (
	ProtocolMismatch   Code = "PROTOCOL_MISMATCH"
	NetworkMismatch    Code = "NETWORK_MISMATCH"
	Malformed          Code = "MALFORMED"
	TooLarge           Code = "TOO_LARGE"
	UnknownWallet      Code = "UNKNOWN_WALLET"
	Frozen             Code = "FROZEN"
	NeedsSession       Code = "NEEDS_SESSION"
	TxUnsupportedField Code = "TX_UNSUPPORTED_FIELD"
	TxNotCanonical     Code = "TX_NOT_CANONICAL"
	TTLTooLong         Code = "TTL_TOO_LONG"
	PolicyBlocked      Code = "POLICY_BLOCKED"
	BudgetExceeded     Code = "BUDGET_EXCEEDED"
	RateLimited        Code = "RATE_LIMITED"
	Internal           Code = "INTERNAL"

	// Codes of the admin socket.
	Locked      Code = "LOCKED"       // the key store is not unlocked yet
	AuthFailed  Code = "AUTH_FAILED"  // wrong password; the wait before the next one doubles
	AuthExpired Code = "AUTH_EXPIRED" // the authorization expired or was used
	NotFound    Code = "NOT_FOUND"    // no such approval, authorization or record entry
)

var codes = map[Code]bool{
	ProtocolMismatch: true, NetworkMismatch: true, Malformed: true, TooLarge: true,
	UnknownWallet: true, Frozen: true, NeedsSession: true, TxUnsupportedField: true,
	TxNotCanonical: true, TTLTooLong: true, PolicyBlocked: true, BudgetExceeded: true,
	RateLimited: true, Internal: true,
	Locked: true, AuthFailed: true, AuthExpired: true, NotFound: true,
}

// rejectionCodes are the codes a SignDraft can be rejected with: what the
// wallet found in the transaction or in the wallet's state. The others are
// failures of the request itself.
var rejectionCodes = map[Code]bool{
	Frozen: true, NeedsSession: true, TxUnsupportedField: true, TxNotCanonical: true,
	TTLTooLong: true, PolicyBlocked: true, BudgetExceeded: true,
}

// MaxDetail bounds the detail of an error.
const MaxDetail = 256

// Error is the err field of a failed response, and the rejection of a
// SignDraft. Detail names the rule or the field; it never carries a secret
// (section 1.3) and may be empty.
type Error struct {
	Code   Code   `cbor:"code"`
	Detail string `cbor:"detail"`
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "ipc: " + string(e.Code)
	}
	return "ipc: " + string(e.Code) + ": " + e.Detail
}

// Is makes errors.Is match any *Error with the same code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code && t.Detail == ""
}

// Validate implements Body.
func (e *Error) Validate() error {
	if !codes[e.Code] {
		return malformed("unknown error code")
	}
	if e.Detail != "" && !text(e.Detail, MaxDetail) {
		return malformed("error detail")
	}
	return nil
}

func malformed(format string, a ...any) *Error {
	return &Error{Code: Malformed, Detail: Detail(fmt.Sprintf(format, a...))}
}

// Detail turns s into a valid error detail: invisible characters become
// "?" and the text is cut to MaxDetail bytes.
func Detail(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r != ' ' && (!unicode.IsGraphic(r) || unicode.IsSpace(r)) {
			r = '?'
		}
		if len(b)+utf8.RuneLen(r) > MaxDetail {
			break
		}
		b = utf8.AppendRune(b, r)
	}
	return string(b)
}

// text reports whether s is 1 to max bytes of visible UTF-8: letters, marks,
// numbers, punctuation, symbols and the ASCII space, as in section 4.1.
func text(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r != ' ' && (!unicode.IsGraphic(r) || unicode.IsSpace(r)) {
			return false
		}
	}
	return true
}
