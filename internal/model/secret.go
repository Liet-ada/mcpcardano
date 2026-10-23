// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package model

import (
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[REDACTED]"

// Secret holds a password, a recovery phrase or a key. However it is printed
// or logged, it shows [REDACTED] (section 10.4); the bytes are reachable only
// by indexing or converting it. Encoders that do not go through fmt, such as
// CBOR, still write the real bytes: that is how a password reaches the wallet
// over the admin socket.
type Secret []byte

// String implements fmt.Stringer.
func (Secret) String() string { return redacted }

// GoString implements fmt.GoStringer, for %#v.
func (Secret) GoString() string { return redacted }

// Format implements fmt.Formatter, so that %x, %q and the other verbs do not
// print the bytes either.
func (Secret) Format(f fmt.State, _ rune) { io.WriteString(f, redacted) }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON implements json.Marshaler.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// Wipe overwrites the bytes with zeros. Go may have copied them elsewhere,
// so it narrows the exposure; it does not end it.
func (s Secret) Wipe() { clear(s) }

// Wipe overwrites the secrets that v holds, if it has a Wipe method, as the
// messages that carry a password or a recovery phrase do.
func Wipe(v any) {
	if w, ok := v.(interface{ Wipe() }); ok {
		w.Wipe()
	}
}
