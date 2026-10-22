// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ipc

import (
	"bytes"
	"slices"
	"testing"
)

// FuzzRequest feeds arbitrary frames to both sockets. Nothing may panic, and
// whatever is accepted must be the one encoding of what it decodes to.
func FuzzRequest(f *testing.F) {
	c := NewCodec()
	for name, pair := range samples(f) {
		frame, err := c.EncodeRequest(name, reqID, pair[0])
		if err != nil {
			f.Fatal(err)
		}
		f.Add(frame)
	}
	f.Fuzz(func(t *testing.T, frame []byte) {
		for _, s := range []Socket{Service, Admin} {
			r, err := c.DecodeRequest(s, frame)
			if err != nil {
				if _, ok := err.(*Error); !ok {
					t.Fatalf("an error that is not *Error: %v", err)
				}
				continue
			}
			again, err := c.EncodeRequest(r.T, r.ID, rawBody(r.B))
			if err != nil || !bytes.Equal(again, frame) {
				t.Fatalf("accepted a frame that does not encode back: %x", frame)
			}
			body := NewRequest(r.T)
			if err := c.DecodeBody(r.B, body); err != nil {
				continue
			}
			if b, err := c.Encode(body); err != nil || !bytes.Equal(b, r.B) {
				t.Fatalf("accepted a %s body that does not encode back", r.T)
			}
			if begin, ok := body.(*BeginAuthorization); ok {
				c.DecodeParams(begin)
			}
		}
	})
}

// rawBody lets an already encoded body go back through EncodeRequest.
type rawBody []byte

func (rawBody) Validate() error { return nil }

func (r rawBody) MarshalCBOR() ([]byte, error) { return r, nil }

// FuzzResponse feeds arbitrary frames as the response to every message type.
func FuzzResponse(f *testing.F) {
	c := NewCodec()
	types := make([]string, 0, len(messages))
	for name := range messages {
		types = append(types, name)
	}
	slices.Sort(types)
	for name, pair := range samples(f) {
		frame, err := c.EncodeResponse(reqID, pair[1])
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(slices.Index(types, name)), frame)
	}
	failed, _ := c.EncodeError(reqID, &Error{Code: BudgetExceeded, Detail: "limits.per_day"})
	f.Add(uint8(0), failed)
	f.Fuzz(func(t *testing.T, n uint8, frame []byte) {
		resp := NewResponse(types[int(n)%len(types)])
		if err := c.DecodeResponse(frame, reqID, resp); err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatalf("an error that is not *Error: %v", err)
			}
		}
	})
}
