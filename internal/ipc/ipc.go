// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package ipc is the protocol between the processes (sections 5 and 6 of the
// specification). The server and the CLI talk to the wallet over two Unix
// sockets, service and admin, with length-prefixed canonical CBOR maps. This
// package frames, encodes and decodes the messages of both sockets, checks
// them in the order of section 5.4, steps 1 to 4, and reads who is at the
// other end of a socket. The business rules of step 5 belong to the wallet.
//
// Every message has exactly one encoding: a message is accepted only if
// encoding what was decoded gives back the same bytes. That rejects
// non-canonical CBOR, missing fields, and optional fields sent with the value
// they should have left out.
package ipc

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
)

// Version is the protocol version (section 5.7). Any change to a message
// raises it; there is no partial compatibility.
const Version = 1

// IDSize is the size of a request id.
const IDSize = 16

// MaxTxSize bounds the transaction body and the auxiliary data of SignDraft,
// each: no transaction the ledger accepts is larger.
const MaxTxSize = 16384

// MaxServiceConns is how many connections the service socket admits at once
// (section 5.5).
const MaxServiceConns = 4

// ConnLimits are the limits of section 5.5 for one connection.
type ConnLimits struct {
	MaxMessageSize int           // a longer declared length is TOO_LARGE
	Receive        time.Duration // to read a whole message once it starts
	Idle           time.Duration // to wait for the next message to start
}

// DefaultConnLimits returns the initial values of section 5.5.
func DefaultConnLimits() ConnLimits {
	return ConnLimits{MaxMessageSize: 256 << 10, Receive: 5 * time.Second, Idle: 60 * time.Second}
}

// Socket is one of the wallet's two sockets.
type Socket uint8

const (
	Service Socket = iota + 1 // the server's (section 5.3)
	Admin                     // the person's, through the CLI (section 6)
)

func (s Socket) String() string {
	switch s {
	case Service:
		return "service"
	case Admin:
		return "admin"
	}
	return fmt.Sprintf("socket(%d)", uint8(s))
}

// Body is the body of a request or of a response. Validate checks its schema,
// step 4 of section 5.4: the types are already right, so it checks formats,
// sizes and the fields that go together.
type Body interface {
	Validate() error
}

// Empty is the body of the messages that carry nothing.
type Empty struct{}

// Validate implements Body.
func (*Empty) Validate() error { return nil }

// Request is the envelope of a request (section 5.2).
type Request struct {
	V  uint64    `cbor:"v"`
	ID []byte    `cbor:"id"`
	T  string    `cbor:"t"`
	B  cborx.Raw `cbor:"b"`
}

// Response is the envelope of a response: the body if OK, the error if not.
type Response struct {
	V   uint64    `cbor:"v"`
	ID  []byte    `cbor:"id"`
	OK  bool      `cbor:"ok"`
	B   cborx.Raw `cbor:"b,omitempty"`
	Err *Error    `cbor:"err,omitempty"`
}

// errNotExact reports bytes that decode but are not the one encoding of what
// they decode to.
var errNotExact = errors.New("not the exact canonical encoding")

// Codec encodes and decodes messages. It is safe for concurrent use.
type Codec struct {
	c *cborx.Codec
}

// NewCodec returns a codec with the record limits of cborx, which bound the
// decoder's depth, arrays and maps (section 5.4, step 2).
func NewCodec() *Codec {
	c, err := cborx.New(cborx.RecordLimits())
	if err != nil {
		panic(err) // constant limits
	}
	return &Codec{c: c}
}

// exact decodes data into v and requires that encoding v gives data back.
func (c *Codec) exact(data []byte, v any) error {
	if err := c.c.Unmarshal(data, v); err != nil {
		return err
	}
	b, err := c.c.Marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, data) {
		return errNotExact
	}
	return nil
}

// DecodeRequest checks the envelope of a request that arrived on socket s,
// steps 2 and 3 of section 5.4. On error it returns what it could read of
// the request, so the reply can carry its id. The body is left for
// DecodeBody.
func (c *Codec) DecodeRequest(s Socket, frame []byte) (Request, error) {
	var r Request
	if err := c.exact(frame, &r); err != nil {
		r.ID = nil // it may not be an id at all
		return r, malformed("envelope: %v", err)
	}
	if r.V != Version {
		return r, &Error{Code: ProtocolMismatch, Detail: fmt.Sprintf("protocol version %d, want %d", r.V, Version)}
	}
	if n := len(r.ID); n != IDSize {
		r.ID = nil
		return r, malformed("id has %d bytes, want %d", n, IDSize)
	}
	if m, ok := messages[r.T]; !ok || !m.on(s) {
		return r, malformed("no message %q on the %s socket", r.T, s)
	}
	return r, nil
}

// DecodeBody decodes and validates a body into v, which must be a pointer:
// step 4 of section 5.4.
func (c *Codec) DecodeBody(raw cborx.Raw, v Body) error {
	if err := c.exact(raw, v); err != nil {
		return malformed("body: %v", err)
	}
	return v.Validate()
}

// EncodeRequest encodes a request of type t with the given id.
func (c *Codec) EncodeRequest(t string, id []byte, body Body) ([]byte, error) {
	b, err := c.c.Marshal(body)
	if err != nil {
		return nil, err
	}
	defer clear(b) // the body may carry a secret, and the request has a copy
	return c.c.Marshal(Request{V: Version, ID: id, T: t, B: b})
}

// EncodeResponse encodes a successful response to the request with this id.
func (c *Codec) EncodeResponse(id []byte, body Body) ([]byte, error) {
	b, err := c.c.Marshal(body)
	if err != nil {
		return nil, err
	}
	defer clear(b) // the body may carry a secret, and the response has a copy
	return c.c.Marshal(Response{V: Version, ID: id, OK: true, B: b})
}

// EncodeError encodes a failed response. id may be nil when the request could
// not be read.
func (c *Codec) EncodeError(id []byte, e *Error) ([]byte, error) {
	return c.c.Marshal(Response{V: Version, ID: id, Err: e})
}

// DecodeResponse checks a response to the request with this id and decodes
// its body into v. A failed response comes back as *Error.
func (c *Codec) DecodeResponse(frame, id []byte, v Body) error {
	var r Response
	if err := c.exact(frame, &r); err != nil {
		return malformed("response envelope: %v", err)
	}
	if r.V != Version {
		return &Error{Code: ProtocolMismatch, Detail: fmt.Sprintf("protocol version %d, want %d", r.V, Version)}
	}
	if !r.OK {
		if r.Err == nil || r.B != nil {
			return malformed("a failed response carries an error and no body")
		}
		if err := r.Err.Validate(); err != nil {
			return err
		}
		if r.ID != nil && !bytes.Equal(r.ID, id) {
			return malformed("response to another request")
		}
		return r.Err
	}
	if r.Err != nil || r.B == nil {
		return malformed("a successful response carries a body and no error")
	}
	if !bytes.Equal(r.ID, id) {
		return malformed("response to another request")
	}
	defer clear(r.B) // decoded: v holds the only copy left
	return c.DecodeBody(r.B, v)
}

// Encode encodes a body on its own, such as the parameters of an action or
// the result of an authorization.
func (c *Codec) Encode(body Body) (cborx.Raw, error) {
	return c.c.Marshal(body)
}
