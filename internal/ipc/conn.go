// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ipc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
)

// ReadFrame reads one message from a connection with the limits of section
// 5.5: it waits up to l.Idle for the message to start and then up to
// l.Receive for the rest, so a slow sender cannot hold a connection open one
// byte at a time. A declared length above l.MaxMessageSize fails with
// TOO_LARGE before the payload is read (section 5.4, step 1).
func ReadFrame(conn net.Conn, l ConnLimits) ([]byte, error) {
	var hdr [cborx.FrameHeaderSize]byte
	if err := conn.SetReadDeadline(time.Now().Add(l.Idle)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, hdr[:1]); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(l.Receive)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, hdr[1:]); err != nil {
		return nil, unexpected(err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, malformed("empty message")
	}
	if uint64(n) > uint64(l.MaxMessageSize) {
		return nil, &Error{Code: TooLarge, Detail: fmt.Sprintf("message of %d bytes, at most %d", n, l.MaxMessageSize)}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, unexpected(err)
	}
	return payload, nil
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// WriteFrame writes one message, within l.Receive.
func WriteFrame(conn net.Conn, payload []byte, l ConnLimits) error {
	if err := conn.SetWriteDeadline(time.Now().Add(l.Receive)); err != nil {
		return err
	}
	return cborx.WriteFrame(conn, payload, l.MaxMessageSize)
}

// DefaultCallTimeout bounds a call when its context has no earlier deadline.
const DefaultCallTimeout = 30 * time.Second

// Client is one connection to a wallet socket. It sends one request at a
// time and waits for its response. After a failure that may have left a
// message half read, it refuses further calls; the caller dials again.
type Client struct {
	mu     sync.Mutex
	conn   net.Conn
	codec  *Codec
	limits ConnLimits
	broken error

	// Peer is the wallet's greeting.
	Peer Hello
}

// Dial connects to the socket at path and exchanges greetings. A wallet of
// another protocol version or network gives an *Error with
// PROTOCOL_MISMATCH or NETWORK_MISMATCH.
func Dial(ctx context.Context, path string, hello Hello) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	c := &Client{conn: conn, codec: NewCodec(), limits: DefaultConnLimits()}
	if err := c.Call(ctx, MsgHello, &hello, &c.Peer); err != nil {
		conn.Close()
		return nil, err
	}
	if c.Peer.Network != hello.Network {
		conn.Close()
		return nil, &Error{Code: NetworkMismatch, Detail: "the wallet serves " + c.Peer.Network}
	}
	return c, nil
}

// Call sends a request of type t and decodes the response into resp. A
// failed response comes back as *Error. A request that does not validate is
// never sent.
func (c *Client) Call(ctx context.Context, t string, req, resp Body) error {
	if err := req.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken != nil {
		return c.broken
	}
	id := make([]byte, IDSize)
	rand.Read(id)
	frame, err := c.codec.EncodeRequest(t, id, req)
	if err != nil {
		return err
	}
	defer clear(frame) // a request may carry a password or a recovery phrase

	deadline := time.Now().Add(DefaultCallTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if err := cborx.WriteFrame(c.conn, frame, c.limits.MaxMessageSize); err != nil {
		return c.fail(ctx, err)
	}
	payload, err := cborx.ReadFrame(c.conn, c.limits.MaxMessageSize)
	if err != nil {
		return c.fail(ctx, err)
	}
	defer clear(payload) // and a response, the recovery phrase
	return c.codec.DecodeResponse(payload, id, resp)
}

// fail marks the connection as broken. When the context ended, which also
// ends the connection's deadline, it reports the context's error.
func (c *Client) fail(ctx context.Context, err error) error {
	c.broken = fmt.Errorf("ipc: connection lost: %w", err)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
		return context.DeadlineExceeded
	}
	return c.broken
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }
