// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cborx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// FrameHeaderSize is the length prefix of a frame: a big-endian uint32.
const FrameHeaderSize = 4

var (
	// ErrFrameTooLarge reports a frame whose declared length exceeds the
	// maximum. It is detected before reading the payload.
	ErrFrameTooLarge = errors.New("cborx: frame exceeds maximum size")
	// ErrEmptyFrame reports a frame with a zero length.
	ErrEmptyFrame = errors.New("cborx: empty frame")
)

// WriteFrame writes the length prefix and the payload in a single Write, so a
// record appended to a file is either fully there or cut short, never
// interleaved with another one.
func WriteFrame(w io.Writer, payload []byte, max int) error {
	if len(payload) == 0 {
		return ErrEmptyFrame
	}
	if len(payload) > max {
		return ErrFrameTooLarge
	}
	buf := make([]byte, FrameHeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload)))
	copy(buf[FrameHeaderSize:], payload)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("cborx: write frame: %w", err)
	}
	return nil
}

// ReadFrame reads one frame of at most max bytes. It returns io.EOF when r
// ends cleanly before a frame, and io.ErrUnexpectedEOF when it ends inside
// one, which on a record file means a write was interrupted.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [FrameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, ErrEmptyFrame
	}
	if uint64(n) > uint64(max) {
		return nil, ErrFrameTooLarge
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return payload, nil
}
