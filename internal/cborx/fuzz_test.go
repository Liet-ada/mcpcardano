// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cborx

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

var fuzzSeeds = []string{
	"00", "17", "1818", "20", "3bffffffffffffffff", "40", "60", "80", "a0",
	"a262696407646e616d6563616263", "d90102820102", "c249010000000000000000",
	"f4", "f5", "f6", "f93c00", "fb3ff0000000000000", "9f01ff", "a2616101616102",
	"818181818181818181818181818181818101", "5f4101ff", "1801",
}

func addSeeds(f *testing.F) {
	for _, s := range fuzzSeeds {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
}

// FuzzCheckCanonical checks that decoding untrusted input never panics and
// that whatever passes as canonical re-encodes to the very same bytes, with
// and without tags.
func FuzzCheckCanonical(f *testing.F) {
	addSeeds(f)
	plain := mustCodec(f, RecordLimits())
	tl := RecordLimits()
	tl.AllowTags = true
	tagged := mustCodec(f, tl)

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, c := range []*Codec{plain, tagged} {
			if err := c.CheckCanonical(data); err != nil {
				continue
			}
			var v any
			if err := c.Unmarshal(data, &v); err != nil {
				t.Fatalf("canonical input %x does not decode: %v", data, err)
			}
			b, err := c.Marshal(v)
			if err != nil {
				t.Fatalf("canonical input %x does not re-encode: %v", data, err)
			}
			if !bytes.Equal(b, data) {
				t.Fatalf("canonical input %x re-encodes as %x", data, b)
			}
		}
	})
}

// FuzzReadFrame checks that a stream of frames never panics, never returns a
// frame longer than the maximum and stops at the first error.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0xa0})
	f.Add([]byte{0, 0, 0, 2, 1})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 0})
	const max = 64
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		read := 0
		for {
			p, err := ReadFrame(r, max)
			if err != nil {
				if errors.Is(err, io.EOF) && read != len(data) {
					t.Fatalf("clean EOF after %d of %d bytes", read, len(data))
				}
				return
			}
			if len(p) == 0 || len(p) > max {
				t.Fatalf("frame of %d bytes", len(p))
			}
			read += FrameHeaderSize + len(p)
		}
	})
}
