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

func mustCodec(t testing.TB, l Limits) *Codec {
	t.Helper()
	c, err := New(l)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type msg struct {
	ID   uint64 `cbor:"id"`
	Name string `cbor:"name"`
}

func TestMarshalIsCanonical(t *testing.T) {
	c := mustCodec(t, RecordLimits())
	// Keys sort by length first: "b" before "aa".
	got, err := c.Marshal(map[string]uint64{"aa": 1, "b": 500})
	if err != nil {
		t.Fatal(err)
	}
	want := unhex(t, "a261621901f462616101")
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestUnmarshalRejects(t *testing.T) {
	c := mustCodec(t, RecordLimits())
	cases := map[string]string{
		"duplicate key":     "a2616101616102",
		"indefinite array":  "9f01ff",
		"trailing bytes":    "0101",
		"invalid utf-8":     "62c328",
		"tag when disabled": "c11a5f000000",
		"too deep":          "818181818181818181818181818181818101",
	}
	for name, h := range cases {
		var v any
		if err := c.Unmarshal(unhex(t, h), &v); err == nil {
			t.Errorf("%s: decoded without error", name)
		}
	}
}

func TestUnmarshalStruct(t *testing.T) {
	c := mustCodec(t, RecordLimits())
	var m msg
	if err := c.Unmarshal(unhex(t, "a262696407646e616d6563616263"), &m); err != nil {
		t.Fatal(err)
	}
	if m != (msg{ID: 7, Name: "abc"}) {
		t.Fatalf("got %+v", m)
	}
	// Unknown field.
	if err := c.Unmarshal(unhex(t, "a362696407646e616d65636162636178f5"), &m); err == nil {
		t.Error("unknown field accepted")
	}
	// Field names are case-sensitive.
	if err := c.Unmarshal(unhex(t, "a162494407"), &m); err == nil {
		t.Error("field matched case-insensitively")
	}
}

func TestTagsWhenAllowed(t *testing.T) {
	l := RecordLimits()
	l.AllowTags = true
	c := mustCodec(t, l)
	// Tag 258 (a set) around [1, 2], as Cardano uses for inputs.
	if err := c.CheckCanonical(unhex(t, "d90102820102")); err != nil {
		t.Fatal(err)
	}
}

func TestCheckCanonical(t *testing.T) {
	c := mustCodec(t, RecordLimits())
	ok := []string{"00", "17", "1818", "a261621901f462616101", "4401020304", "a1410102"}
	for _, h := range ok {
		if err := c.CheckCanonical(unhex(t, h)); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
	bad := map[string]string{
		"non-minimal integer": "1801",
		"float not shortest":  "fb3ff0000000000000",
	}
	for name, h := range bad {
		err := c.CheckCanonical(unhex(t, h))
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A well-formed but unsorted map is reported as not canonical.
	if err := c.CheckCanonical(unhex(t, "a262616101616202")); !errors.Is(err, ErrNotCanonical) {
		t.Errorf("unsorted map: got %v, want ErrNotCanonical", err)
	}
}

func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte{0xa0}, 16); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(&buf, []byte{0x01, 0x02}, 16); err != nil {
		t.Fatal(err)
	}
	if got := buf.Bytes(); !bytes.Equal(got, unhex(t, "00000001a0000000020102")) {
		t.Fatalf("frames %x", got)
	}
	r := bytes.NewReader(buf.Bytes())
	for _, want := range [][]byte{{0xa0}, {0x01, 0x02}} {
		got, err := ReadFrame(r, 16)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("got %x, %v", got, err)
		}
	}
	if _, err := ReadFrame(r, 16); err != io.EOF {
		t.Fatalf("end: got %v, want io.EOF", err)
	}
}

func TestFrameErrors(t *testing.T) {
	cases := []struct {
		in   string
		want error
	}{
		{"000000", io.ErrUnexpectedEOF},
		{"00000003a0", io.ErrUnexpectedEOF},
		{"00000000", ErrEmptyFrame},
		{"ffffffff", ErrFrameTooLarge},
	}
	for _, tc := range cases {
		_, err := ReadFrame(bytes.NewReader(unhex(t, tc.in)), 16)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.in, err, tc.want)
		}
	}
	if err := WriteFrame(io.Discard, make([]byte, 17), 16); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("write too large: %v", err)
	}
	if err := WriteFrame(io.Discard, nil, 16); !errors.Is(err, ErrEmptyFrame) {
		t.Errorf("write empty: %v", err)
	}
}
