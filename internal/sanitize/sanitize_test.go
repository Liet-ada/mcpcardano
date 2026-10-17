// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

const r = "\uFFFD"

func TestText(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "Pago de la factura 42", "Pago de la factura 42"},
		{"accents and emoji", "Árbol ñandú 🌳", "Árbol ñandú 🌳"},
		{"newline and tab", "line1\nline2\tend", "line1" + r + "line2" + r + "end"},
		{"escape sequence", "\x1b[31mred", r + "[31mred"},
		{"C1 control", "a\u0085b", "a" + r + "b"},
		{"right-to-left override", "invoice\u202Etxt.exe", "invoice" + r + "txt.exe"},
		{"isolates", "\u2066a\u2069", r + "a" + r},
		{"zero-width space and joiner", "ig\u200Bnore\u200D", "ig" + r + "nore" + r},
		{"byte order mark", "\uFEFFhi", r + "hi"},
		{"soft hyphen", "pay\u00ADment", "pay" + r + "ment"},
		{"tag characters", "ok\U000E0049\U000E0067", "ok" + r + r},
		{"variation selectors", "a\uFE0F\U000E0100", "a" + r + r},
		{"Hangul filler", "\u3164name", r + "name"},
		{"Braille blank", "\u2800\u2800", r + r},
		{"private use", "\uE000x", r + "x"},
		{"unassigned", "\U000EFFFF", r},
		{"no-break and wide spaces", "a\u00A0b\u3000c", "a" + r + "b" + r + "c"},
		{"line separator", "a\u2028b", "a" + r + "b"},
		{"invalid UTF-8", "ok\xff\xfe", "ok" + r + r},
		{"truncated rune", "ok\xe2\x82", "ok" + r + r},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Text(c.in, 1000); got != c.want {
				t.Errorf("Text(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestTextCuts(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"abcdef", 6, "abcdef"},
		{"abcdefg", 6, "abc\u2026"},
		{"ñññ", 6, "ñññ"},
		{"ññññ", 6, "ñ\u2026"},
		{"a\u202Eb", 5, "a\uFFFDb"}, // the replacement takes 3 bytes: 1+3+1
		{"a\u202Eb", 4, "a\u2026"},
		{"abcdef", 2, "ab"}, // no room for the ellipsis
		{"ñ", 1, ""},
		{"abc", 0, ""},
		{"abc", -1, ""},
	}
	for _, c := range cases {
		if got := Text(c.in, c.max); got != c.want {
			t.Errorf("Text(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}

// TestTextBoundsWork feeds a huge input with a small max: the work and the
// result follow the max, not the input.
func TestTextBoundsWork(t *testing.T) {
	in := strings.Repeat("\u202E", 1<<20)
	got := Text(in, 64)
	if len(got) > 64 || !strings.HasSuffix(got, Ellipsis) {
		t.Fatalf("got %d bytes: %q", len(got), got)
	}
	allocs := testing.AllocsPerRun(10, func() { Text(in, 64) })
	if allocs > 3 {
		t.Errorf("%v allocations for a 64-byte result", allocs)
	}
}

func TestName(t *testing.T) {
	if got := Name([]byte("HOSKY"), 64); got != "HOSKY" {
		t.Errorf("Name = %q", got)
	}
	// A CIP-68 reference token: a binary label and then the name.
	if got := Name([]byte("\x00\x06\x43\xb0Name"), 64); got != "" {
		t.Errorf("a name that is not UTF-8 gave %q", got)
	}
	if got := Name([]byte("a\u200Bb"), 64); got != "a"+r+"b" {
		t.Errorf("Name = %q", got)
	}
}

// FuzzText checks the properties every caller relies on, for any input.
func FuzzText(f *testing.F) {
	for _, s := range []string{"", "hello", "a\u202Eb", "\xff", "ñ\u200B\U000E0041", strings.Repeat("x", 300)} {
		f.Add(s, 64)
	}
	f.Fuzz(func(t *testing.T, s string, limit int) {
		limit %= 512
		got := Text(s, limit)
		if !utf8.ValidString(got) {
			t.Fatalf("invalid UTF-8: %q", got)
		}
		if len(got) > max(limit, 0) {
			t.Fatalf("%d bytes for max %d", len(got), limit)
		}
		for _, c := range got {
			if !Visible(c) {
				t.Fatalf("invisible %U in %q", c, got)
			}
		}
		if again := Text(got, limit); again != got {
			t.Fatalf("not idempotent: %q then %q", got, again)
		}
		if len(s) <= limit && utf8.ValidString(s) && strings.IndexFunc(s, func(c rune) bool { return !Visible(c) }) < 0 && got != s {
			t.Fatalf("changed visible text %q into %q", s, got)
		}
	})
}
