// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package sanitize neutralizes text that comes from the chain before it
// reaches the agent or the person (section 7.1 of the paper). Anyone can
// write such text for a few tenths of an ADA, so it is the cheapest prompt
// injection channel against an agent.
//
// Text keeps only visible characters: controls, invisible and format
// characters (zero-width, bidirectional, tags), variation selectors, private
// use and unassigned code points, invalid UTF-8 and every space other than
// the ASCII one become U+FFFD, so the manipulation shows instead of acting.
// The result is cut to a maximum length. Callers put it in a field whose name
// ends in _unverified (section 4.1 of the specification).
package sanitize

import (
	"unicode"
	"unicode/utf8"
)

// Replacement stands in for every character that is not visible.
const Replacement = '\uFFFD'

// Ellipsis marks text cut to its maximum length.
const Ellipsis = "\u2026"

// Text returns s with every character that is not visible replaced by
// U+FFFD, cut to at most max bytes. Text that is cut ends in an ellipsis,
// within the max. The result is always valid UTF-8, and Text does no more
// work than max allows, however long s is.
func Text(s string, max int) string {
	if max <= 0 {
		return ""
	}
	out := make([]byte, 0, min(len(s), max)+utf8.UTFMax)
	// Ranging over a string gives U+FFFD for each invalid byte.
	for _, r := range s {
		if !Visible(r) {
			r = Replacement
		}
		out = utf8.AppendRune(out, r)
		if len(out) > max {
			return cut(out, max)
		}
	}
	return string(out)
}

// cut shortens out to fit, with the ellipsis, in max bytes, never inside a
// character. A max too small for the ellipsis gets none.
func cut(out []byte, max int) string {
	limit, tail := max-len(Ellipsis), Ellipsis
	if limit < 0 {
		limit, tail = max, ""
	}
	for len(out) > limit {
		_, n := utf8.DecodeLastRune(out)
		out = out[:len(out)-n]
	}
	return string(out) + tail
}

// Visible reports whether r is a character that shows: a letter, mark,
// number, punctuation or symbol, or the ASCII space, and not one of the
// characters that are visible in name only.
func Visible(r rune) bool {
	if !unicode.IsPrint(r) {
		return false // controls, format characters, private use, unassigned, other spaces
	}
	switch {
	case unicode.Is(unicode.Variation_Selector, r),
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r), // Hangul fillers, combining grapheme joiner
		r == '\u2800': // Braille pattern blank, a symbol that draws nothing
		return false
	}
	return true
}

// Name returns the display text of a name from the chain, such as an asset
// name, or "" if it is not valid UTF-8. The caller then shows only its hex,
// which it always shows anyway, since the hex is what identifies the asset.
func Name(b []byte, max int) string {
	if !utf8.Valid(b) {
		return ""
	}
	return Text(string(b), max)
}
