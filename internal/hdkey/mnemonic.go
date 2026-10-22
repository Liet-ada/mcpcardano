// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package hdkey

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// english is the BIP-39 English word list, byte for byte as published in
// bitcoin/bips; a test checks its SHA-256.
//
//go:embed english.txt
var english string

var wordlist = sync.OnceValue(func() []string { return strings.Fields(english) })

// EntropySize is the entropy of a new wallet: 32 bytes, a 24-word phrase.
const EntropySize = 32

var (
	// ErrPhrase reports a recovery phrase that is not BIP-39. The error never
	// quotes the phrase.
	ErrPhrase = errors.New("hdkey: invalid recovery phrase")
)

// NewEntropy reads the entropy of a new wallet from r, or from crypto/rand if
// r is nil.
func NewEntropy(r io.Reader) (model.Secret, error) {
	if r == nil {
		r = rand.Reader
	}
	e := make(model.Secret, EntropySize)
	if _, err := io.ReadFull(r, e); err != nil {
		return nil, fmt.Errorf("hdkey: reading randomness: %w", err)
	}
	return e, nil
}

// Phrase returns the BIP-39 recovery phrase of the entropy: its bits followed
// by the first len/32 bits of its SHA-256, in groups of 11, each a word, with
// single spaces in between.
func Phrase(entropy []byte) (model.Secret, error) {
	n := len(entropy)
	if n < 16 || n > 32 || n%4 != 0 {
		return nil, ErrEntropy
	}
	sum := sha256.Sum256(entropy)
	bits := append(slices.Clone(entropy), sum[0]) // the checksum has at most 8 bits
	defer clear(bits)
	words := (n*8 + n/4) / 11
	list := wordlist()
	var out bytes.Buffer
	for w := range words {
		if w > 0 {
			out.WriteByte(' ')
		}
		out.WriteString(list[bitsAt(bits, w*11)])
	}
	return model.Secret(out.Bytes()), nil
}

// bitsAt reads 11 bits of b starting at bit off, most significant first.
func bitsAt(b []byte, off int) int {
	v := 0
	for i := range 11 {
		bit := off + i
		v = v<<1 | int(b[bit/8]>>(7-bit%8)&1)
	}
	return v
}

// Entropy reads a recovery phrase back into its entropy. The phrase has 12,
// 15, 18, 21 or 24 words of the English list, in lowercase, separated by
// white space, and its checksum must match.
func Entropy(phrase []byte) (model.Secret, error) {
	fields := bytes.Fields(phrase)
	words := len(fields)
	if words < 12 || words > 24 || words%3 != 0 {
		return nil, fmt.Errorf("%w: %d words, want 12, 15, 18, 21 or 24", ErrPhrase, words)
	}
	list := wordlist()
	bits := make([]byte, (words*11+7)/8)
	defer clear(bits)
	for w, f := range fields {
		idx, ok := slices.BinarySearch(list, string(f))
		if !ok {
			return nil, fmt.Errorf("%w: word %d is not in the list", ErrPhrase, w+1)
		}
		for i := range 11 {
			if idx>>(10-i)&1 == 1 {
				bit := w*11 + i
				bits[bit/8] |= 0x80 >> (bit % 8)
			}
		}
	}
	n := words * 11 * 32 / 33 / 8 // entropy bytes
	entropy := model.Secret(slices.Clone(bits[:n]))
	sum := sha256.Sum256(entropy)
	cs := n / 4 // checksum bits
	if bits[n]>>(8-cs) != sum[0]>>(8-cs) {
		entropy.Wipe()
		return nil, fmt.Errorf("%w: the checksum does not match", ErrPhrase)
	}
	return entropy, nil
}
