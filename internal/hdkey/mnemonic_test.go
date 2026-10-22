// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package hdkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
)

// bip39Vectors are the English vectors of trezor/python-mnemonic
// (vectors.json): entropy and its phrase.
var bip39Vectors = [][2]string{
	{"00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"},
	{"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"},
	{"80808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"},
	{"ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"},
	{"000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"},
	{"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"},
	{"808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always"},
	{"ffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when"},
	{"0000000000000000000000000000000000000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"},
	{"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"},
	{"8080808080808080808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"},
	{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"},
	{"9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"},
	{"6610b25967cdcca9d59875f5cb50b0ea75433311869e930b", "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog"},
	{"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c", "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"},
	{"c0ba5a8e914111210f2bd131f3d5e08d", "scheme spot photo card baby mountain device kick cradle pact join borrow"},
	{"6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3", "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave"},
	{"9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863", "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside"},
	{"23db8160a31d3e0dca3688ed941adbf3", "cat swing flag economy stadium alone churn speed unique patch report train"},
	{"8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0", "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access"},
	{"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad", "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform"},
	{"f30f8c1da665478f49b001d94c5fc452", "vessel ladder alter error federal sibling chat ability sun glass valve picture"},
	{"c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05", "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump"},
	{"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f", "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"},
}

func TestWordList(t *testing.T) {
	// The SHA-256 of english.txt in bitcoin/bips.
	const want = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	if got := sha256.Sum256([]byte(english)); hex.EncodeToString(got[:]) != want {
		t.Fatalf("english.txt has SHA-256 %x", got)
	}
	l := wordlist()
	if len(l) != 2048 || !slices.IsSorted(l) || len(slices.Compact(slices.Clone(l))) != 2048 {
		t.Fatalf("%d words, sorted %v", len(l), slices.IsSorted(l))
	}
}

func TestBIP39Vectors(t *testing.T) {
	for _, v := range bip39Vectors {
		entropy, _ := hex.DecodeString(v[0])
		p, err := Phrase(entropy)
		if err != nil || string(p) != v[1] {
			t.Errorf("Phrase(%s) = %q, %v", v[0], p, err)
		}
		e, err := Entropy([]byte(v[1]))
		if err != nil || !bytes.Equal(e, entropy) {
			t.Errorf("Entropy(%q) = %x, %v", v[1], []byte(e), err)
		}
	}
}

func TestBadPhrases(t *testing.T) {
	good := bip39Vectors[len(bip39Vectors)-1][1] // 24 words
	words := strings.Fields(good)
	swapLast := func(w string) string { return strings.Join(append(slices.Clone(words[:23]), w), " ") }
	for _, tc := range []struct{ name, phrase string }{
		{"empty", ""},
		{"13 words", strings.Join(words[:13], " ")},
		{"27 words", good + " " + strings.Join(words[:3], " ")},
		{"a wrong checksum", swapLast("abandon")},
		{"an unknown word", swapLast("cardano")},
		{"uppercase", strings.ToUpper(good)},
		{"a word cut short", swapLast(words[23][:3])},
	} {
		if _, err := Entropy([]byte(tc.phrase)); !errors.Is(err, ErrPhrase) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// The error never quotes the phrase.
	_, err := Entropy([]byte(swapLast("cardano")))
	for _, w := range append(words, "cardano") {
		if len(w) > 3 && strings.Contains(err.Error(), w) {
			t.Errorf("the error quotes %q: %v", w, err)
		}
	}
	// White space around and between the words is allowed.
	if _, err := Entropy([]byte("  " + strings.ReplaceAll(good, " ", " \n\t") + "\n")); err != nil {
		t.Errorf("white space: %v", err)
	}
	for _, n := range []int{0, 15, 33, 18} {
		if _, err := Phrase(make([]byte, n)); !errors.Is(err, ErrEntropy) {
			t.Errorf("%d bytes of entropy: %v", n, err)
		}
	}
}

func TestNewEntropy(t *testing.T) {
	e, err := NewEntropy(nil)
	if err != nil || len(e) != EntropySize {
		t.Fatalf("%d bytes, %v", len(e), err)
	}
	p, err := Phrase(e)
	if err != nil || len(strings.Fields(string(p))) != 24 {
		t.Fatalf("phrase: %v", err)
	}
	back, err := Entropy(p)
	if err != nil || !bytes.Equal(back, e) {
		t.Errorf("round trip: %v", err)
	}
	if _, err := NewEntropy(bytes.NewReader(make([]byte, 31))); err == nil {
		t.Error("short randomness accepted")
	}
}

// FuzzEntropy feeds arbitrary phrases to Entropy. Nothing may panic, and what
// it accepts must be the phrase of the entropy it returns.
func FuzzEntropy(f *testing.F) {
	for _, v := range bip39Vectors {
		f.Add([]byte(v[1]))
	}
	f.Fuzz(func(t *testing.T, phrase []byte) {
		e, err := Entropy(phrase)
		if err != nil {
			return
		}
		p, err := Phrase(e)
		if err != nil || string(p) != strings.Join(strings.Fields(string(phrase)), " ") {
			t.Fatalf("accepted %q, which is not the phrase of %x", phrase, []byte(e))
		}
	})
}
