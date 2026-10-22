// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package hdkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func xprvBytes(x *XPrv) string {
	return hex.EncodeToString(x.kl[:]) + hex.EncodeToString(x.kr[:]) + hex.EncodeToString(x.cc[:])
}

// TestCIP3 checks the root key against the Icarus vectors of CIP-3
// (CIP-0003/Icarus.md), with and without a passphrase.
func TestCIP3(t *testing.T) {
	e, err := Entropy([]byte("eight country switch draw meat scout mystery blade tip drift useless good keep usage title"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		passphrase string
		want       string
	}{
		{"", "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620"},
		{"foo", "70531039904019351e1afb361cd1b312a4d0565d4ff9f8062d38acf4b15cce41d7b5738d9c893feea55512a3004acb0d222c35d3e3d5cde943a15a9824cbac59443cf67e589614076ba01e354b1a432e0e6db3b59e37fc56b5fb0222970a010e"},
	} {
		x, err := icarus(e, []byte(tc.passphrase))
		if err != nil || xprvBytes(x) != tc.want {
			t.Errorf("passphrase %q: %s, %v", tc.passphrase, xprvBytes(x), err)
		}
	}
	x, _ := Root(e)
	if xprvBytes(x) != "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620" {
		t.Error("Root differs from icarus without passphrase")
	}
}

// csl are vectors of cardano-serialization-lib (rust/src/tests/address.rs and
// crypto.rs): the root key of a 15-word phrase, and the base addresses of
// m/1852'/1815'/0'/0/0 and m/1852'/1815'/0'/2/0 for phrases of 12, 15 and 24
// words, on preprod and mainnet.
var csl = []struct {
	entropy, preprod, mainnet string
}{
	{ // test walk nut penalty hip pave soap entry language right filter choice
		"df9ed25ed146bf43336a5d7cf7395994",
		"addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp",
		"addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwqfjkjv7",
	},
	{ // art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy
		"0ccb74f36b7da1649a8144675522d4d8097c6412",
		"addr_test1qpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5ewvxwdrt70qlcpeeagscasafhffqsxy36t90ldv06wqrk2qum8x5w",
		"addr1q9u5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5ewvxwdrt70qlcpeeagscasafhffqsxy36t90ldv06wqrk2qld6xc3",
	},
	{
		"4e828f9a67ddcff0e6391ad4f26ddb7579f59ba14b6dd4baf63dcfdb9d2420da",
		"addr_test1qqy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmn8k8ttq8f3gag0h89aepvx3xf69g0l9pf80tqv7cve0l33sw96paj",
		"addr1qyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmn8k8ttq8f3gag0h89aepvx3xf69g0l9pf80tqv7cve0l33sdn8p3d",
	},
}

func TestCSLRoot(t *testing.T) {
	x, err := Root(unhex(csl[1].entropy))
	const want = "b8f2bece9bdfe2b0282f5bad705562ac996efb6af96b648f4445ec44f47ad95c10e3d72f26ed075422a36ed8585c745a0e1150bcceba2357d058636991f38a3791e248de509c070d812ab2fda57860ac876bc489192c1ef4ce253c197ee219a4"
	if err != nil || xprvBytes(x) != want {
		t.Errorf("root: %s, %v", xprvBytes(x), err)
	}
}

// TestCSLAddresses goes from the entropy to the address: root, hardened and
// soft derivation, public keys, key hashes and the address header.
func TestCSLAddresses(t *testing.T) {
	for _, v := range csl {
		k, err := WalletKeys(unhex(v.entropy))
		if err != nil {
			t.Fatal(err)
		}
		pay, stake := k.Payment.PublicKey(), k.Stake.PublicKey()
		for _, n := range []struct {
			net  model.Network
			hrp  string
			want string
		}{{model.Preprod, "addr_test", v.preprod}, {model.Mainnet, "addr", v.mainnet}} {
			a := BaseAddress(n.net, pay, stake)
			if got := bech32(n.hrp, a.Raw); got != n.want {
				t.Errorf("%s on %s: %s", v.entropy, n.net, got)
			}
		}
	}
}

// TestCIP19 ties the payment key above to the test vectors of CIP-19, which
// use it: its bech32 form and its enterprise address.
func TestCIP19(t *testing.T) {
	k, _ := WalletKeys(unhex(csl[0].entropy))
	vk := k.Payment.PublicKey()
	if got := bech32("addr_vk", vk); got != "addr_vk1w0l2sr2zgfm26ztc6nl9xy8ghsk5sh6ldwemlpmp9xylzy4dtf7st80zhd" {
		t.Errorf("payment key %s", got)
	}
	h := KeyHash(vk)
	if got := bech32("addr_test", append([]byte{0x60}, h[:]...)); got != "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz" {
		t.Errorf("enterprise address %s", got)
	}
	a := BaseAddress(model.Preprod, vk, k.Stake.PublicKey())
	if a.Type != 0 || a.NetworkID != 0 || a.Payment.Hash != h || a.Stake == nil || !bytes.Equal(a.Raw[1:29], h[:]) {
		t.Errorf("address parts %+v", a)
	}
}

// TestSignMatchesEd25519 compares Sign with crypto/ed25519, an independent
// implementation: a key expanded from an Ed25519 seed as RFC 8032 does
// (kL = clamped SHA-512(seed)[0:32], kR = SHA-512(seed)[32:64]) must give the
// very same signature.
func TestSignMatchesEd25519(t *testing.T) {
	for i := range 300 {
		seed := make([]byte, ed25519.SeedSize)
		rand.Read(seed)
		msg := make([]byte, i)
		rand.Read(msg)
		h := sha512.Sum512(seed)
		x := new(XPrv)
		copy(x.kl[:], h[:32])
		copy(x.kr[:], h[32:])
		x.kl[0] &= 248
		x.kl[31] &= 127
		x.kl[31] |= 64
		std := ed25519.NewKeyFromSeed(seed)
		if !bytes.Equal(x.PublicKey(), std.Public().(ed25519.PublicKey)) {
			t.Fatalf("public key differs for seed %x", seed)
		}
		if !bytes.Equal(x.Sign(msg), ed25519.Sign(std, msg)) {
			t.Fatalf("signature differs for seed %x, message of %d bytes", seed, i)
		}
	}
}

// TestDerivedKeysSign checks that keys deep in the tree, whose kL is no longer
// clamped, still sign what crypto/ed25519 verifies.
func TestDerivedKeysSign(t *testing.T) {
	for _, v := range csl {
		k, _ := WalletKeys(unhex(v.entropy))
		for _, x := range []*XPrv{k.Payment, k.Stake, k.Payment.Derive(7, 1<<30, Hardened|5)} {
			msg := []byte("a transaction id, 32 bytes long.")
			if !ed25519.Verify(x.PublicKey(), msg, x.Sign(msg)) {
				t.Errorf("%s: a signature does not verify", v.entropy)
			}
		}
	}
}

func TestDeriveLeavesTheParent(t *testing.T) {
	root, _ := Root(unhex(csl[0].entropy))
	before := xprvBytes(root)
	a := root.Derive(purpose, coinType, Hardened)
	b := root.Derive(purpose).Derive(coinType).Derive(Hardened)
	if xprvBytes(root) != before || xprvBytes(a) != xprvBytes(b) {
		t.Error("Derive changed the parent or depends on how the path is split")
	}
	if xprvBytes(root.Derive()) != before {
		t.Error("an empty path is not a copy")
	}
	a.Wipe()
	if xprvBytes(a) != strings.Repeat("00", 96) || xprvBytes(b) == strings.Repeat("00", 96) {
		t.Error("Wipe")
	}
	if _, err := Root(make([]byte, 15)); err != ErrEntropy {
		t.Errorf("short entropy: %v", err)
	}
}

func TestKeysNeverPrint(t *testing.T) {
	k, _ := WalletKeys(unhex(csl[0].entropy))
	secret := hex.EncodeToString(k.Payment.kl[:8])
	var logs bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&logs, nil))
	l.Info("keys", "payment", k.Payment, "keys", k)
	out := []string{logs.String()}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
		out = append(out, fmt.Sprintf(verb, k.Payment), fmt.Sprintf(verb, *k.Payment), fmt.Sprintf(verb, k))
	}
	for _, o := range out {
		if strings.Contains(o, secret) || strings.Contains(strings.ToLower(o), secret) {
			t.Errorf("a key leaked: %s", o)
		}
	}
}

// bech32 encodes data as BIP-173 bech32 without the length limit, for
// comparing with the vectors.
func bech32(hrp string, data []byte) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	var five []byte
	acc, n := 0, 0
	for _, b := range data {
		acc = acc<<8 | int(b)
		n += 8
		for n >= 5 {
			n -= 5
			five = append(five, byte(acc>>n&31))
		}
	}
	if n > 0 {
		five = append(five, byte(acc<<(5-n)&31))
	}
	values := []byte{}
	for _, c := range hrp {
		values = append(values, byte(c>>5))
	}
	values = append(values, 0)
	for _, c := range hrp {
		values = append(values, byte(c&31))
	}
	values = append(append(values, five...), 0, 0, 0, 0, 0, 0)
	gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := range 5 {
			if top>>i&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	chk ^= 1
	var b strings.Builder
	b.WriteString(hrp + "1")
	for _, v := range five {
		b.WriteByte(charset[v])
	}
	for i := range 6 {
		b.WriteByte(charset[chk>>(5*(5-i))&31])
	}
	return b.String()
}
