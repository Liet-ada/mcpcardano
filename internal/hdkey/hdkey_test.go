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
	k := x.key()
	return hex.EncodeToString(k.kl[:]) + hex.EncodeToString(k.kr[:]) + hex.EncodeToString(k.cc[:])
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
		x, k := newXPrv()
		copy(k.kl[:], h[:32])
		copy(k.kr[:], h[32:])
		k.kl[0] &= 248
		k.kl[31] &= 127
		k.kl[31] |= 64
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

// paths are vectors of an independent implementation in Python, written from
// the standards for the review of hdkey (decision 121): keys and signatures
// from the entropy of csl[0], at the edges of the index range and deep in the
// tree. The first path gives the payment key of the vectors of CIP-19.
var paths = []struct {
	path              []uint32
	xprv, pubkey, sig string
}{
	{[]uint32{purpose, coinType, Hardened, 0, 0}, "b813a62becba674d8e29ce907ee3533f622d41e155768d58793cbad373e1a45e47f9d20ab7f78b023a2cf363c2217400a8c658dfd1c8057c4f62b6f6746d1c41dd75e154da417becec55cdd249327454138f082110297d5e87ab25e15fad150f", "73fea80d424276ad0978d4fe5310e8bc2d485f5f6bb3bf87612989f112ad5a7d", "732ebe2cfd33c7df23516645d5711532659687c167adfe8fadb03e8e264725061c8e04a18709fb98ec61c9826d7eb9ad180f1c4ed5a8ab88ac7e50c5d94b2a0b"},
	{[]uint32{purpose, coinType, Hardened, 2, 0}, "a0156d1fb884e6a7c549c32758d0ca72b237a5bee93cbfb9b983d59a70e1a45e7cef128a6d68df8047b86502e6663e8e8c10adbcc1f91f878849c4b56d4e1e12abbec7b28b61543d4b1401a1bb5b799770b79f5cb49ee7c539e5e6e4eb047367", "2c041c9c6a676ac54d25e2fdce44c56581e316ae43adc4c7bf17f23214d8d892", "425da1d3b48b49ff08bb082ab2a850de3dc9dc6d2a2cbbaabb54c65e8c80a3b5692dc8397cb1d60d316381c6d96739d838f67798fedf9ececdd7c96b0e235603"},
	{[]uint32{purpose, coinType, Hardened, 0, 1}, "e062f25ddbb7249b49aa1b08528bc047b6d081a79f999bc08c4814f173e1a45eecef3adcad12701624f702ac6a8b818158b5985930d467fa9830475f3b38db1ff7ab126f2884db9059fa09ca83be6b8bd0250426aeb62191bdd9861457b8bc91", "f626ab887eb5f40b502463ccf2ec5a7311676ee9e5d55c492059a366c0b4d4a1", "0ac95bfba7947bf26210d2d60a1adec3b175c66d95f920daaa441e37a4c739070ff28166660a0d02bbb5b30f3d00d033cd1748daba33bd65be7e50b3c989410a"},
	{[]uint32{purpose, coinType, 7 | Hardened, 0, 19}, "f07320fe962f7a09c1779e770fbbdf3bdabf998b31c1ce5c8852233c6de1a45e59ab584cd73f2a929e2f99d40ace47ebacac2897bf0b19c0b724d706311269900f003bf3bae4a82a300c0e1ba90d33f40915bd1e5659ec9a286aeb1b3eede4de", "5cebe2becad41e6f967cacb46bc993fd26c173d87c913d31a17733d3996e3448", "7bc33112b578e7ffaa261dc133eec6211685c24cd7d637ab27ed780fc3168e938399ac54733534350f68862e9e4aa70618b94870faabdeab222ffa28ba9bae03"},
	{[]uint32{0, 1, 2, 3, 4, 5}, "b8510736ee656984a7ff9172197affaf5b291519003f8581ff5f36dd7ae1a45e9237262c5d7653d5999511585e26b22593f2bcff803be19005e97ce93fe4bb4c3992b83c42b5715152e904a7d6b6a89790503172a298c98c6d86a0c7c6c833d5", "8de6e57f0bc870e4987a440d91dabc3cb8c643dac901f9014a75991a24aa4e4b", "3ea44053a68a5b4ea4707df696a8e4c9c1a9fc3454387d7822739328bdf91fcc11b0bcf3d8485e5246604f99afa6fcf66f600d06c2251091ba86b3cac1506b0f"},
	{[]uint32{1<<32 - 1, 1<<32 - 2, Hardened - 1, 1}, "501262d03bae3f5a012415b799f8597cc58321549b6efae16b8958b96be1a45ef4714722fb72054a3b8a29d02bc1ef9483ace32168148d60296eb9f18224c4474a92e6e96e8083695c4443b5dbdcecd1b9e979d20c693f5ba49948227f6914b8", "cfcefc4117ea69285d698d153393d9d68e3bb0d020c2c19e9946bcaa74b2ab6d", "a4296ac236828af30aad4a65e4e9efdd354b9299b1786b3aa8a9c387dcc12dd22835aef63c99edd689148ee8e9eca25a367eb52cf680339e4de71295ed45b700"},
	{[]uint32{purpose, coinType, Hardened, 0, 0, 9, 9, 9, 9}, "e0e3e9ecdfd8ecd9b5dd44b0e723bf1716a1b97e9838e68899c044a77fe1a45ea8a52144104058bf527aabe92be2940e197625f45585e5241cd1a763791c2b5f3d3f1def6830ec0b5cc30e9e2de10f0b661d28c0eb6ee38b98f4a2d50774f0f5", "b87f098b88e5138d2385d6ea70f27e2052b53d64018655f2a67e8b215fe839b3", "55926bef57ab4a271db5fe6eb8cac33c226ffbe76ef5cfa539991267a03482d6d38dcf85244e0c1dd81604cf7176d0b17d84480eb2a7f269776c505652cb9b07"},
}

// TestPaths checks the keys, and the signature bytes of keys deep in the
// tree, which ed25519.Verify alone does not fix: any nonce verifies.
func TestPaths(t *testing.T) {
	root, _ := Root(unhex(csl[0].entropy))
	msg := []byte("a transaction id, 32 bytes long.")
	for _, v := range paths {
		x := root.Derive(v.path...)
		if xprvBytes(x) != v.xprv || hex.EncodeToString(x.PublicKey()) != v.pubkey || hex.EncodeToString(x.Sign(msg)) != v.sig {
			t.Errorf("path %x differs", v.path)
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
	kl := k.Payment.key().kl[:8]
	// A key would show in hex, as decimal bytes, or as the raw bytes.
	secrets := []string{hex.EncodeToString(kl), strings.Trim(fmt.Sprint(kl), "[]"), string(kl)}
	var logs bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&logs, nil))
	l.Info("keys", "payment", k.Payment, "keys", k)
	out := []string{logs.String()}
	// fmt prints by reflection, without asking Formatter, for %p, %w and the
	// verbs it does not expect, and for unexported fields.
	type holder struct {
		key  XPrv
		keyp *XPrv
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d", "%p", "%w", "%c", "%t", "%T"} {
		for _, v := range []any{k.Payment, *k.Payment, k, holder{*k.Payment, k.Payment}, []XPrv{*k.Payment}} {
			out = append(out, fmt.Sprintf(verb, v))
		}
	}
	for _, o := range out {
		for _, s := range secrets {
			if strings.Contains(o, s) || strings.Contains(strings.ToLower(o), s) {
				t.Errorf("a key leaked: %q", o)
			}
		}
	}
}

// TestWipeZero wipes the zero Keys, which WalletKeys returns with an error.
func TestWipeZero(t *testing.T) {
	Keys{}.Wipe()
	new(XPrv).Wipe()
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
