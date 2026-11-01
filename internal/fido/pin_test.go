// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package fido

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	authn "github.com/go-authn/fido"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
)

// ctapKey answers as a key does over CTAPHID, enough for the PIN: the
// handshake, getKeyAgreement, and a request for a token, which it keeps
// and refuses as a wrong PIN.
type ctapKey struct {
	t       *testing.T
	channel uint32
	agree   *ecdh.PrivateKey
	reasm   *authn.Reassembler
	asked   map[int]any   // the request for a token
	silent  []map[int]any // the assertions asked for
	holds   bool          // whether it has the credential
}

func newCTAPKey(t *testing.T) *ctapKey {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &ctapKey{t: t, channel: 0x01020304, agree: priv, reasm: authn.NewReassembler(0x01020304)}
}

func (k *ctapKey) reply(d *device, cmd byte, data []byte) {
	packets, err := authn.Split(k.channel, cmd, data)
	if err != nil {
		k.t.Error(err)
		return
	}
	for _, p := range packets {
		d.reads <- p
	}
}

func (k *ctapKey) answer(d *device, w []byte) {
	if len(w) != 1+authn.ReportSize || w[0] != 0 {
		return
	}
	r := w[1:]
	if binary.BigEndian.Uint32(r) == authn.BroadcastChannel && r[4] == 0x80|authn.CmdInit {
		init := make([]byte, 17)
		copy(init, r[7:15]) // the nonce
		binary.BigEndian.PutUint32(init[8:], k.channel)
		copy(init[12:], []byte{2, 5, 7, 4, byte(authn.CapWink | authn.CapCBOR)})
		packets, _ := authn.Split(authn.BroadcastChannel, authn.CmdInit, init)
		d.reads <- packets[0]
		return
	}
	msg, done, err := k.reasm.Feed(r)
	if err != nil || !done || msg.Cmd != authn.CmdCBOR || len(msg.Data) == 0 {
		return
	}
	c, _ := cborx.New(cborx.RecordLimits())
	if msg.Data[0] == 0x02 { // getAssertion
		var req map[int]any
		if err := c.Unmarshal(msg.Data[1:], &req); err != nil {
			k.t.Errorf("getAssertion: %v", err)
		}
		k.silent = append(k.silent, req)
		if k.holds {
			k.reply(d, authn.CmdCBOR, []byte{0x01}) // any other failure: it cannot say
			return
		}
		k.reply(d, authn.CmdCBOR, []byte{0x2e}) // CTAP2_ERR_NO_CREDENTIALS
		return
	}
	if msg.Data[0] != authn.CmdClientPIN {
		return
	}
	var params map[int]any
	if err := c.Unmarshal(msg.Data[1:], &params); err != nil {
		k.t.Errorf("clientPIN: %v", err)
		return
	}
	if params[0x02] == uint64(0x02) { // getKeyAgreement
		pub := k.agree.PublicKey().Bytes()
		body, _ := c.Marshal(map[int]any{0x01: map[int]any{1: 2, 3: -25, -1: 1, -2: pub[1:33], -3: pub[33:]}})
		k.reply(d, authn.CmdCBOR, append([]byte{0x00}, body...))
		return
	}
	k.asked = params
	k.reply(d, authn.CmdCBOR, []byte{0x31}) // CTAP2_ERR_PIN_INVALID
}

// TestPINTokenWithGetPinToken: the token is asked for with getPinToken
// (0x05), with the key agreement and the PIN's hash and nothing else. With
// permissions, go-authn/fido v0.6.2 puts them under keys a YubiKey does not
// read, which E5 found as CTAP2_ERR_MISSING_PARAMETER.
func TestPINTokenWithGetPinToken(t *testing.T) {
	ck := newCTAPKey(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ak, err := authn.Open(ctx, newHidraw(newDevice(ck.answer), "test key"))
	if err != nil {
		t.Fatal(err)
	}
	defer ak.Close()
	k := &key{k: ak, info: authn.Info{PINProtocols: []uint{2, 1}, Options: map[string]bool{"clientPin": true}}}
	if _, err := k.token(ctx, "1234"); err == nil {
		t.Fatal("a token from a key that refused the PIN")
	}
	if ck.asked == nil {
		t.Fatal("no request for a token")
	}
	if ck.asked[0x02] != uint64(0x05) || ck.asked[0x01] != uint64(2) {
		t.Errorf("subcommand %v with protocol %v, want getPinToken (5) with protocol 2", ck.asked[0x02], ck.asked[0x01])
	}
	for _, key := range []int{0x03, 0x06} {
		if ck.asked[key] == nil {
			t.Errorf("no parameter %#x", key)
		}
	}
	for _, key := range []int{0x07, 0x08, 0x09, 0x0a} {
		if _, ok := ck.asked[key]; ok {
			t.Errorf("parameter %#x sent", key)
		}
	}

	// A key that gives tokens only with permissions is refused here, before
	// anything is sent.
	ck.asked = nil
	k.info.Options["noMcGaPermissionsWithClientPin"] = true
	if _, err := k.token(ctx, "1234"); err == nil || ck.asked != nil {
		t.Errorf("a key that wants permissions: %v, asked %v", err, ck.asked)
	}
}

// TestNoPINForAnotherKey: a key that holds none of the credentials hears
// nothing of the PIN, and the error names it. The question takes no touch and
// no PIN.
func TestNoPINForAnotherKey(t *testing.T) {
	ck := newCTAPKey(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ak, err := authn.Open(ctx, newHidraw(newDevice(ck.answer), "Trezor Safe 7"))
	if err != nil {
		t.Fatal(err)
	}
	defer ak.Close()
	k := &key{k: ak, info: authn.Info{PINProtocols: []uint{2, 1}, Options: map[string]bool{"clientPin": true}}}
	_, err = k.Assert(ctx, "mcpcardano", make([]byte, 32), [][]byte{{1}}, "1234")
	if !errors.Is(err, ErrNotRegistered) || !strings.Contains(err.Error(), "Trezor Safe 7 is not a registered key") {
		t.Fatalf("Assert: %v", err)
	}
	if ck.asked != nil {
		t.Error("the PIN reached a key that is not registered")
	}
	if len(ck.silent) != 1 {
		t.Fatalf("%d assertions asked for", len(ck.silent))
	}
	if opts, _ := ck.silent[0][5].(map[any]any); opts["up"] != false {
		t.Errorf("the question asks for a touch: %v", ck.silent[0][5])
	}
	if _, ok := ck.silent[0][6]; ok {
		t.Error("the question carries a PIN token")
	}
}

// TestPINForTheKey: a key that does not say no goes on to the PIN.
func TestPINForTheKey(t *testing.T) {
	ck := newCTAPKey(t)
	ck.holds = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ak, err := authn.Open(ctx, newHidraw(newDevice(ck.answer), "YubiKey"))
	if err != nil {
		t.Fatal(err)
	}
	defer ak.Close()
	k := &key{k: ak, info: authn.Info{PINProtocols: []uint{2, 1}, Options: map[string]bool{"clientPin": true}}}
	if _, err = k.Assert(ctx, "mcpcardano", make([]byte, 32), [][]byte{{1}}, "1234"); errors.Is(err, ErrNotRegistered) {
		t.Fatalf("Assert: %v", err)
	}
	if ck.asked == nil {
		t.Error("the PIN did not reach the key")
	}
}
