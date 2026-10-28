// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build live

package datasource

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// TestLiveKoiosPreprod is the exit check of step 2 of H-1: it reads the tip,
// the protocol parameters and the UTxOs of an address from the public preprod
// endpoint. Run it with `make live`. MCPCARDANO_LIVE_ADDRESS picks another
// address; by default it uses the recorded one, whose UTxOs may have been
// spent since.
func TestLiveKoiosPreprod(t *testing.T) {
	chain.Configure()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	k, err := NewKoios(KoiosConfig{Network: model.Preprod})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.CheckNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	tip, err := k.Tip(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if age := time.Since(tip.Time); age > 10*time.Minute {
		t.Errorf("tip is %s old", age)
	}
	t.Logf("tip: slot %d, height %d, epoch %d, %s", tip.Slot, tip.Height, tip.Epoch, tip.Time)

	p, err := k.ProtocolParameters(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parameters: epoch %d, protocol %d.%d, fee %d·size + %d", p.Epoch, p.ProtocolMajor, p.ProtocolMinor, p.MinFeeA, p.MinFeeB)

	bech := os.Getenv("MCPCARDANO_LIVE_ADDRESS")
	if bech == "" {
		bech = fixture(t, "address.txt")
	}
	addr, err := chain.ParseAddress(model.Preprod, bech)
	if err != nil {
		t.Fatal(err)
	}
	utxos, err := k.UTxOs(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, u := range utxos {
		total += u.Value.Lovelace
	}
	t.Logf("UTxOs: %d, %d lovelace", len(utxos), total)

	acc, err := k.Account(ctx, delegatingAccount)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("account: registered %v, pool %s, drep %s", acc.Registered, acc.Pool, acc.DRep)
	id, err := k.AssetByFingerprint(ctx, cip25Fingerprint)
	if err != nil || id.String() != cip25Asset {
		t.Fatalf("fingerprint: %s, %v", id, err)
	}
	a, err := k.Asset(ctx, id)
	if err != nil || a.Standard != CIP25 {
		t.Fatalf("asset: %v", err)
	}
	t.Logf("asset %s: supply %s", id, a.Supply)
	tx, err := k.Transaction(ctx, txID(t, mintTx))
	if err != nil {
		t.Fatal(err)
	}
	d, err := chain.DecodeTransaction(tx.CBOR)
	if err != nil || hex.EncodeToString(d.ID[:]) != mintTx {
		t.Fatalf("the CBOR is not the transaction: %v", err)
	}
	t.Logf("transaction %s in block %d", mintTx, tx.BlockHeight)

	// More transactions than one request to the public endpoint can carry.
	ids := [][32]byte{txID(t, mintTx)}
	for i := 1; i < 120; i++ {
		ids = append(ids, [32]byte{byte(i), 0xff})
	}
	confirmations, err := k.Confirmations(ctx, ids)
	if err != nil || confirmations[ids[0]] == 0 || confirmations[ids[1]] != 0 {
		t.Fatalf("confirmations: %v", err)
	}
	t.Logf("%d confirmations of %s among %d transactions", confirmations[ids[0]], mintTx, len(ids))
}

// TestLiveBlockfrostPreprod reads preprod through Blockfrost and, if Koios
// answers, checks that both clients read the same chain (decision 136). It
// needs the project id of a Blockfrost project for preprod, in the file
// MCPCARDANO_BLOCKFROST_KEY_FILE; without it, it is skipped. Run it with
// `make live`.
func TestLiveBlockfrostPreprod(t *testing.T) {
	keyFile := os.Getenv("MCPCARDANO_BLOCKFROST_KEY_FILE")
	if keyFile == "" {
		t.Skip("MCPCARDANO_BLOCKFROST_KEY_FILE names no file with a project id")
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	chain.Configure()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	b, err := NewBlockfrost(BlockfrostConfig{Network: model.Preprod, ProjectID: strings.TrimSpace(string(key))})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.CheckNetwork(ctx); err != nil {
		t.Fatal(err)
	}

	tip, err := b.Tip(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if age := time.Since(tip.Time); age > 10*time.Minute {
		t.Errorf("tip is %s old", age)
	}
	t.Logf("tip: slot %d, height %d, epoch %d, %s", tip.Slot, tip.Height, tip.Epoch, tip.Time)
	p, err := b.ProtocolParameters(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parameters: epoch %d, protocol %d.%d, fee %d·size + %d", p.Epoch, p.ProtocolMajor, p.ProtocolMinor, p.MinFeeA, p.MinFeeB)

	bech := os.Getenv("MCPCARDANO_LIVE_ADDRESS")
	if bech == "" {
		bech = fixture(t, "address.txt")
	}
	addr, err := chain.ParseAddress(model.Preprod, bech)
	if err != nil {
		t.Fatal(err)
	}
	utxos, err := b.UTxOs(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("UTxOs: %d", len(utxos))
	acc, err := b.Account(ctx, delegatingAccount)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("account: registered %v, pool %s, drep %s", acc.Registered, acc.Pool, acc.DRep)
	assets := map[string]Asset{}
	for _, s := range []string{cip25Asset, cip68Asset} {
		a, err := b.Asset(ctx, asset(t, s))
		if err != nil || a.Standard == "" || a.Metadata == nil {
			t.Fatalf("asset %s: %+v, %v", s, a, err)
		}
		assets[s] = a
		t.Logf("asset %s: %s, supply %s, metadata %v", s, a.Standard, a.Supply, a.Metadata)
	}
	if _, err := b.AssetByFingerprint(ctx, cip25Fingerprint); !errors.Is(err, ErrUnsupported) {
		t.Errorf("fingerprint: %v", err)
	}
	tx, err := b.Transaction(ctx, txID(t, mintTx))
	if err != nil {
		t.Fatal(err)
	}
	d, err := chain.DecodeTransaction(tx.CBOR)
	if err != nil || hex.EncodeToString(d.ID[:]) != mintTx {
		t.Fatalf("the CBOR is not the transaction: %v", err)
	}
	ids := [][32]byte{txID(t, mintTx), {1, 0xff}}
	conf, err := b.Confirmations(ctx, ids)
	if err != nil || conf[ids[0]] == 0 || conf[ids[1]] != 0 {
		t.Fatalf("confirmations %v: %v", conf, err)
	}
	t.Logf("transaction %s in block %d, %d confirmations", mintTx, tx.BlockHeight, conf[ids[0]])

	// The same chain through Koios, if it answers: the public endpoint
	// limits each address to a quota a day.
	k, err := NewKoios(KoiosConfig{Network: model.Preprod})
	if err != nil {
		t.Fatal(err)
	}
	kt, err := k.Tip(ctx)
	if err != nil {
		t.Logf("Koios does not answer (%v): nothing to compare with", err)
		return
	}
	if gap := int64(tip.Height) - int64(kt.Height); gap > 3 || gap < -3 {
		t.Errorf("Blockfrost's tip is at %d and Koios's at %d", tip.Height, kt.Height)
	}
	if kp, err := k.ProtocolParameters(ctx); err != nil || p != kp {
		t.Errorf("parameters differ:\nBlockfrost %+v\nKoios      %+v (%v)", p, kp, err)
	}
	if ku, err := k.UTxOs(ctx, addr); err != nil || !reflect.DeepEqual(utxos, ku) {
		t.Errorf("UTxOs differ: Blockfrost %d, Koios %d (%v); a block between the two reads can do it, so run it again", len(utxos), len(ku), err)
	}
	if ka, err := k.Account(ctx, delegatingAccount); err != nil || acc.Registered != ka.Registered || acc.Pool != ka.Pool || acc.DRep != ka.DRep {
		t.Errorf("accounts differ: Blockfrost %+v, Koios %+v (%v)", acc, ka, err)
	}
	for s, a := range assets {
		if ka, err := k.Asset(ctx, asset(t, s)); err != nil || a.Standard != ka.Standard || a.Supply != ka.Supply {
			t.Errorf("asset %s: Blockfrost %+v, Koios %+v (%v)", s, a, ka, err)
		}
	}
	if ktx, err := k.Transaction(ctx, txID(t, mintTx)); err != nil || !reflect.DeepEqual(tx, ktx) {
		t.Errorf("transactions differ: %v", err)
	}
}
