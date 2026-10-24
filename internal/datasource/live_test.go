// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build live

package datasource

import (
	"context"
	"encoding/hex"
	"os"
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
	if err != nil || a.CIP25 == nil {
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
