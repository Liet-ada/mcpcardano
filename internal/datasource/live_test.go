// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build live

package datasource

import (
	"context"
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
}
