// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package mcp

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/datasource"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// witnessSet signs a transaction id as the hardware wallet would.
func witnessSet(t *testing.T, key ed25519.PrivateKey, id [32]byte) []byte {
	t.Helper()
	c, err := cborx.New(cborx.Limits{MaxDepth: 8, MaxArrayElements: 16, MaxMapPairs: 16, AllowTags: true})
	if err != nil {
		t.Fatal(err)
	}
	w, err := c.Marshal(map[uint64]any{0: cborx.Tag{Number: 258, Content: []any{
		[]any{[]byte(key.Public().(ed25519.PublicKey)), ed25519.Sign(key, id[:])}}}})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// pending builds and authorizes a draft and returns its id and tx id.
func (e *env) pending(lovelace string) (model.DraftID, [32]byte) {
	e.t.Helper()
	d := e.ok("build_payment", e.pay(lovelace))
	id := model.DraftID(d["draft_id"].(string))
	e.ok("authorize_draft", map[string]any{"draft_id": string(id)})
	draft, err := e.server.d.Drafts.Get(id)
	if err != nil {
		e.t.Fatal(err)
	}
	return id, draft.Tx.ID
}

func TestSubmitAndStatus(t *testing.T) {
	e := newEnv(t)
	id, txID := e.pending("5000000")
	w := hex.EncodeToString(witnessSet(t, e.priv, txID))
	txHex := hex.EncodeToString(txID[:])

	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	e.fails("submit_signed_transaction", map[string]any{"draft_id": string(id), "witness_set": hex.EncodeToString(witnessSet(t, other, txID))}, CodeDraftMismatch)
	if len(e.src.submitted) != 0 {
		t.Fatal("a mismatched signature was sent")
	}

	for range 2 {
		s := e.ok("submit_signed_transaction", map[string]any{"draft_id": string(id), "witness_set": w})
		if s["state"] != "submitted" || !strings.Contains(s["next"].(string), "get_draft") {
			t.Fatalf("after submit: %v", s)
		}
	}
	if len(e.src.submitted) != 1 {
		t.Fatalf("sent %d times", len(e.src.submitted))
	}
	if st := e.ok("get_transaction_status", map[string]any{"tx_id": txHex}); st["status"] != "in_mempool" || st["draft_id"] != string(id) {
		t.Errorf("status %v", st)
	}
	e.src.confirmations[txID] = 4
	if st := e.ok("get_transaction_status", map[string]any{"tx_id": txHex}); st["status"] != "confirmed" || st["depth"] != 4.0 {
		t.Errorf("status %v", st)
	}
	if st := e.ok("get_transaction_status", map[string]any{"tx_id": strings.Repeat("1", 64)}); st["status"] != "unknown" {
		t.Errorf("unknown transaction %v", st)
	}
}

func TestSubmitSignedTransaction(t *testing.T) {
	e := newEnv(t)
	id, txID := e.pending("5000000")
	d, _ := e.server.d.Drafts.Get(id)
	signed, err := d.Tx.Signed(witnessSet(t, e.priv, txID))
	if err != nil {
		t.Fatal(err)
	}
	if s := e.ok("submit_signed_transaction", map[string]any{"draft_id": string(id), "signed_tx": hex.EncodeToString(signed)}); s["state"] != "submitted" {
		t.Fatalf("after submit: %v", s)
	}
	// A signed transaction with another body is not this draft's.
	id2, tx2 := e.pending("6000000")
	other, _ := e.server.d.Drafts.Get(id)
	wrong, _ := other.Tx.Signed(witnessSet(t, e.priv, tx2))
	e.fails("submit_signed_transaction", map[string]any{"draft_id": string(id2), "signed_tx": hex.EncodeToString(wrong)}, CodeDraftMismatch)
	e.fails("submit_signed_transaction", map[string]any{"draft_id": string(id2)}, CodeInvalidParams)
}

func TestSubmitFailures(t *testing.T) {
	e := newEnv(t)

	// Another transaction spent an input: the draft fails and frees the rest.
	id, txID := e.pending("5000000")
	e.src.submitErr = fmt.Errorf("%w: BadInputsUTxO", datasource.ErrRejected)
	e.fails("submit_signed_transaction", map[string]any{"draft_id": string(id), "witness_set": hex.EncodeToString(witnessSet(t, e.priv, txID))}, CodeUTxOContention)
	if d, _ := e.server.d.Drafts.Get(id); d.State != "failed" || len(e.server.d.Drafts.Reserved(walletID)) != 0 {
		t.Errorf("after contention: %s", d.State)
	}

	// No clear answer: the draft stays signed and a retry asks again; then
	// BadInputsUTxO may be its own inputs, so it counts as sent.
	id, txID = e.pending("5000000")
	w := hex.EncodeToString(witnessSet(t, e.priv, txID))
	e.src.submitErr = datasource.ErrUnavailable
	f := e.fails("submit_signed_transaction", map[string]any{"draft_id": string(id), "witness_set": w}, CodeDatasourceUnavailable)
	if !strings.Contains(f.Hint, "signature is kept") {
		t.Errorf("hint %q", f.Hint)
	}
	if d, _ := e.server.d.Drafts.Get(id); d.State != "signed" {
		t.Fatalf("after an unclear send: %s", d.State)
	}
	e.src.submitErr = fmt.Errorf("%w: BadInputsUTxO", datasource.ErrRejected)
	if s := e.ok("submit_signed_transaction", map[string]any{"draft_id": string(id), "witness_set": w}); s["state"] != "submitted" {
		t.Errorf("retry after an unclear send: %v", s)
	}

	// Any other refusal is a failed draft and an internal error.
	id, txID = e.pending("5000000")
	e.src.submitErr = fmt.Errorf("%w: FeeTooSmallUTxO", datasource.ErrRejected)
	e.fails("submit_signed_transaction", map[string]any{"draft_id": string(id), "witness_set": hex.EncodeToString(witnessSet(t, e.priv, txID))}, CodeInternal)
	if d, _ := e.server.d.Drafts.Get(id); d.State != "failed" || d.Reason != "FeeTooSmallUTxO" {
		t.Errorf("after a refusal: %s %q", d.State, d.Reason)
	}
}
