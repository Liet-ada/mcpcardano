// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/datasource"
	"github.com/Liet-ada/mcpcardano/internal/drafts"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// sendState remembers the drafts whose last send got no clear answer: the
// node may hold them already, so a later BadInputsUTxO may be their own
// inputs (section 9.4).
type sendState struct {
	mu        sync.Mutex
	uncertain map[model.DraftID]bool
}

func (s *sendState) mark(id model.DraftID, uncertain bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if uncertain {
		s.uncertain[id] = true
	} else {
		delete(s.uncertain, id)
	}
}

func (s *sendState) wasUncertain(id model.DraftID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uncertain[id]
}

func (s *Server) registerSubmit() error {
	for _, err := range []error{
		addTool(s, tool{name: "submit_signed_transaction", destructive: true, openWorld: true,
			description: "Takes the signature of a draft, as the witness set or the whole signed transaction in CBOR hex, checks that it belongs exactly to the draft and sends the transaction to the network, which moves funds irreversibly. The mode A signer and `mcpcardano sign` use it after the person confirms on the hardware wallet."},
			s.submitSigned),
		addTool(s, tool{name: "get_transaction_status", readOnly: true, openWorld: true,
			description: "Where a transaction is: in_mempool (sent and not yet in a block), confirmed with its depth, rolled_back, expired, failed or unknown."},
			s.transactionStatus),
	} {
		if err != nil {
			return err
		}
	}
	return nil
}

type submitArg struct {
	DraftID    string `json:"draft_id" jsonschema:"The draft the signature is for."`
	WitnessSet string `json:"witness_set,omitempty" jsonschema:"The witness set in CBOR hex. Give this or signed_tx."`
	SignedTx   string `json:"signed_tx,omitempty" jsonschema:"The whole signed transaction in CBOR hex. Give this or witness_set."`
}

func (s *Server) submitSigned(ctx context.Context, a submitArg) (draftView, error) {
	id, err := draftID(a.DraftID)
	if err != nil {
		return draftView{}, err
	}
	var witnesses []byte
	switch {
	case (a.WitnessSet == "") == (a.SignedTx == ""):
		return draftView{}, invalid("give witness_set or signed_tx, not both")
	case len(a.WitnessSet) > 2*drafts.MaxWitnessBytes || len(a.SignedTx) > 2*MaxDecodeBytes:
		return draftView{}, invalid("the signature is too large")
	case a.WitnessSet != "":
		if witnesses, err = hex.DecodeString(a.WitnessSet); err != nil {
			return draftView{}, invalid("witness_set is not hex")
		}
	default:
		raw, err := hex.DecodeString(a.SignedTx)
		if err != nil {
			return draftView{}, invalid("signed_tx is not hex")
		}
		d, err := s.d.Drafts.Get(id)
		if err != nil {
			return draftView{}, err
		}
		if witnesses, err = witnessesOf(raw, d); err != nil {
			return draftView{}, err
		}
	}
	d, err := s.d.Drafts.Sign(id, witnesses)
	if err != nil {
		return draftView{}, err
	}
	if d.State != drafts.StateSigned {
		return s.view(d, false) // sent already: the same answer again
	}
	return s.send(ctx, d)
}

// witnessesOf takes the witness set out of a whole signed transaction, which
// must hold exactly the draft's body and auxiliary data.
func witnessesOf(raw []byte, d drafts.Draft) ([]byte, error) {
	c, err := cborx.New(cborx.Limits{MaxDepth: 64, MaxArrayElements: 1 << 16, MaxMapPairs: 1 << 16, AllowTags: true})
	if err != nil {
		return nil, err
	}
	var parts []cborx.Raw
	if err := c.Unmarshal(raw, &parts); err != nil || len(parts) != 4 {
		return nil, invalid("signed_tx is not a transaction")
	}
	aux := []byte{0xf6} // null
	if d.Tx.AuxData != nil {
		aux = d.Tx.AuxData
	}
	if !bytes.Equal(parts[0], d.Tx.Body) || !bytes.Equal(parts[3], aux) || !bytes.Equal(parts[2], []byte{0xf5}) {
		return nil, fmt.Errorf("%w: signed_tx is not this draft's transaction", drafts.ErrMismatch)
	}
	return parts[1], nil
}

// send sends a signed draft. It never sends blindly twice (section 9.6): if
// an earlier send got no clear answer, it first asks whether the
// transaction is already in the chain.
func (s *Server) send(ctx context.Context, d drafts.Draft) (draftView, error) {
	retry := s.sends.wasUncertain(d.ID)
	if retry {
		if _, err := s.src(ctx).Transaction(ctx, d.Tx.ID); err == nil {
			return s.sent(d)
		}
	}
	err := s.src(ctx).Submit(ctx, d.Signed, d.Tx.ID)
	switch {
	case err == nil:
		return s.sent(d)
	case errors.Is(err, datasource.ErrRejected) && strings.Contains(err.Error(), "BadInputsUTxO"):
		if retry {
			// Our own earlier send may be what spent the inputs; the chain
			// decides, or the TTL.
			return s.sent(d)
		}
		s.d.Drafts.Failed(d.ID, "BadInputsUTxO")
		return draftView{}, newError(CodeUTxOContention, "an input of the draft was spent by another transaction")
	case errors.Is(err, datasource.ErrRejected):
		s.d.Drafts.Failed(d.ID, strings.TrimPrefix(err.Error(), datasource.ErrRejected.Error()+": "))
		return draftView{}, fmt.Errorf("mcp: the node rejected draft %s: %w", d.ID, err)
	default:
		s.sends.mark(d.ID, true)
		e := translate(err)
		e.Hint = "Nobody knows yet whether the transaction arrived. The signature is kept: call submit_signed_transaction again later, or follow the draft with get_draft."
		return draftView{}, e
	}
}

func (s *Server) sent(d drafts.Draft) (draftView, error) {
	s.sends.mark(d.ID, false)
	d, err := s.d.Drafts.Submitted(d.ID)
	if err != nil {
		return draftView{}, err
	}
	return s.view(d, false)
}

type statusArg struct {
	TxID string `json:"tx_id" jsonschema:"The transaction id, 64 hex characters."`
}

type statusView struct {
	Network string `json:"network"`
	TxID    string `json:"tx_id"`
	Status  string `json:"status"`
	Depth   uint64 `json:"depth,omitempty"`
	DraftID string `json:"draft_id,omitempty"`
}

// transactionStatus answers from the chain, and for the server's own drafts
// also from what it knows: sent, rolled back, expired or failed.
func (s *Server) transactionStatus(ctx context.Context, a statusArg) (statusView, error) {
	b, err := hex.DecodeString(a.TxID)
	if err != nil || len(b) != 32 || strings.ToLower(a.TxID) != a.TxID {
		return statusView{}, invalid("tx_id must be 64 lowercase hex characters")
	}
	id := [32]byte(b)
	out := statusView{Network: string(s.d.Network), TxID: a.TxID, Status: "unknown"}
	confirmations, err := s.src(ctx).Confirmations(ctx, [][32]byte{id})
	if err != nil {
		return statusView{}, err
	}
	if n := confirmations[id]; n > 0 {
		out.Status, out.Depth = "confirmed", n
	}
	d, err := s.d.Drafts.ByTx(id)
	if err != nil {
		// A transaction the wallet signed before the server's restart, which
		// the watcher follows (section 9.5).
		if o, ok := s.orphanOf(id); ok && o.expired && out.Status != "confirmed" {
			out.Status = "expired"
		}
		return out, nil
	}
	out.DraftID = string(d.ID)
	if out.Status == "confirmed" {
		return out, nil
	}
	switch d.State {
	case drafts.StateSigned, drafts.StateSubmitted:
		out.Status = "in_mempool"
	case drafts.StateRolledBack:
		out.Status = "rolled_back"
	case drafts.StateExpired:
		out.Status = "expired"
	case drafts.StateFailed:
		out.Status = "failed"
	}
	return out, nil
}
