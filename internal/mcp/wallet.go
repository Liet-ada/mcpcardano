// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/drafts"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/policy"
)

// ErrWalletUnavailable reports a wallet process that does not answer, or a
// server configured without one.
var ErrWalletUnavailable = errors.New("mcp: the wallet process does not answer")

// WalletConn is the server's end of the wallet's service socket (section
// 5.3): one connection, dialed when first needed and dialed again once when
// it breaks. A request is sent again only on a new connection, and every
// request the server sends is idempotent at the wallet (section 9.4).
type WalletConn struct {
	Path  string
	Hello ipc.Hello

	mu     sync.Mutex
	client *ipc.Client
}

// Call sends a request and decodes the response. A failed response comes
// back as *ipc.Error; a wallet that cannot be reached, as
// ErrWalletUnavailable.
func (w *WalletConn) Call(ctx context.Context, t string, req, resp ipc.Body) error {
	if w == nil {
		return fmt.Errorf("%w: this server has no wallet process", ErrWalletUnavailable)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for attempt := range 2 {
		if w.client == nil {
			c, err := ipc.Dial(ctx, w.Path, w.Hello)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrWalletUnavailable, err)
			}
			w.client = c
		}
		err := w.client.Call(ctx, t, req, resp)
		var e *ipc.Error
		if err == nil || errors.As(err, &e) || ctx.Err() != nil {
			return err
		}
		w.client.Close()
		w.client = nil
		if attempt == 1 {
			return fmt.Errorf("%w: %v", ErrWalletUnavailable, err)
		}
	}
	return nil
}

// Close closes the connection.
func (w *WalletConn) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.client != nil {
		w.client.Close()
		w.client = nil
	}
}

// orphan is a transaction the wallet signed whose draft the server lost in a
// restart (section 9.5): the server follows it on the chain until it is
// confirmed or expired, as it follows the drafts it sent.
type orphan struct {
	wallet  model.WalletID
	ttl     uint64
	expired bool // the server stopped waiting for it
}

// walletState is what the server keeps of the wallet process: its wallets,
// with the policy they last reported, and the transactions it signed before
// the server's last start.
type walletState struct {
	mu      sync.Mutex
	wallets []Wallet // in the wallet process's order
	synced  bool     // the pending transactions were read
	orphans map[[32]byte]orphan
}

// remote returns the wallets of the wallet process the server knows.
func (s *Server) remote() []Wallet {
	s.ws.mu.Lock()
	defer s.ws.mu.Unlock()
	return slices.Clone(s.ws.wallets)
}

// refresh asks the wallet process for its wallets (decision 94) and for the
// policy of those the server does not know yet.
func (s *Server) refresh(ctx context.Context) error {
	if s.d.Wallet == nil {
		return nil
	}
	var list ipc.WalletList
	if err := s.d.Wallet.Call(ctx, ipc.MsgListWallets, &ipc.Empty{}, &list); err != nil {
		return err
	}
	known := map[model.WalletID]Wallet{}
	for _, w := range s.remote() {
		known[w.ID] = w
	}
	var out []Wallet
	for _, iw := range list.Wallets {
		id := model.WalletID(iw.ID)
		if _, ok := s.wallets[id]; ok || model.Network(iw.Network) != s.d.Network {
			s.d.Logger.Warn("wallet process: a wallet the server cannot take", "wallet", iw.ID)
			continue
		}
		w, ok := known[id]
		if !ok {
			var err error
			if w, err = s.fetch(ctx, iw); err != nil {
				return err
			}
		}
		w.Policy.Frozen = iw.Frozen
		out = append(out, w)
	}
	s.ws.mu.Lock()
	s.ws.wallets = out
	s.ws.mu.Unlock()
	return nil
}

// fetch builds a wallet of the wallet process from its data and its policy.
func (s *Server) fetch(ctx context.Context, iw ipc.Wallet) (Wallet, error) {
	addr, err := chain.AddressFromBytes(iw.Address)
	if err != nil {
		return Wallet{}, err
	}
	w := Wallet{Wallet: iw.Model()}
	w.Address = addr
	ps, err := s.status(ctx, w.ID)
	if err != nil {
		return Wallet{}, err
	}
	w.Mode, w.Policy = model.Mode(ps.Mode), ps.Policy.Model()
	return w, nil
}

// status asks the wallet process for a wallet's policy and spending, and
// keeps the policy.
func (s *Server) status(ctx context.Context, id model.WalletID) (*ipc.PolicyStatus, error) {
	var ps ipc.PolicyStatus
	if err := s.d.Wallet.Call(ctx, ipc.MsgGetPolicyStatus, &ipc.GetPolicyStatus{WalletID: string(id)}, &ps); err != nil {
		return nil, err
	}
	s.ws.mu.Lock()
	for i := range s.ws.wallets {
		if s.ws.wallets[i].ID == id {
			s.ws.wallets[i].Mode, s.ws.wallets[i].Policy = model.Mode(ps.Mode), ps.Policy.Model()
		}
	}
	s.ws.mu.Unlock()
	return &ps, nil
}

// usage is what a policy status says a wallet has spent, for the verdict of
// a draft. The wallet decides with its own record when asked to sign.
func usage(ps *ipc.PolicyStatus) policy.Usage {
	u := policy.Usage{Hour: policy.Window{Lovelace: ps.SpentHour}, Day: policy.Window{Lovelace: ps.SpentDay}}
	if b := ps.Policy.Limits.Budget; ps.BudgetRemaining <= b {
		u.BudgetSpent = b - ps.BudgetRemaining
	}
	if ps.Session != nil {
		u.Session = &policy.Session{Remaining: ps.Session.Remaining}
	}
	return u
}

// Sync reads, once, the transactions the wallet process signed and that may
// still reach the chain: the server lost their drafts if it restarted, and
// follows them (section 9.5). It is tried again until the wallet answers.
func (s *Server) Sync(ctx context.Context) {
	if s.d.Wallet == nil {
		return
	}
	s.ws.mu.Lock()
	synced := s.ws.synced
	s.ws.mu.Unlock()
	if synced {
		return
	}
	if err := s.refresh(ctx); err != nil {
		s.d.Logger.Warn("wallet process", "err", err)
		return
	}
	orphans := map[[32]byte]orphan{}
	for _, w := range s.remote() {
		ps, err := s.status(ctx, w.ID)
		if err != nil {
			s.d.Logger.Warn("wallet process", "err", err)
			return
		}
		for _, p := range ps.Pending {
			orphans[[32]byte(p.TxID)] = orphan{wallet: w.ID, ttl: p.TTL}
		}
	}
	ids := make([]string, 0, len(orphans))
	for id := range orphans {
		ids = append(ids, hex.EncodeToString(id[:]))
	}
	slices.Sort(ids)
	s.ws.mu.Lock()
	s.ws.orphans, s.ws.synced = orphans, true
	s.ws.mu.Unlock()
	s.note(ctx, "wallet_sync", map[string]any{"wallets": len(s.remote()), "pending": ids})
}

// FollowOrphans asks the chain about the transactions of Sync, with the
// rules of the drafts the server sent: one deep enough is dropped, and one
// still missing grace after its TTL is expired (decision 78). Each outcome
// is noted in the audit log.
func (s *Server) FollowOrphans(ctx context.Context, depth uint32, grace time.Duration) {
	s.ws.mu.Lock()
	var ids [][32]byte
	for id, o := range s.ws.orphans {
		if !o.expired {
			ids = append(ids, id)
		}
	}
	s.ws.mu.Unlock()
	if len(ids) == 0 {
		return
	}
	confirmations, err := s.d.Source.Confirmations(ctx, ids)
	if err != nil {
		return
	}
	clock := chain.Clock(s.d.Network)
	for _, id := range ids {
		s.ws.mu.Lock()
		o := s.ws.orphans[id]
		var outcome string
		switch {
		case confirmations[id] >= uint64(depth):
			outcome = "confirmed"
			delete(s.ws.orphans, id)
		case confirmations[id] == 0 && s.d.Now().After(clock.Time(o.ttl).Add(grace)):
			outcome = "expired"
			o.expired = true
			s.ws.orphans[id] = o
		}
		s.ws.mu.Unlock()
		if outcome != "" {
			s.note(ctx, "pending_"+outcome, map[string]any{"wallet_id": string(o.wallet), "tx_id": hex.EncodeToString(id[:])})
		}
	}
}

// orphanOf returns a transaction of Sync, if the server still follows it.
func (s *Server) orphanOf(id [32]byte) (orphan, bool) {
	s.ws.mu.Lock()
	defer s.ws.mu.Unlock()
	o, ok := s.ws.orphans[id]
	return o, ok
}

// authorizeWithWallet is authorize_draft in modes B and C: the wallet process
// signs, asks the person, or refuses (section 9.1). A signature is checked
// against the draft and sent at once.
func (s *Server) authorizeWithWallet(ctx context.Context, id model.DraftID) (draftView, error) {
	d, err := s.d.Drafts.BeginAuthorize(id)
	if err != nil {
		return draftView{}, err
	}
	switch d.State {
	case drafts.StateAuthorizing:
	case drafts.StateSigned:
		return s.send(ctx, d) // signed, but the send was lost
	default:
		return s.view(d, false)
	}
	req, err := signRequest(d)
	if err != nil {
		return draftView{}, err
	}
	var res ipc.SignDraftResult
	if err := s.d.Wallet.Call(ctx, ipc.MsgSignDraft, req, &res); err != nil {
		// The draft stays authorizing: authorize_draft asks again.
		return draftView{}, err
	}
	switch res.Status {
	case ipc.Signed:
		return s.signAndSend(ctx, d.ID, res.Witnesses)
	case ipc.PendingApproval:
		if d, err = s.d.Drafts.AwaitApproval(d.ID, res.ApprovalID); err != nil {
			return draftView{}, err
		}
		return s.view(d, false)
	}
	e := rejectionError(res.Rejection)
	if _, err := s.d.Drafts.Reject(d.ID, e.Message); err != nil {
		return draftView{}, err
	}
	return draftView{}, e
}

// signRequest is the SignDraft of a draft, with the outputs its inputs
// spend, which the wallet only shows (section 5.3).
func signRequest(d drafts.Draft) (*ipc.SignDraft, error) {
	spent, err := d.Tx.Spent()
	if err != nil {
		return nil, err
	}
	req := &ipc.SignDraft{WalletID: string(d.Wallet), DraftID: string(d.ID), Body: d.Tx.Body, AuxData: d.Tx.AuxData,
		Inputs: make([]ipc.ResolvedInput, len(spent))}
	for i, sp := range spent {
		req.Inputs[i] = ipc.ResolvedInput{TxID: sp.In.TxID[:], Index: uint64(sp.In.Index), Output: sp.Output}
	}
	return req, nil
}

// signAndSend attaches the wallet's witnesses to the draft, which checks
// them with every phase-1 rule, and sends the transaction.
func (s *Server) signAndSend(ctx context.Context, id model.DraftID, ws []ipc.Witness) (draftView, error) {
	set, err := encodeWitnesses(ws)
	if err != nil {
		return draftView{}, err
	}
	d, err := s.d.Drafts.Sign(id, set)
	if err != nil {
		return draftView{}, err
	}
	if d.State != drafts.StateSigned {
		return s.view(d, false)
	}
	return s.send(ctx, d)
}

// encodeWitnesses encodes key witnesses as the witness set of a transaction,
// {0: 258([[vkey, signature], ...])}, the form the fee was computed for.
func encodeWitnesses(ws []ipc.Witness) ([]byte, error) {
	items := make([]any, len(ws))
	for i, w := range ws {
		items[i] = []any{w.VKey, w.Signature}
	}
	return witnessCodec.Marshal(map[uint64]any{0: cborx.Tag{Number: 258, Content: items}})
}

var witnessCodec = func() *cborx.Codec {
	c, err := cborx.New(cborx.Limits{MaxDepth: 8, MaxArrayElements: 64, MaxMapPairs: 16, AllowTags: true})
	if err != nil {
		panic(err) // constant limits
	}
	return c
}()

// FollowApprovals asks the wallet process about the drafts that wait for the
// person, and sends those the person approved.
func (s *Server) FollowApprovals(ctx context.Context) {
	for _, d := range s.d.Drafts.List("", drafts.StatePendingApproval) {
		if d.ApprovalID == "" {
			continue // mode A: the signer brings the signature
		}
		var st ipc.ApprovalStatus
		if err := s.d.Wallet.Call(ctx, ipc.MsgGetApprovalStatus, &ipc.GetApprovalStatus{ApprovalID: d.ApprovalID}, &st); err != nil {
			s.d.Logger.Warn("approval status", "draft", d.ID, "err", err)
			continue
		}
		var err error
		switch st.Status {
		case ipc.ApprovalApproved:
			_, err = s.signAndSend(ctx, d.ID, st.Witnesses)
		case ipc.ApprovalRejected:
			_, err = s.d.Drafts.Reject(d.ID, "the person rejected it")
		case ipc.ApprovalExpired:
			_, err = s.d.Drafts.Expire(d.ID)
		default:
			continue
		}
		if err != nil {
			s.d.Logger.Warn("approval", "draft", d.ID, "err", err)
		}
		s.note(ctx, "approval_"+st.Status, map[string]any{"draft_id": string(d.ID), "approval_id": d.ApprovalID})
	}
}

// newIdempotencyKey gives a CreateWallet without the agent's key one of the
// server's, so that sending it again after a lost connection cannot create a
// second wallet.
func newIdempotencyKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "server-" + hex.EncodeToString(b)
}
