// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package ledger is the wallet's spending record (sections 3.9, 7.3, 8.5 and
// 9.1 of the specification): an append-only, hash-chained log of what each
// signature spends. It is the authority of the budget. A spend reaches the
// disk before its signature leaves the wallet, and from the record the wallet
// derives what policy compares a transaction with: the rolling windows, the
// budget spent and the destinations it already knows.
//
// The record has the format of the audit log, with kind "ledger". On opening,
// every entry is replayed and checked against the ones before it; a record
// whose entries contradict each other is not reliable, and the wallet must not
// start on it.
package ledger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/policy"
)

// Kind is the kind of the log.
const Kind = "ledger"

// Entry types of section 7.3 that the MVP writes. Deposits arrive in phase 2
// and committed value in phase 3. An entry whose TTL has passed is
// expired_unconfirmed: a state derived from the wallet's clock, not an entry
// (decision 107).
const (
	TypeReserved = "reserved"
	TypeSigned   = "signed"
	TypeReleased = "released"
)

var (
	// ErrCorrupt reports a record whose entries contradict each other.
	ErrCorrupt = errors.New("ledger: inconsistent record")
	// ErrConflict reports a transaction reserved already by another wallet.
	ErrConflict = errors.New("ledger: transaction reserved by another wallet")
	// ErrUnknown reports a transaction the wallet never reserved.
	ErrUnknown = errors.New("ledger: no such reservation")
	// ErrNotExpired reports a release of a transaction whose TTL has not
	// passed by the wallet's clock: it may still enter the chain.
	ErrNotExpired = errors.New("ledger: the transaction may still enter the chain")
	// ErrReleased reports a transaction released already.
	ErrReleased = errors.New("ledger: released already")
	// ErrSigned reports a second, different signature of a transaction.
	// Ed25519 is deterministic: it means a bug, never a retry.
	ErrSigned = errors.New("ledger: signed already with another signature")
)

// maxRelease is the most transactions one release names: the arrays of a
// record hold at most 4096 elements.
const maxRelease = 4096

// SignatureSize is the size of an Ed25519 signature.
const SignatureSize = 64

// The bodies of the entries. Every one names its wallet and its transaction,
// whose id is the hash of its body.
type (
	reservation struct {
		WalletID     string                                           `cbor:"wallet_id"`
		TxID         []byte                                           `cbor:"tx_id"`
		Lovelace     uint64                                           `cbor:"lovelace"`
		Assets       map[cborx.ByteString]map[cborx.ByteString]uint64 `cbor:"assets,omitempty"`
		Fee          uint64                                           `cbor:"fee"`
		TTL          uint64                                           `cbor:"ttl"`
		Destinations [][]byte                                         `cbor:"destinations,omitempty"`
	}
	signature struct {
		WalletID  string `cbor:"wallet_id"`
		TxID      []byte `cbor:"tx_id"`
		Signature []byte `cbor:"signature"`
	}
	release struct {
		WalletID string   `cbor:"wallet_id"`
		TxIDs    [][]byte `cbor:"tx_ids"`
		Lovelace uint64   `cbor:"lovelace"`
	}
)

// Record is a reservation as the record holds it.
type Record struct {
	Seq      uint64    // of the reserved entry
	Time     time.Time // when the spend was reserved, by the wallet's clock
	WalletID model.WalletID
	TxID     [32]byte
	Lovelace uint64
	Assets   map[model.AssetID]uint64
	Fee      uint64
	TTL      uint64 // slot
	// Destinations are the addresses of the outputs that are not own.
	Destinations [][]byte
	// Signature is nil until the signature is written.
	Signature []byte
	Released  bool
}

// state is what the entries say, rebuilt on opening.
type state struct {
	seq     uint64
	records map[[32]byte]*Record
	wallets map[model.WalletID]*wallet
}

// wallet holds the reservations of one wallet, in record order, and the time
// each destination first appeared.
type wallet struct {
	records   []*Record
	firstSeen map[string]time.Time
}

func newState() *state {
	return &state{records: map[[32]byte]*Record{}, wallets: map[model.WalletID]*wallet{}}
}

func (s *state) wallet(id model.WalletID) *wallet {
	w := s.wallets[id]
	if w == nil {
		w = &wallet{firstSeen: map[string]time.Time{}}
		s.wallets[id] = w
	}
	return w
}

// Ledger is an open spending record. It is safe for concurrent use.
type Ledger struct {
	mu    sync.Mutex
	log   *audit.Log
	codec *cborx.Codec
	st    *state
}

func newCodec() *cborx.Codec {
	c, err := cborx.New(cborx.RecordLimits())
	if err != nil {
		panic(err) // constant limits
	}
	return c
}

// Open opens the record at path, creating it if it does not exist, and
// replays it. now is the wallet's clock, which stamps every entry. An
// incomplete last entry is cut off and reported in the recovery, for the
// audit log (section 7.3).
func Open(ctx context.Context, path string, now func() time.Time) (*Ledger, audit.Recovery, error) {
	log, entries, rec, err := audit.OpenEntries(ctx, path, audit.Options{Kind: Kind, Now: now})
	if err != nil {
		return nil, audit.Recovery{}, err
	}
	c := newCodec()
	st := newState()
	for _, e := range entries[1:] { // the first one is the header
		if err := st.apply(c, e); err != nil {
			log.Close()
			return nil, audit.Recovery{}, err
		}
	}
	if n := len(entries); n > 0 {
		st.seq = entries[n-1].Seq
	}
	return &Ledger{log: log, codec: c, st: st}, rec, nil
}

// Close closes the record.
func (l *Ledger) Close() error { return l.log.Close() }

// Seq returns the number of the last entry. A budget counts the spend of the
// entries after the one that was last when the person set it (section 8.5).
func (l *Ledger) Seq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.st.seq
}

// Lookup returns the reservation of a transaction, to answer a repeated
// SignDraft without counting it twice (section 9.4, M-13).
func (l *Ledger) Lookup(txID [32]byte) (Record, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.st.records[txID]
	if !ok {
		return Record{}, false
	}
	return *r, true
}

// Reserve writes the spend of a transaction before it is signed (section
// 9.1, step 5). Reserving again a transaction of the same wallet writes
// nothing and returns the reservation there is.
func (l *Ledger) Reserve(ctx context.Context, w model.WalletID, txID [32]byte, s policy.Spend, fee, ttl uint64) (Record, error) {
	if err := w.Validate(); err != nil {
		return Record{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if r, ok := l.st.records[txID]; ok {
		if r.WalletID != w {
			return Record{}, ErrConflict
		}
		return *r, nil
	}
	// Everything is checked before writing: an entry on disk must never
	// contradict the state.
	body := reservation{WalletID: string(w), TxID: txID[:], Lovelace: s.Lovelace, Fee: fee, TTL: ttl}
	for a, q := range s.Assets {
		if q == 0 {
			continue
		}
		if len(a.Name) > model.MaxAssetNameSize {
			return Record{}, model.ErrInvalidAsset
		}
		if body.Assets == nil {
			body.Assets = map[cborx.ByteString]map[cborx.ByteString]uint64{}
		}
		p := cborx.ByteString(a.Policy[:])
		if body.Assets[p] == nil {
			body.Assets[p] = map[cborx.ByteString]uint64{}
		}
		body.Assets[p][cborx.ByteString(a.Name)] = q
	}
	for _, d := range s.Destinations {
		if len(d.Raw) == 0 {
			return Record{}, errors.New("ledger: a destination without an address")
		}
		body.Destinations = append(body.Destinations, d.Raw)
	}
	if err := l.append(ctx, TypeReserved, body); err != nil {
		return Record{}, err
	}
	return *l.st.records[txID], nil
}

// Sign writes the signature of a reserved transaction (section 9.1, step 7).
// Writing the same signature again does nothing.
func (l *Ledger) Sign(ctx context.Context, txID [32]byte, sig []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.st.records[txID]
	switch {
	case !ok:
		return ErrUnknown
	case len(sig) != SignatureSize:
		return fmt.Errorf("ledger: a signature of %d bytes", len(sig))
	case r.Signature != nil && bytes.Equal(r.Signature, sig):
		return nil
	case r.Signature != nil:
		return ErrSigned
	}
	return l.append(ctx, TypeSigned, signature{WalletID: string(r.WalletID), TxID: txID[:], Signature: sig})
}

// Release frees the spend of transactions whose TTL has passed by the
// wallet's clock, at the person's request (section 9.2). It returns the
// lovelace released.
func (l *Ledger) Release(ctx context.Context, w model.WalletID, txIDs [][32]byte, slot uint64) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(txIDs) > maxRelease {
		return 0, fmt.Errorf("ledger: release at most %d transactions at once", maxRelease)
	}
	body := release{WalletID: string(w)}
	for i, id := range txIDs {
		r, ok := l.st.records[id]
		switch {
		case !ok || r.WalletID != w:
			return 0, fmt.Errorf("%w: %x", ErrUnknown, id)
		case r.Released || slices.Contains(txIDs[:i], id):
			return 0, fmt.Errorf("%w: %x", ErrReleased, id)
		case r.TTL > slot:
			return 0, fmt.Errorf("%w: %x is valid until slot %d", ErrNotExpired, id, r.TTL)
		}
		var err error
		if body.Lovelace, err = model.Add(body.Lovelace, r.Lovelace); err != nil {
			return 0, err
		}
		body.TxIDs = append(body.TxIDs, id[:])
	}
	if len(body.TxIDs) == 0 {
		return 0, fmt.Errorf("%w: nothing to release", ErrUnknown)
	}
	if err := l.append(ctx, TypeReleased, body); err != nil {
		return 0, err
	}
	return body.Lovelace, nil
}

// append writes an entry and then applies it to the state, so the state never
// holds what is not on disk.
func (l *Ledger) append(ctx context.Context, typ string, body any) error {
	e, err := l.log.Append(ctx, typ, body)
	if err != nil {
		return err
	}
	if err := l.st.apply(l.codec, e); err != nil {
		// What was written contradicts the state: no further write is safe.
		l.log.Close()
		return err
	}
	l.st.seq = e.Seq
	return nil
}

// Pending returns the reservations of a wallet whose TTL has passed by the
// wallet's clock and that the person has not released: the
// expired_unconfirmed entries of section 9.2, which still count.
func (l *Ledger) Pending(w model.WalletID, slot uint64) []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Record
	if wl := l.st.wallets[w]; wl != nil {
		for _, r := range wl.records {
			if !r.Released && r.TTL <= slot {
				out = append(out, *r)
			}
		}
	}
	return out
}

// Usage returns what policy compares a transaction of a wallet with at time
// now (section 8.5): the spend of the last hour and the last day, the spend
// of the budget since entry since, and the destinations the wallet knows. A
// released reservation no longer counts as spend; its destinations stay
// known. The session is the caller's.
func (l *Ledger) Usage(w model.WalletID, now time.Time, since uint64) policy.Usage {
	l.mu.Lock()
	defer l.mu.Unlock()
	var u policy.Usage
	wl := l.st.wallets[w]
	if wl == nil {
		return u
	}
	hour, day := now.Add(-time.Hour), now.Add(-24*time.Hour)
	for _, r := range wl.records {
		if r.Released {
			continue
		}
		if r.Time.After(day) {
			add(&u.Day, r.Lovelace)
		}
		if r.Time.After(hour) {
			add(&u.Hour, r.Lovelace)
		}
		if r.Seq > since {
			u.BudgetSpent = saturate(u.BudgetSpent, r.Lovelace)
		}
	}
	known := make(map[string]bool, len(wl.firstSeen))
	for d, t := range wl.firstSeen {
		known[d] = true
		if t.After(day) {
			u.Day.NewDestinations++
		}
		if t.After(hour) {
			u.Hour.NewDestinations++
		}
	}
	u.Known = func(a model.Address) bool { return known[string(a.Raw)] }
	return u
}

func add(w *policy.Window, lovelace uint64) {
	w.Lovelace = saturate(w.Lovelace, lovelace)
	w.Transactions++
}

// saturate adds without wrapping: a sum beyond uint64 exceeds every limit.
func saturate(a, b uint64) uint64 {
	if s, err := model.Add(a, b); err == nil {
		return s
	}
	return ^uint64(0)
}

// apply replays one entry, checking it against the ones before.
func (s *state) apply(c *cborx.Codec, e audit.Entry) error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: entry %d: %s", ErrCorrupt, e.Seq, fmt.Sprintf(format, args...))
	}
	switch e.Type {
	case TypeReserved:
		var b reservation
		if err := c.Unmarshal(e.Body, &b); err != nil {
			return bad("%v", err)
		}
		w := model.WalletID(b.WalletID)
		if w.Validate() != nil || len(b.TxID) != 32 {
			return bad("malformed reservation")
		}
		id := [32]byte(b.TxID)
		if _, dup := s.records[id]; dup {
			return bad("transaction %x reserved twice", id)
		}
		r := &Record{Seq: e.Seq, Time: time.Unix(e.Time, 0), WalletID: w, TxID: id,
			Lovelace: b.Lovelace, Fee: b.Fee, TTL: b.TTL, Destinations: b.Destinations}
		for p, names := range b.Assets {
			for n, q := range names {
				a, err := model.NewAssetID([]byte(p), []byte(n))
				if err != nil || q == 0 {
					return bad("malformed asset")
				}
				if r.Assets == nil {
					r.Assets = map[model.AssetID]uint64{}
				}
				r.Assets[a] = q
			}
		}
		wl := s.wallet(w)
		for _, d := range b.Destinations {
			if len(d) == 0 {
				return bad("empty destination")
			}
			if _, seen := wl.firstSeen[string(d)]; !seen {
				wl.firstSeen[string(d)] = r.Time
			}
		}
		s.records[id] = r
		wl.records = append(wl.records, r)
	case TypeSigned:
		var b signature
		if err := c.Unmarshal(e.Body, &b); err != nil {
			return bad("%v", err)
		}
		if len(b.TxID) != 32 || len(b.Signature) != SignatureSize {
			return bad("malformed signature")
		}
		r, ok := s.records[[32]byte(b.TxID)]
		switch {
		case !ok || string(r.WalletID) != b.WalletID:
			return bad("signature of a transaction never reserved")
		case r.Signature != nil:
			return bad("transaction %x signed twice", r.TxID)
		}
		r.Signature = b.Signature
	case TypeReleased:
		var b release
		if err := c.Unmarshal(e.Body, &b); err != nil {
			return bad("%v", err)
		}
		if len(b.TxIDs) == 0 {
			return bad("empty release")
		}
		var sum uint64
		released := make([]*Record, 0, len(b.TxIDs))
		for _, id := range b.TxIDs {
			if len(id) != 32 {
				return bad("malformed release")
			}
			r, ok := s.records[[32]byte(id)]
			switch {
			case !ok || string(r.WalletID) != b.WalletID:
				return bad("release of a transaction never reserved")
			case r.Released || slices.Contains(released, r):
				return bad("transaction %x released twice", r.TxID)
			}
			sum = saturate(sum, r.Lovelace)
			released = append(released, r)
		}
		if sum != b.Lovelace {
			return bad("the release sums %d, not %d", sum, b.Lovelace)
		}
		for _, r := range released {
			r.Released = true
		}
	default:
		return bad("unknown type %q", e.Type)
	}
	return nil
}
