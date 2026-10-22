// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ledger

import (
	"bytes"
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/policy"
)

var ctx = context.Background()

// clock is the wallet's clock, under the test's control.
type clock struct{ t time.Time }

func newClock() *clock                   { return &clock{t: time.Unix(1_800_000_000, 0)} }
func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

// slot is the slot of the clock; the tests need only its order.
func (c *clock) slot() uint64 { return uint64(c.t.Unix()) }

func open(t testing.TB, path string, c *clock) *Ledger {
	t.Helper()
	l, _, err := Open(ctx, path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func newLedger(t testing.TB) (*Ledger, *clock, string) {
	t.Helper()
	c := newClock()
	path := filepath.Join(t.TempDir(), "ledger.log")
	return open(t, path, c), c, path
}

func walletID(t testing.TB) model.WalletID {
	t.Helper()
	id, err := model.NewWalletID(nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func addr(b byte) model.Address {
	return model.Address{Raw: []byte{0x60, b}, Type: 6}
}

func tx(b byte) [32]byte { return [32]byte{b} }

func sig(b byte) []byte { return bytes.Repeat([]byte{b}, SignatureSize) }

func spend(lovelace uint64, to ...model.Address) policy.Spend {
	return policy.Spend{Lovelace: lovelace, Destinations: to}
}

func TestReserveSignAndReplay(t *testing.T) {
	l, c, path := newLedger(t)
	w := walletID(t)
	tok, _ := model.NewAssetID(bytes.Repeat([]byte{0xa1}, 28), []byte("MC"))
	s := spend(5_200_000, addr(1), addr(2))
	s.Assets = map[model.AssetID]uint64{tok: 7}
	r, err := l.Reserve(ctx, w, tx(1), s, 200_000, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if r.Seq != 2 || r.Lovelace != 5_200_000 || r.Fee != 200_000 || r.TTL != 5000 || r.Signature != nil || !r.Time.Equal(c.now()) {
		t.Errorf("reservation %+v", r)
	}
	if err := l.Sign(ctx, tx(1), sig(9)); err != nil {
		t.Fatal(err)
	}
	if l.Seq() != 3 {
		t.Errorf("seq %d", l.Seq())
	}
	l.Close()

	// The record rebuilds the same state.
	again := open(t, path, c)
	got, ok := again.Lookup(tx(1))
	want := Record{Seq: 2, Time: c.now(), WalletID: w, TxID: tx(1), Lovelace: 5_200_000, Assets: s.Assets,
		Fee: 200_000, TTL: 5000, Destinations: [][]byte{addr(1).Raw, addr(2).Raw}, Signature: sig(9)}
	if !ok || !equal(got, want) {
		t.Errorf("after reopening\n%+v\nwant\n%+v", got, want)
	}
	if again.Seq() != 3 {
		t.Errorf("seq %d after reopening", again.Seq())
	}
}

func equal(a, b Record) bool {
	if a.Seq != b.Seq || !a.Time.Equal(b.Time) || a.WalletID != b.WalletID || a.TxID != b.TxID ||
		a.Lovelace != b.Lovelace || a.Fee != b.Fee || a.TTL != b.TTL || a.Released != b.Released ||
		!bytes.Equal(a.Signature, b.Signature) || len(a.Assets) != len(b.Assets) || len(a.Destinations) != len(b.Destinations) {
		return false
	}
	for k, v := range a.Assets {
		if b.Assets[k] != v {
			return false
		}
	}
	for i := range a.Destinations {
		if !bytes.Equal(a.Destinations[i], b.Destinations[i]) {
			return false
		}
	}
	return true
}

// TestRepeatedRequest_M13: the same body twice is one reservation and one
// spend, and the same signature twice is one entry.
func TestRepeatedRequest_M13(t *testing.T) {
	l, c, _ := newLedger(t)
	w := walletID(t)
	l.Reserve(ctx, w, tx(1), spend(5_000_000, addr(1)), 1, 100)
	seq := l.Seq()
	if r, err := l.Reserve(ctx, w, tx(1), spend(9_000_000, addr(2)), 1, 100); err != nil || r.Lovelace != 5_000_000 || l.Seq() != seq {
		t.Fatalf("second reservation: %+v, %v, seq %d", r, err, l.Seq())
	}
	l.Sign(ctx, tx(1), sig(1))
	seq = l.Seq()
	if err := l.Sign(ctx, tx(1), sig(1)); err != nil || l.Seq() != seq {
		t.Fatalf("second signature: %v, seq %d", err, l.Seq())
	}
	if err := l.Sign(ctx, tx(1), sig(2)); !errors.Is(err, ErrSigned) || l.Seq() != seq {
		t.Fatalf("another signature: %v", err)
	}
	if u := l.Usage(w, c.now(), 0); u.Hour.Lovelace != 5_000_000 || u.Hour.Transactions != 1 || u.BudgetSpent != 5_000_000 {
		t.Errorf("usage %+v", u)
	}
	if _, err := l.Reserve(ctx, walletID(t), tx(1), spend(1), 1, 100); !errors.Is(err, ErrConflict) {
		t.Errorf("another wallet: %v", err)
	}
}

func TestInvalidWrites(t *testing.T) {
	l, _, _ := newLedger(t)
	w := walletID(t)
	seq := l.Seq()
	if _, err := l.Reserve(ctx, "w_x", tx(1), spend(1), 1, 1); err == nil {
		t.Error("an invalid wallet id was accepted")
	}
	if _, err := l.Reserve(ctx, w, tx(1), spend(1, model.Address{}), 1, 1); err == nil {
		t.Error("a destination without address was accepted")
	}
	long := model.AssetID{Name: string(make([]byte, 33))}
	if _, err := l.Reserve(ctx, w, tx(1), policy.Spend{Assets: map[model.AssetID]uint64{long: 1}}, 1, 1); err == nil {
		t.Error("an asset name of 33 bytes was accepted")
	}
	if err := l.Sign(ctx, tx(1), sig(1)); !errors.Is(err, ErrUnknown) {
		t.Errorf("signing what was never reserved: %v", err)
	}
	l.Reserve(ctx, w, tx(1), spend(1), 1, 1)
	if err := l.Sign(ctx, tx(1), sig(1)[:63]); err == nil {
		t.Error("a short signature was accepted")
	}
	if l.Seq() != seq+1 {
		t.Errorf("rejected writes reached the record: seq %d", l.Seq())
	}
}

func TestWindows(t *testing.T) {
	l, c, _ := newLedger(t)
	w, other := walletID(t), walletID(t)
	start := c.now()
	l.Reserve(ctx, w, tx(1), spend(1_000_000, addr(1)), 1, 1)
	c.advance(30 * time.Minute)
	l.Reserve(ctx, w, tx(2), spend(2_000_000, addr(2), addr(1)), 1, 1)
	l.Reserve(ctx, other, tx(3), spend(4_000_000, addr(3)), 1, 1)
	c.advance(31 * time.Minute) // the first is now older than an hour

	u := l.Usage(w, c.now(), 0)
	if u.Hour != (policy.Window{Lovelace: 2_000_000, Transactions: 1, NewDestinations: 1}) {
		t.Errorf("hour %+v", u.Hour)
	}
	if u.Day != (policy.Window{Lovelace: 3_000_000, Transactions: 2, NewDestinations: 2}) {
		t.Errorf("day %+v", u.Day)
	}
	if !u.Known(addr(1)) || !u.Known(addr(2)) || u.Known(addr(3)) {
		t.Error("known destinations: addr(3) belongs to another wallet")
	}
	// The windows roll: a day after the first, only the second counts.
	if u := l.Usage(w, start.Add(24*time.Hour), 0); u.Day.Lovelace != 2_000_000 || u.Day.NewDestinations != 1 {
		t.Errorf("a day later: %+v", u.Day)
	}
	// A clock that went back still counts what it wrote.
	if u := l.Usage(w, start.Add(-time.Hour), 0); u.Day.Lovelace != 3_000_000 {
		t.Errorf("clock back: %+v", u.Day)
	}
	// A wallet without entries uses nothing and knows nobody.
	if u := l.Usage(walletID(t), c.now(), 0); u.Day != (policy.Window{}) || u.Known != nil {
		t.Errorf("empty wallet: %+v", u)
	}
}

// TestSumsSaturate: a sum beyond uint64 stays at the maximum, which exceeds
// every limit, instead of wrapping to a small number.
func TestSumsSaturate(t *testing.T) {
	l, c, _ := newLedger(t)
	w := walletID(t)
	l.Reserve(ctx, w, tx(1), spend(math.MaxUint64-5), 1, 100)
	l.Reserve(ctx, w, tx(2), spend(10), 1, 100)
	u := l.Usage(w, c.now(), 0)
	if u.Hour.Lovelace != math.MaxUint64 || u.Day.Lovelace != math.MaxUint64 || u.BudgetSpent != math.MaxUint64 {
		t.Errorf("usage %+v", u)
	}
}

// TestBudgetSince: the budget counts from the entry that was last when the
// person set it (section 8.5), and a release gives back its spend.
func TestBudgetSince(t *testing.T) {
	l, c, _ := newLedger(t)
	w := walletID(t)
	l.Reserve(ctx, w, tx(1), spend(10), 1, 100)
	since := l.Seq()
	l.Reserve(ctx, w, tx(2), spend(20), 1, 100)
	l.Reserve(ctx, w, tx(3), spend(40), 1, 200)
	if u := l.Usage(w, c.now(), since); u.BudgetSpent != 60 || u.Day.Lovelace != 70 {
		t.Errorf("usage %+v", u)
	}
	if n, err := l.Release(ctx, w, [][32]byte{tx(2)}, 100); err != nil || n != 20 {
		t.Fatalf("release: %d, %v", n, err)
	}
	if u := l.Usage(w, c.now(), since); u.BudgetSpent != 40 || u.Day.Lovelace != 50 || u.Day.Transactions != 2 {
		t.Errorf("after the release: %+v", u)
	}
}

// TestRelease follows section 9.2: only the person releases, and only what
// has expired by the wallet's clock.
func TestRelease(t *testing.T) {
	l, _, path := newLedger(t)
	w, other := walletID(t), walletID(t)
	l.Reserve(ctx, w, tx(1), spend(10), 1, 100)
	l.Sign(ctx, tx(1), sig(1))
	l.Reserve(ctx, w, tx(2), spend(20), 1, 100) // a crash before signing
	l.Reserve(ctx, w, tx(3), spend(40), 1, 300)
	l.Reserve(ctx, other, tx(4), spend(80), 1, 100)

	if p := l.Pending(w, 99); len(p) != 0 {
		t.Errorf("pending before the TTL: %d", len(p))
	}
	p := l.Pending(w, 100)
	if len(p) != 2 || p[0].TxID != tx(1) || p[1].TxID != tx(2) {
		t.Fatalf("pending %+v", p)
	}
	seq := l.Seq()
	for name, c := range map[string]struct {
		ids  [][32]byte
		want error
	}{
		"not expired":          {[][32]byte{tx(1), tx(3)}, ErrNotExpired},
		"another wallet's":     {[][32]byte{tx(4)}, ErrUnknown},
		"never reserved":       {[][32]byte{tx(9)}, ErrUnknown},
		"twice in one release": {[][32]byte{tx(1), tx(1)}, ErrReleased},
		"nothing":              {nil, ErrUnknown},
	} {
		if _, err := l.Release(ctx, w, c.ids, 100); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if l.Seq() != seq {
		t.Fatal("a refused release reached the record")
	}
	if n, err := l.Release(ctx, w, [][32]byte{tx(1), tx(2)}, 100); err != nil || n != 30 {
		t.Fatalf("release: %d, %v", n, err)
	}
	if _, err := l.Release(ctx, w, [][32]byte{tx(1)}, 100); !errors.Is(err, ErrReleased) {
		t.Errorf("again: %v", err)
	}
	if p := l.Pending(w, 1000); len(p) != 1 || p[0].TxID != tx(3) {
		t.Errorf("pending after the release: %+v", p)
	}
	l.Close()
	again := open(t, path, newClock())
	if r, _ := again.Lookup(tx(2)); !r.Released {
		t.Error("the release did not survive reopening")
	}
}

// TestCrashBeforeSigning follows the table of section 9.1: a reservation
// without a signature counts, and a repeated request completes it.
func TestCrashBeforeSigning(t *testing.T) {
	l, c, path := newLedger(t)
	w := walletID(t)
	l.Reserve(ctx, w, tx(1), spend(10, addr(1)), 1, 100)
	l.Close()

	again := open(t, path, c)
	r, ok := again.Lookup(tx(1))
	if !ok || r.Signature != nil {
		t.Fatalf("lookup: %+v, %v", r, ok)
	}
	if u := again.Usage(w, c.now(), 0); u.Hour.Lovelace != 10 || !u.Known(addr(1)) {
		t.Errorf("usage %+v", u)
	}
	if err := again.Sign(ctx, tx(1), sig(1)); err != nil {
		t.Fatal(err)
	}
}

// TestIncompleteLastEntry: a crash in the middle of a write leaves an entry
// that is cut off and reported (section 7.3).
func TestIncompleteLastEntry(t *testing.T) {
	l, c, path := newLedger(t)
	w := walletID(t)
	l.Reserve(ctx, w, tx(1), spend(10), 1, 100)
	l.Close()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.Write([]byte{0, 0, 0, 40, 0xa6})
	f.Close()
	again, rec, err := Open(ctx, path, c.now)
	if err != nil || rec.Discarded != 5 {
		t.Fatalf("got %+v, %v", rec, err)
	}
	defer again.Close()
	if _, ok := again.Lookup(tx(1)); !ok {
		t.Error("the complete entry was lost")
	}
}

// writeRaw writes entries straight into a record, bypassing the checks of the
// ledger, as damage or a bug would.
func writeRaw(t *testing.T, entries ...[2]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.log")
	log, _, err := audit.Open(ctx, path, audit.Options{Kind: Kind})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	for _, e := range entries {
		if _, err := log.Append(ctx, e[0].(string), e[1]); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestInconsistentRecord(t *testing.T) {
	w := string(walletID(t))
	id := func(b byte) []byte { x := tx(b); return x[:] }
	ok1 := [2]any{TypeReserved, reservation{WalletID: w, TxID: id(1), Lovelace: 10}}
	cases := map[string][][2]any{
		"reserved twice":       {ok1, ok1},
		"signed, not reserved": {{TypeSigned, signature{WalletID: w, TxID: id(1), Signature: sig(1)}}},
		"signed twice": {ok1, {TypeSigned, signature{WalletID: w, TxID: id(1), Signature: sig(1)}},
			{TypeSigned, signature{WalletID: w, TxID: id(1), Signature: sig(1)}}},
		"signed by another wallet": {ok1, {TypeSigned, signature{WalletID: string(walletID(t)), TxID: id(1), Signature: sig(1)}}},
		"short signature":          {ok1, {TypeSigned, signature{WalletID: w, TxID: id(1), Signature: sig(1)[:10]}}},
		"released twice": {ok1, {TypeReleased, release{WalletID: w, TxIDs: [][]byte{id(1)}, Lovelace: 10}},
			{TypeReleased, release{WalletID: w, TxIDs: [][]byte{id(1)}, Lovelace: 10}}},
		"release with another sum": {ok1, {TypeReleased, release{WalletID: w, TxIDs: [][]byte{id(1)}, Lovelace: 11}}},
		"release of nothing":       {ok1, {TypeReleased, release{WalletID: w, Lovelace: 0}}},
		"invalid wallet id":        {{TypeReserved, reservation{WalletID: "w_1", TxID: id(1)}}},
		"short transaction id":     {{TypeReserved, reservation{WalletID: w, TxID: id(1)[:31]}}},
		"empty destination":        {{TypeReserved, reservation{WalletID: w, TxID: id(1), Destinations: [][]byte{{}}}}},
		"zero token": {{TypeReserved, reservation{WalletID: w, TxID: id(1),
			Assets: map[cborx.ByteString]map[cborx.ByteString]uint64{cborx.ByteString(make([]byte, 28)): {"A": 0}}}}},
		"unknown field": {{TypeReserved, map[string]any{"wallet_id": w, "tx_id": id(1), "lovelace": uint64(1), "fee": uint64(0), "ttl": uint64(0), "extra": uint64(1)}}},
		"unknown type":  {{"deposit_locked", map[string]any{}}},
	}
	for name, entries := range cases {
		path := writeRaw(t, entries...)
		if l, _, err := Open(ctx, path, time.Now); !errors.Is(err, ErrCorrupt) {
			if l != nil {
				l.Close()
			}
			t.Errorf("%s: got %v", name, err)
		}
	}
	// A log of another kind is not a spending record.
	path := filepath.Join(t.TempDir(), "audit.log")
	log, _, _ := audit.Open(ctx, path, audit.Options{Kind: "audit"})
	log.Close()
	if _, _, err := Open(ctx, path, time.Now); !errors.Is(err, audit.ErrWrongKind) {
		t.Errorf("an audit log: %v", err)
	}
}

// TestTemplateBrakes_R02 is criterion 4 of milestone H-2 (decision 28): the
// default template refuses to send the whole budget at once, and a third new
// destination within the same hour.
func TestTemplateBrakes_R02(t *testing.T) {
	l, c, _ := newLedger(t)
	tpl := policy.DefaultTemplate(model.Preprod)
	own := model.Address{Raw: []byte{0x00, 1}, Type: 0}
	wallet := model.Wallet{ID: walletID(t), Network: model.Preprod, Mode: tpl.Mode, Address: own}
	n := byte(0)
	pay := func(to model.Address, lovelace uint64) policy.Verdict {
		t.Helper()
		ttl := c.slot() + 600
		v := policy.Evaluate(policy.Input{
			Wallet: wallet, Policy: tpl.Policy, CurrentSlot: c.slot(),
			Usage: l.Usage(wallet.ID, c.now(), 0),
			View: model.TxView{Fee: 200_000, TTL: &ttl, Outputs: []model.Output{
				{Address: to, Value: model.Value{Lovelace: lovelace}},
				{Address: own, Value: model.Value{Lovelace: 1_000_000}, Own: true},
			}},
		})
		if v.Status == policy.Allowed {
			n++
			if _, err := l.Reserve(ctx, wallet.ID, tx(n), v.Spend, 200_000, ttl); err != nil {
				t.Fatal(err)
			}
		}
		return v
	}
	blocked := func(v policy.Verdict, rule policy.Rule) {
		t.Helper()
		if v.Status != policy.Blocked || v.Rule != rule || v.Code != policy.CodeBudgetExceeded {
			t.Fatalf("got %s/%s (%s), want blocked by %s", v.Status, v.Rule, v.Detail, rule)
		}
	}
	allowed := func(v policy.Verdict) {
		t.Helper()
		if v.Status != policy.Allowed {
			t.Fatalf("got %s/%s: %s", v.Status, v.Rule, v.Detail)
		}
	}

	blocked(pay(addr(1), tpl.Policy.Limits.Budget), policy.RulePerTx)
	allowed(pay(addr(1), 5_000_000))
	c.advance(10 * time.Minute)
	allowed(pay(addr(2), 5_000_000))
	c.advance(10 * time.Minute)
	blocked(pay(addr(3), 5_000_000), policy.RuleNewPerHour)
	// A destination the wallet knows still passes, and an hour after the
	// first one the third destination does too.
	allowed(pay(addr(1), 5_000_000))
	c.advance(41 * time.Minute)
	allowed(pay(addr(3), 5_000_000))
}

// TestNoSequenceExceedsTheLimits is the property of step 5 of the plan: under
// any sequence of payments, releases and budget resets, what the wallet
// signs never takes a window or the budget beyond its limit. The test keeps
// its own plain account of every signature and checks the ledger against it
// at every step.
func TestNoSequenceExceedsTheLimits(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 8))
	dests := make([]model.Address, 12)
	for i := range dests {
		dests[i] = addr(byte(i + 1))
	}
	own := model.Address{Raw: []byte{0x00, 1}, Type: 0}

	type signed struct {
		at       time.Time
		seq      uint64
		lovelace uint64
		to       []model.Address
		ttl      uint64
		released bool
	}
	blocked := map[policy.Rule]int{}
	allowed := 0
	// Each reservation waits for the disk, so the sample is kept small; the
	// spend counts from the reservation, and the signature changes nothing.
	for run := range 15 {
		l, c, path := newLedger(t)
		w := model.Wallet{ID: walletID(t), Network: model.Preprod, Mode: model.ModeC, Address: own}
		pol := policy.DefaultTemplate(model.Preprod).Policy
		lim := &pol.Limits
		lim.PerTx = uint64(1+r.IntN(30)) * 1_000_000
		lim.PerHour = uint64(1+r.IntN(60)) * 1_000_000
		lim.PerDay = uint64(1+r.IntN(150)) * 1_000_000
		lim.Budget = uint64(1+r.IntN(200)) * 1_000_000
		lim.TxPerHour = uint32(1 + r.IntN(8))
		lim.NewDestinationsPerHour = uint32(r.IntN(4))
		lim.NewDestinationsPerDay = uint32(r.IntN(8))

		var log []signed
		var since uint64
		for range 250 {
			c.advance(time.Duration(r.IntN(40)) * time.Minute)
			now, slot := c.now(), c.slot()

			switch r.IntN(20) {
			case 0: // the person releases what expired
				var ids [][32]byte
				var sum uint64
				for _, p := range l.Pending(w.ID, slot) {
					ids = append(ids, p.TxID)
					sum += p.Lovelace
				}
				if len(ids) > 0 {
					if n, err := l.Release(ctx, w.ID, ids, slot); err != nil || n != sum {
						t.Fatalf("release: %d, %v", n, err)
					}
					for i := range log {
						if log[i].ttl <= slot {
							log[i].released = true
						}
					}
				}
			case 1: // the person sets a new budget
				since = l.Seq()
			}

			var outs []model.Output
			var to []model.Address
			for range r.IntN(3) {
				d := dests[r.IntN(len(dests))]
				outs = append(outs, model.Output{Address: d, Value: model.Value{Lovelace: uint64(r.IntN(int(lim.PerTx)))}})
				to = append(to, d)
			}
			outs = append(outs, model.Output{Address: own, Value: model.Value{Lovelace: 1}, Own: true})
			ttl := slot + uint64(60+r.IntN(3000))
			usage := l.Usage(w.ID, now, since)
			v := policy.Evaluate(policy.Input{Wallet: w, Policy: pol, CurrentSlot: slot, Usage: usage,
				View: model.TxView{Fee: 170_000, TTL: &ttl, Outputs: outs}})

			// The ledger agrees with the plain account.
			var hour, day policy.Window
			var budget uint64
			seen := map[string]time.Time{}
			for _, s := range log {
				for _, d := range s.to {
					if _, ok := seen[string(d.Raw)]; !ok {
						seen[string(d.Raw)] = s.at
					}
				}
				if s.released {
					continue
				}
				if s.at.After(now.Add(-time.Hour)) {
					hour.Lovelace += s.lovelace
					hour.Transactions++
				}
				if s.at.After(now.Add(-24 * time.Hour)) {
					day.Lovelace += s.lovelace
					day.Transactions++
				}
				if s.seq > since {
					budget += s.lovelace
				}
			}
			for _, at := range seen {
				if at.After(now.Add(-time.Hour)) {
					hour.NewDestinations++
				}
				if at.After(now.Add(-24 * time.Hour)) {
					day.NewDestinations++
				}
			}
			if usage.Hour != hour || usage.Day != day || usage.BudgetSpent != budget {
				t.Fatalf("run %d: the ledger says %+v %+v %d, the account %+v %+v %d",
					run, usage.Hour, usage.Day, usage.BudgetSpent, hour, day, budget)
			}
			if v.Status != policy.Allowed {
				blocked[v.Rule]++
				continue
			}
			allowed++

			// What is allowed stays within every limit.
			var fresh uint32
			for _, d := range v.Spend.Destinations {
				if _, ok := seen[string(d.Raw)]; !ok {
					fresh++
				}
			}
			switch {
			case hour.Lovelace+v.Spend.Lovelace > lim.PerHour, day.Lovelace+v.Spend.Lovelace > lim.PerDay,
				budget+v.Spend.Lovelace > lim.Budget, hour.Transactions+1 > lim.TxPerHour,
				hour.NewDestinations+fresh > lim.NewDestinationsPerHour, day.NewDestinations+fresh > lim.NewDestinationsPerDay:
				t.Fatalf("run %d: allowed beyond a limit: %+v with %+v %+v %d", run, v.Spend, hour, day, budget)
			}
			id := [32]byte{byte(run), byte(len(log)), byte(len(log) >> 8)}
			rec, err := l.Reserve(ctx, w.ID, id, v.Spend, 170_000, ttl)
			if err != nil {
				t.Fatal(err)
			}
			log = append(log, signed{at: now, seq: rec.Seq, lovelace: v.Spend.Lovelace, to: v.Spend.Destinations, ttl: ttl})
		}
		if len(log) == 0 {
			t.Fatalf("run %d signed nothing", run)
		}

		// Replaying the record gives the same account.
		want := l.Usage(w.ID, c.now(), since)
		l.Close()
		again := open(t, path, c)
		if got := again.Usage(w.ID, c.now(), since); got.Hour != want.Hour || got.Day != want.Day || got.BudgetSpent != want.BudgetSpent {
			t.Fatalf("run %d: after reopening %+v, before %+v", run, got, want)
		}
	}
	// The sample reaches every limit, and signs plenty.
	t.Logf("%d signed; blocked: %v", allowed, blocked)
	for _, rule := range []policy.Rule{policy.RulePerTx, policy.RulePerHour, policy.RulePerDay, policy.RuleTxPerHour,
		policy.RuleNewPerHour, policy.RuleNewPerDay, policy.RuleBudget} {
		if blocked[rule] == 0 {
			t.Errorf("no transaction reached %s", rule)
		}
	}
	if allowed < 500 {
		t.Errorf("only %d signed", allowed)
	}
}

func FuzzApply(f *testing.F) {
	c := newCodec()
	enc := func(v any) []byte {
		b, err := c.Marshal(v)
		if err != nil {
			f.Fatal(err)
		}
		return b
	}
	w := string(walletID(f))
	id := tx(1)
	f.Add(TypeReserved, enc(reservation{WalletID: w, TxID: id[:], Lovelace: 10, Destinations: [][]byte{{1}}}),
		TypeSigned, enc(signature{WalletID: w, TxID: id[:], Signature: sig(1)}),
		TypeReleased, enc(release{WalletID: w, TxIDs: [][]byte{id[:]}, Lovelace: 10}))
	f.Fuzz(func(t *testing.T, t1 string, b1 []byte, t2 string, b2 []byte, t3 string, b3 []byte) {
		st := newState()
		for i, e := range []audit.Entry{{Type: t1, Body: b1}, {Type: t2, Body: b2}, {Type: t3, Body: b3}} {
			e.Seq, e.Time = uint64(i+2), 1
			if err := st.apply(c, e); err != nil {
				if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("an error that is not ErrCorrupt: %v", err)
				}
				return
			}
		}
		// Whatever replays leaves a state Usage can read.
		for id := range st.wallets {
			l := &Ledger{st: st}
			l.Usage(id, time.Unix(1, 0), 0)
		}
	})
}
