// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package datasource

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// fakeSource answers every call with its tip, or fails with err. It counts
// the calls it gets.
type fakeSource struct {
	name    string
	network model.Network
	err     atomic.Pointer[error]
	byPrint error // what AssetByFingerprint fails with, if not err
	sent    atomic.Int32
	calls   atomic.Int32
}

func newFake(name string) *fakeSource { return &fakeSource{name: name, network: model.Preprod} }

func (f *fakeSource) fail(err error) { f.err.Store(&err) }

func (f *fakeSource) answer() error {
	f.calls.Add(1)
	if p := f.err.Load(); p != nil {
		return *p
	}
	return nil
}

func (f *fakeSource) Name() string           { return f.name }
func (f *fakeSource) Network() model.Network { return f.network }
func (f *fakeSource) CheckNetwork(context.Context) error {
	if f.network != model.Preprod {
		return ErrNetworkMismatch
	}
	return f.answer()
}
func (f *fakeSource) Tip(context.Context) (Tip, error) {
	return Tip{Height: uint64(len(f.name))}, f.answer()
}
func (f *fakeSource) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{}, f.answer()
}
func (f *fakeSource) UTxOs(context.Context, model.Address) ([]chain.UTxO, error) {
	return nil, f.answer()
}
func (f *fakeSource) Account(context.Context, string) (Account, error) { return Account{}, f.answer() }
func (f *fakeSource) Asset(context.Context, model.AssetID) (Asset, error) {
	return Asset{Supply: f.name}, f.answer()
}
func (f *fakeSource) AssetByFingerprint(context.Context, string) (model.AssetID, error) {
	if f.byPrint != nil {
		f.calls.Add(1)
		return model.AssetID{}, f.byPrint
	}
	return model.AssetID{}, f.answer()
}
func (f *fakeSource) Transaction(context.Context, [32]byte) (Transaction, error) {
	return Transaction{}, f.answer()
}
func (f *fakeSource) Submit(context.Context, []byte, [32]byte) error {
	f.sent.Add(1)
	return f.answer()
}
func (f *fakeSource) Confirmations(_ context.Context, ids [][32]byte) (map[[32]byte]uint64, error) {
	return map[[32]byte]uint64{}, f.answer()
}

// testRelay is a relay over a and b, in that order, with a clock the test
// moves.
func testRelay(t *testing.T, sources ...Source) (*Relay, *time.Time) {
	t.Helper()
	r, err := NewRelay(sources, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	return r, &now
}

func TestRelayPassesOnAndSetsAside(t *testing.T) {
	a, b := newFake("a"), newFake("bb")
	r, now := testRelay(t, a, b)

	if tip, err := r.Tip(ctx); err != nil || tip.Height != 1 || b.calls.Load() != 0 {
		t.Fatalf("the first source answers: %+v, %v", tip, err)
	}

	for _, failure := range []error{ErrUnavailable, ErrInvalidResponse} {
		a, b := newFake("a"), newFake("bb")
		r, now := testRelay(t, a, b)
		a.fail(fmt.Errorf("%w: down", failure))
		if tip, err := r.Tip(ctx); err != nil || tip.Height != 2 {
			t.Errorf("%v: the second answers: %+v, %v", failure, tip, err)
		}
		// Set aside: the next call goes to b first.
		r.Tip(ctx)
		if a.calls.Load() != 1 || b.calls.Load() != 2 {
			t.Errorf("%v: a asked %d times, b %d", failure, a.calls.Load(), b.calls.Load())
		}
		// A minute later, a is asked first again, and answers.
		*now = now.Add(asideFor)
		a.err.Store(nil)
		if tip, _ := r.Tip(ctx); tip.Height != 1 {
			t.Errorf("%v: after a minute, %+v", failure, tip)
		}
	}

	// An answer that is not a failure of the source does not pass on.
	a.fail(ErrNotFound)
	if _, err := r.Account(ctx, "stake_test1x"); !errors.Is(err, ErrNotFound) || b.calls.Load() != 0 {
		t.Errorf("not found: %v, b asked %d times", err, b.calls.Load())
	}
	a.fail(ErrTooManyUTxOs)
	if _, err := r.UTxOs(ctx, model.Address{}); !errors.Is(err, ErrTooManyUTxOs) || b.calls.Load() != 0 {
		t.Errorf("too many UTxOs: %v", err)
	}
	*now = now.Add(time.Second)
	if tip, _ := r.Tip(ctx); tip.Height != 1 {
		t.Error("an answer set the source aside")
	}
}

func TestRelayUnsupported(t *testing.T) {
	a, b := newFake("a"), newFake("bb")
	a.byPrint = fmt.Errorf("%w: no fingerprints", ErrUnsupported)
	r, _ := testRelay(t, a, b)
	if _, err := r.AssetByFingerprint(ctx, "asset1x"); err != nil || b.calls.Load() != 1 {
		t.Errorf("the second looks it up: %v", err)
	}
	// a was not set aside for declining.
	if tip, _ := r.Tip(ctx); tip.Height != 1 {
		t.Error("a source that declined a query was set aside")
	}

	b.byPrint = a.byPrint
	if _, err := r.AssetByFingerprint(ctx, "asset1x"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("no source looks it up: %v", err)
	}
	// When one source is down and the other declines, the agent should come
	// back later rather than give up.
	b.byPrint = nil
	b.fail(ErrUnavailable)
	if _, err := r.AssetByFingerprint(ctx, "asset1x"); !errors.Is(err, ErrUnavailable) || !strings.HasPrefix(err.Error(), "bb: ") {
		t.Errorf("declined and down: %v", err)
	}
}

func TestRelayAllFail(t *testing.T) {
	a, b := newFake("a"), newFake("bb")
	a.fail(fmt.Errorf("%w: a is down", ErrUnavailable))
	b.fail(fmt.Errorf("%w: b lies", ErrInvalidResponse))
	r, _ := testRelay(t, a, b)
	_, err := r.Tip(ctx)
	if !errors.Is(err, ErrUnavailable) || err.Error() != "a: datasource: unavailable: a is down" {
		t.Errorf("got %v", err)
	}
	// Both are set aside, so both are still tried, in order of preference.
	if _, err := r.Tip(ctx); a.calls.Load() != 2 || b.calls.Load() != 2 || !errors.Is(err, ErrUnavailable) {
		t.Errorf("a asked %d times, b %d: %v", a.calls.Load(), b.calls.Load(), err)
	}
}

func TestRelaySubmitDoesNotPassOn(t *testing.T) {
	a, b := newFake("a"), newFake("bb")
	r, _ := testRelay(t, a, b)
	a.fail(fmt.Errorf("%w: time-out", ErrUnavailable))
	if err := r.Submit(ctx, nil, [32]byte{}); !errors.Is(err, ErrUnavailable) || b.sent.Load() != 0 {
		t.Errorf("an unclear send: %v, b got %d", err, b.sent.Load())
	}
	// The retry, which asks the chain first, sends through b.
	if err := r.Submit(ctx, nil, [32]byte{}); err != nil || a.sent.Load() != 1 || b.sent.Load() != 1 {
		t.Errorf("the retry: %v, a got %d, b %d", err, a.sent.Load(), b.sent.Load())
	}

	c, d := newFake("c"), newFake("dd")
	r, _ = testRelay(t, c, d)
	c.fail(fmt.Errorf("%w: BadInputsUTxO", ErrRejected))
	if err := r.Submit(ctx, nil, [32]byte{}); !errors.Is(err, ErrRejected) || err.Error() != "datasource: the node rejected the transaction: BadInputsUTxO" {
		t.Errorf("a rejection: %v", err)
	}
	if r.Submit(ctx, nil, [32]byte{}); c.sent.Load() != 2 {
		t.Error("a rejection set the source aside")
	}
}

func TestRelayCanceled(t *testing.T) {
	a, b := newFake("a"), newFake("bb")
	r, _ := testRelay(t, a, b)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	a.fail(fmt.Errorf("%w: %w", ErrUnavailable, context.Canceled))
	if _, err := r.Tip(canceled); !errors.Is(err, context.Canceled) || b.calls.Load() != 0 {
		t.Errorf("canceled: %v, b asked %d times", err, b.calls.Load())
	}
	a.err.Store(nil)
	if tip, _ := r.Tip(ctx); tip.Height != 1 {
		t.Error("a canceled call set the source aside")
	}
}

func TestRelayConfirmationsFrom(t *testing.T) {
	a, b := newFake("a"), newFake("bb")
	r, _ := testRelay(t, a, b)
	if _, from, err := r.ConfirmationsFrom(ctx, nil); err != nil || from != "a" {
		t.Errorf("from %q, %v", from, err)
	}
	a.fail(ErrUnavailable)
	if _, from, err := r.ConfirmationsFrom(ctx, nil); err != nil || from != "bb" {
		t.Errorf("from %q, %v", from, err)
	}
}

func TestRelayCheckNetwork(t *testing.T) {
	a, b := newFake("a"), newFake("bb")
	r, _ := testRelay(t, a, b)
	if err := r.CheckNetwork(ctx); err != nil {
		t.Fatal(err)
	}
	a.fail(ErrUnavailable)
	err := r.CheckNetwork(ctx)
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNetworkMismatch) || !strings.Contains(err.Error(), "a: ") {
		t.Errorf("a source down: %v", err)
	}
	if tip, _ := r.Tip(ctx); tip.Height != 2 {
		t.Error("a source down at start-up was not set aside")
	}

	c := newFake("c")
	c.network = model.Preview
	r, err = NewRelay([]Source{a, c}, nil)
	if err == nil {
		t.Error("a relay over two networks")
	}
	// A source that says it serves preprod and does not.
	liar := &mislabeled{newFake("liar")}
	r, _ = testRelay(t, a, liar)
	if err := r.CheckNetwork(ctx); !errors.Is(err, ErrNetworkMismatch) {
		t.Errorf("a source of another network: %v", err)
	}
}

type mislabeled struct{ *fakeSource }

func (m *mislabeled) CheckNetwork(context.Context) error { return ErrNetworkMismatch }

func TestNewRelay(t *testing.T) {
	if _, err := NewRelay(nil, nil); err == nil {
		t.Error("a relay over nothing")
	}
	if _, err := NewRelay([]Source{newFake("a"), newFake("a")}, nil); err == nil {
		t.Error("two sources with one name")
	}
	r, _ := testRelay(t, newFake("blockfrost"), newFake("koios"))
	if r.Name() != "blockfrost,koios" || r.Network() != model.Preprod {
		t.Errorf("%s on %s", r.Name(), r.Network())
	}
}

func TestProbeAll(t *testing.T) {
	a, b := newFake("a"), newFake("bb")
	r, _ := testRelay(t, a, b)
	a.fail(ErrUnavailable)
	got := ProbeAll(ctx, r)
	if len(got) != 2 || got[0].Name != "a" || !errors.Is(got[0].Err, ErrUnavailable) || got[1].Name != "bb" || got[1].Err != nil || got[1].Tip.Height != 2 {
		t.Errorf("probes %+v", got)
	}
	// The probe set a aside.
	a.err.Store(nil)
	if tip, _ := r.Tip(ctx); tip.Height != 2 {
		t.Error("a failed probe did not set the source aside")
	}
	if got := ProbeAll(ctx, b); len(got) != 1 || got[0].Name != "bb" || got[0].Err != nil {
		t.Errorf("one source: %+v", got)
	}
}

// TestRelayPrefer: a view asks the sources in its own order and shares with
// the relay which ones are set aside (decision 137).
func TestRelayPrefer(t *testing.T) {
	a, b, c := newFake("a"), newFake("bb"), newFake("ccc")
	r, _ := testRelay(t, a, b, c)
	v, err := r.Prefer([]string{"ccc", "a"})
	if err != nil || v.Name() != "ccc,a" || !slices.Equal(v.Names(), []string{"a", "bb", "ccc"}) {
		t.Fatalf("view %v, %v", v, err)
	}
	if tip, _ := v.Tip(ctx); tip.Height != 3 {
		t.Errorf("the view asks ccc first: %+v", tip)
	}
	// ccc goes down for the view, and so for the relay.
	c.fail(ErrUnavailable)
	if tip, _ := v.Tip(ctx); tip.Height != 1 {
		t.Errorf("the view passes on to a: %+v", tip)
	}
	if got := ProbeAll(ctx, v); len(got) != 3 || got[0].Name != "a" || got[2].Name != "ccc" {
		t.Errorf("a view probes every configured source: %+v", got)
	}
	// A view of one source does not pass on to the others.
	only, _ := r.Prefer([]string{"ccc"})
	if _, err := only.Tip(ctx); !errors.Is(err, ErrUnavailable) || b.calls.Load() != 1 {
		t.Errorf("a view of ccc alone: %v, bb asked %d times", err, b.calls.Load())
	}
	if all, err := r.Prefer(nil); err != nil || all.Name() != "a,bb,ccc" {
		t.Errorf("no names: %v, %v", all, err)
	}
	for _, names := range [][]string{{"d"}, {"a", "a"}} {
		if _, err := r.Prefer(names); err == nil {
			t.Errorf("%v accepted", names)
		}
	}
	// The names a relay over named clients gives.
	k, _ := NewKoios(KoiosConfig{Network: model.Preprod, Name: "my-koios", BaseURL: "http://127.0.0.1:1"})
	if k.Name() != "my-koios" {
		t.Errorf("name %q", k.Name())
	}
}
