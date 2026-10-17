// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package drafts

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/policy"
)

// TestTransitions checks the state machine against section 3.4, written out
// here a second time: every state with every event, accepted or refused.
func TestTransitions(t *testing.T) {
	want := map[string]State{
		"draft authorize":          StateAuthorizing,
		"draft cancel":             StateCancelled,
		"draft expire":             StateExpired,
		"authorizing ask_approval": StatePendingApproval,
		"authorizing sign":         StateSigned,
		"authorizing reject":       StateRejected,
		"authorizing cancel":       StateCancelled,
		"authorizing expire":       StateExpired,
		"pending_approval sign":    StateSigned,
		"pending_approval reject":  StateRejected,
		"pending_approval cancel":  StateCancelled,
		"pending_approval expire":  StateExpired,
		"signed submit":            StateSubmitted,
		"signed fail":              StateFailed,
		"signed expire":            StateExpired,
		"submitted confirm":        StateConfirmed,
		"submitted fail":           StateFailed,
		"submitted expire":         StateExpired,
		"confirmed confirm":        StateConfirmed,
		"confirmed roll_back":      StateRolledBack,
		"rolled_back reenter":      StateSubmitted,
		"rolled_back expire":       StateExpired,
	}
	accepted := 0
	for _, s := range States {
		for _, e := range Events {
			got, ok := next(s, e)
			exp, should := want[string(s)+" "+string(e)]
			switch {
			case ok != should:
				t.Errorf("%s + %s: accepted %v, want %v", s, e, ok, should)
			case ok && got != exp:
				t.Errorf("%s + %s → %s, want %s", s, e, got, exp)
			}
			if ok {
				accepted++
			}
		}
	}
	if accepted != len(want) {
		t.Errorf("%d transitions, the specification has %d", accepted, len(want))
	}
	for _, s := range States {
		if s.Final() && len(transitions[s]) > 0 {
			t.Errorf("final state %s has transitions", s)
		}
		if s.Final() == s.Live() && s != StateConfirmed {
			t.Errorf("%s is both or neither final and live", s)
		}
	}
}

// The parameters of preprod at epoch 319.
func params() chain.ProtocolParameters {
	return chain.ProtocolParameters{
		Epoch: 319, MinFeeA: 44, MinFeeB: 155381, MaxTxSize: 16384, MaxValueSize: 5000, CoinsPerUTxOByte: 4310,
		KeyDeposit: 2_000_000, PoolDeposit: 500_000_000, DRepDeposit: 500_000_000, GovActionDeposit: 1_000_000_000,
		PriceMem: chain.Rational{Num: 577, Den: 10000}, PriceStep: chain.Rational{Num: 721, Den: 10000000},
		MaxTxExMem: 17_500_000, MaxTxExSteps: 10_000_000_000, CollateralPercent: 150, MaxCollateralInputs: 3,
		MinFeeRefScriptByte: chain.Rational{Num: 15, Den: 1}, ProtocolMajor: 11,
	}
}

func ada(n uint64) uint64 { return n * 1_000_000 }

// clock is a settable server clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *clock) advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

// fixture is a mode A wallet whose key the test holds, standing in for the
// hardware wallet, with a store and a clock.
type fixture struct {
	t      *testing.T
	priv   ed25519.PrivateKey
	wallet model.Wallet
	policy model.Policy
	clock  *clock
	store  *Store
	shop   model.Address
}

func newFixture(t *testing.T) *fixture {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	h, _ := blake2b.New(28, nil)
	h.Write(priv.Public().(ed25519.PublicKey))
	addr, err := chain.AddressFromBytes(append(append([]byte{0x00}, h.Sum(nil)...), bytes.Repeat([]byte{0x5a}, 28)...))
	if err != nil {
		t.Fatal(err)
	}
	shop, err := chain.AddressFromBytes(append([]byte{0x60}, bytes.Repeat([]byte{0x77}, 28)...))
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	return &fixture{
		t: t, priv: priv, shop: shop, clock: c,
		wallet: model.Wallet{ID: "w_k3fq2mx7c4v6bn5ta2sd7hpely", Network: model.Preprod, Mode: model.ModeA, Address: addr, CreatedBy: model.ByPerson},
		policy: model.Policy{
			Networks:     []model.Network{model.Preprod},
			Limits:       model.Limits{PerTx: ada(1000), MaxFee: ada(2), MaxLiveDrafts: 3, MaxTTLSeconds: 7200},
			Destinations: model.Destinations{Any: true},
			UTxO:         model.UTxOPolicy{TargetADAOnly: 1, MinSplit: ada(5), DustThreshold: ada(1), MaxDustSweep: 2},
		},
		store: New(c.now, nil),
	}
}

func (f *fixture) utxos(amounts ...uint64) []chain.UTxO {
	var out []chain.UTxO
	for i, a := range amounts {
		out = append(out, chain.UTxO{In: chain.TxIn{TxID: [32]byte{0: 0xee, 31: byte(i)}}, Address: f.wallet.Address, Value: model.Value{Lovelace: a}})
	}
	return out
}

func (f *fixture) request(lovelace uint64, utxos []chain.UTxO) Request {
	return Request{
		Wallet: f.wallet, Policy: f.policy, UTxOs: utxos, Params: params(),
		TipSlot: chain.Clock(model.Preprod).Slot(f.clock.now()),
		Intent: model.Intent{Kind: model.IntentPayment, Payment: &model.Payment{
			Outputs: []model.PaymentOutput{{Address: f.shop, Value: model.Value{Lovelace: lovelace}}}}},
	}
}

func (f *fixture) create(lovelace uint64, utxos []chain.UTxO) Draft {
	f.t.Helper()
	d, err := f.store.Create(f.request(lovelace, utxos))
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}

// witnesses signs the draft's transaction id with key, as the hardware
// wallet would, and returns the witness set.
func witnesses(t *testing.T, key ed25519.PrivateKey, id [32]byte) []byte {
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

func (f *fixture) reserved() int { return len(f.store.Reserved(f.wallet.ID)) }

// TestModeAFlow walks a draft along the main path of section 3.4 in mode A,
// with the repeated calls of section 9.4.
func TestModeAFlow(t *testing.T) {
	f := newFixture(t)
	d := f.create(ada(5), f.utxos(ada(50)))
	if d.State != StateDraft || d.Verdict.Status != policy.NeedsApproval || f.reserved() != 1 {
		t.Fatalf("new draft %s, verdict %s, %d reserved", d.State, d.Verdict.Status, f.reserved())
	}
	if d.Summary.NetEffect == nil || d.Summary.Outputs[0].Own == nil || *d.Summary.Outputs[0].Own {
		t.Fatalf("summary %+v", d.Summary)
	}
	for range 2 {
		if d, _ = f.store.Authorize(d.ID); d.State != StatePendingApproval {
			t.Fatalf("authorized draft is %s", d.State)
		}
	}
	if got := f.store.List(f.wallet.ID, StatePendingApproval); len(got) != 1 || got[0].ID != d.ID {
		t.Fatalf("the signer does not find the draft: %v", got)
	}

	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	if _, err := f.store.Sign(d.ID, witnesses(t, other, d.Tx.ID)); !errors.Is(err, ErrMismatch) {
		t.Fatalf("a signature by another key: %v", err)
	}
	if _, err := f.store.Sign(d.ID, witnesses(t, f.priv, [32]byte{1})); !errors.Is(err, ErrMismatch) {
		t.Fatalf("a signature of another transaction: %v", err)
	}
	if _, err := f.store.Sign(d.ID, []byte{0xff}); !errors.Is(err, ErrMismatch) {
		t.Fatalf("garbage: %v", err)
	}
	if again, _ := f.store.Get(d.ID); again.State != StatePendingApproval {
		t.Fatalf("a bad signature moved the draft to %s", again.State)
	}
	w := witnesses(t, f.priv, d.Tx.ID)
	for range 2 {
		if d, err := f.store.Sign(d.ID, w); err != nil || d.State != StateSigned || len(d.Signed) == 0 {
			t.Fatalf("signing: %v, %s", err, d.State)
		}
	}

	steps := []struct {
		do   func() (Draft, error)
		want State
	}{
		{func() (Draft, error) { return f.store.Submitted(d.ID) }, StateSubmitted},
		{func() (Draft, error) { return f.store.Confirmed(d.ID, 1) }, StateConfirmed},
		{func() (Draft, error) { return f.store.Confirmed(d.ID, 5) }, StateConfirmed},
		{func() (Draft, error) { return f.store.RolledBack(d.ID) }, StateRolledBack},
		{func() (Draft, error) { return f.store.Reentered(d.ID) }, StateSubmitted},
		{func() (Draft, error) { return f.store.Confirmed(d.ID, 3) }, StateConfirmed},
	}
	for i, s := range steps {
		got, err := s.do()
		if err != nil || got.State != s.want {
			t.Fatalf("step %d: %v, %s, want %s", i, err, got.State, s.want)
		}
		if f.reserved() != 1 {
			t.Fatalf("step %d: the inputs were freed in %s", i, got.State)
		}
	}
	if got, _ := f.store.Get(d.ID); got.Depth != 3 {
		t.Errorf("depth %d", got.Depth)
	}
	if len(f.store.List(f.wallet.ID, "")) != 0 {
		t.Error("a confirmed draft is listed as live")
	}
	f.clock.advance(Retention + time.Minute)
	if _, err := f.store.Get(d.ID); !errors.Is(err, ErrNotFound) || f.reserved() != 0 {
		t.Errorf("an old confirmed draft is still kept: %v", err)
	}
}

func TestReservations(t *testing.T) {
	f := newFixture(t)
	utxos := f.utxos(ada(50), ada(50))
	a := f.create(ada(20), utxos)
	b := f.create(ada(20), utxos)
	if a.Tx.Inputs[0].In == b.Tx.Inputs[0].In {
		t.Fatal("two drafts took the same UTxO")
	}
	if _, err := f.store.Create(f.request(ada(20), utxos)); !errors.Is(err, ErrNoFreeUTxOs) {
		t.Fatalf("a third draft: %v", err)
	}
	if _, err := f.store.Create(f.request(ada(500), utxos)); errors.Is(err, ErrNoFreeUTxOs) || err == nil {
		t.Fatalf("a payment above the balance: %v", err)
	}
	if _, err := f.store.Cancel(a.ID, ""); err != nil {
		t.Fatal(err)
	}
	if c := f.create(ada(20), utxos); c.Tx.Inputs[0].In != a.Tx.Inputs[0].In {
		t.Error("cancelling did not free the input")
	}
}

func TestMaxLiveDrafts(t *testing.T) {
	f := newFixture(t)
	f.policy.Limits.MaxLiveDrafts = 1
	utxos := f.utxos(ada(50), ada(50))
	a := f.create(ada(5), utxos)
	if _, err := f.store.Create(f.request(ada(5), utxos)); !errors.Is(err, ErrTooManyDrafts) {
		t.Fatalf("second draft: %v", err)
	}
	f.store.Cancel(a.ID, "")
	f.create(ada(5), utxos)

	f.policy.Limits.MaxLiveDrafts = 0 // zero forbids (decision 38)
	if _, err := f.store.Create(f.request(ada(5), utxos)); !errors.Is(err, ErrTooManyDrafts) {
		t.Fatalf("with a maximum of zero: %v", err)
	}
}

func TestBlockedCreatesNothing(t *testing.T) {
	f := newFixture(t)
	f.policy.Frozen = true
	_, err := f.store.Create(f.request(ada(5), f.utxos(ada(50))))
	var blocked *BlockedError
	if !errors.As(err, &blocked) || blocked.Verdict.Rule != policy.RuleFrozen {
		t.Fatalf("got %v", err)
	}
	if f.reserved() != 0 || len(f.store.List("", "")) != 0 {
		t.Error("a blocked transaction left a draft or a reservation")
	}
}

func TestTTL(t *testing.T) {
	f := newFixture(t)
	tip := chain.Clock(model.Preprod).Slot(f.clock.now())
	d := f.create(ada(5), f.utxos(ada(50)))
	if d.Tx.TTL != tip+DefaultTTLSeconds || !d.ExpiresAt.Equal(f.clock.now().Add(DefaultTTLSeconds*time.Second)) {
		t.Errorf("default TTL %d, expires %v", d.Tx.TTL-tip, d.ExpiresAt)
	}
	f.policy.Limits.MaxTTLSeconds = 600
	if d := f.create(ada(5), f.utxos(ada(50), ada(50))); d.Tx.TTL != tip+600 {
		t.Errorf("the default is not capped by the policy: %d", d.Tx.TTL-tip)
	}
	r := f.request(ada(5), f.utxos(ada(50), ada(50), ada(50)))
	r.TTLSeconds = 601
	var blocked *BlockedError
	if _, err := f.store.Create(r); !errors.As(err, &blocked) || blocked.Verdict.Rule != policy.RuleTTL {
		t.Errorf("a TTL above the maximum: %v", err)
	}
}

// TestExpiry: drafts never sent expire with the clock and free their inputs;
// a sent transaction expires only when whoever watches the chain says so.
func TestExpiry(t *testing.T) {
	f := newFixture(t)
	utxos := f.utxos(ada(50), ada(50), ada(50))
	waiting := f.create(ada(5), utxos)
	pending := f.create(ada(5), utxos)
	f.store.Authorize(pending.ID)
	sent := f.create(ada(5), utxos)
	f.store.Authorize(sent.ID)
	if _, err := f.store.Sign(sent.ID, witnesses(t, f.priv, sent.Tx.ID)); err != nil {
		t.Fatal(err)
	}
	f.store.Submitted(sent.ID)

	f.clock.advance(DefaultTTLSeconds*time.Second - time.Second)
	if d, _ := f.store.Get(waiting.ID); d.State != StateDraft {
		t.Fatalf("expired a second early: %s", d.State)
	}
	f.clock.advance(time.Second)
	for _, id := range []model.DraftID{waiting.ID, pending.ID} {
		if d, _ := f.store.Get(id); d.State != StateExpired {
			t.Errorf("%s after its TTL", d.State)
		}
	}
	if _, err := f.store.Authorize(waiting.ID); !errors.Is(err, ErrExpired) {
		t.Errorf("authorizing an expired draft: %v", err)
	}
	if d, _ := f.store.Get(sent.ID); d.State != StateSubmitted || f.reserved() != 1 {
		t.Fatalf("the clock expired a sent transaction: %s, %d reserved", d.State, f.reserved())
	}
	if d, err := f.store.Unconfirmed(sent.ID); err != nil || d.State != StateExpired || f.reserved() != 0 {
		t.Fatalf("unconfirmed: %v, %s, %d reserved", err, d.State, f.reserved())
	}
}

func TestCancelAndReject(t *testing.T) {
	f := newFixture(t)
	utxos := f.utxos(ada(50), ada(50), ada(50))
	a := f.create(ada(5), utxos)
	for range 2 {
		if d, err := f.store.Cancel(a.ID, "changed my mind"); err != nil || d.State != StateCancelled || d.Reason != "changed my mind" {
			t.Fatalf("cancel: %v, %+v", err, d.State)
		}
	}
	b := f.create(ada(5), utxos)
	if _, err := f.store.Cancel(b.ID, RejectedByHardwareWallet); err == nil {
		t.Error("a draft nobody tried to sign was rejected on the device")
	}
	f.store.Authorize(b.ID)
	if d, err := f.store.Cancel(b.ID, RejectedByHardwareWallet); err != nil || d.State != StateRejected {
		t.Fatalf("hw_rejected: %v, %s", err, d.State)
	}
	c := f.create(ada(5), utxos)
	f.store.Authorize(c.ID)
	f.store.Sign(c.ID, witnesses(t, f.priv, c.Tx.ID))
	var se *StateError
	if _, err := f.store.Cancel(c.ID, ""); !errors.As(err, &se) {
		t.Errorf("cancelling a signed draft: %v", err)
	}
	if d, err := f.store.Failed(c.ID, "BadInputsUTxO"); err != nil || d.State != StateFailed || f.reserved() != 0 {
		t.Errorf("failed: %v, %s, %d reserved", err, d.State, f.reserved())
	}
}

func TestUnknownDraft(t *testing.T) {
	f := newFixture(t)
	for name, call := range map[string]func() (Draft, error){
		"get":       func() (Draft, error) { return f.store.Get("d_nothing") },
		"authorize": func() (Draft, error) { return f.store.Authorize("d_nothing") },
		"cancel":    func() (Draft, error) { return f.store.Cancel("d_nothing", "") },
		"sign":      func() (Draft, error) { return f.store.Sign("d_nothing", nil) },
	} {
		if _, err := call(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestConcurrentCreates builds drafts from many goroutines over the same
// UTxOs: no UTxO is ever reserved by two drafts.
func TestConcurrentCreates(t *testing.T) {
	f := newFixture(t)
	f.policy.Limits.MaxLiveDrafts = 100
	var amounts []uint64
	for range 20 {
		amounts = append(amounts, ada(10))
	}
	utxos := f.utxos(amounts...)
	var wg sync.WaitGroup
	results := make(chan Draft, 40)
	for range 40 {
		wg.Go(func() {
			if d, err := f.store.Create(f.request(ada(3), utxos)); err == nil {
				results <- d
			}
		})
	}
	wg.Wait()
	close(results)
	seen := map[chain.TxIn]model.DraftID{}
	n := 0
	for d := range results {
		n++
		for _, u := range d.Tx.Inputs {
			if other, ok := seen[u.In]; ok {
				t.Fatalf("%s is in %s and %s", u.In, other, d.ID)
			}
			seen[u.In] = d.ID
		}
	}
	if n == 0 || len(seen) != f.reserved() {
		t.Fatalf("%d drafts, %d inputs, %d reserved", n, len(seen), f.reserved())
	}
	t.Logf("%d drafts over 20 UTxOs", n)
}
