// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package authz

import (
	"errors"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

const wallet = model.WalletID("w_aeaqcaibaeaqcaibaeaqcaibae")

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newAuthorizer() (*Authorizer, *clock) {
	c := &clock{t: time.Unix(1_792_000_000, 0)}
	a := New(model.Preprod)
	a.Now = c.now
	return a, c
}

func password(ok bool) func() error {
	return func() error {
		if ok {
			return nil
		}
		return ErrWrongPassword
	}
}

func TestCanonicalMessage(t *testing.T) {
	a, c := newAuthorizer()
	det := map[string]any{"seconds": uint64(3600), "max": uint64(50_000_000)}
	au, err := a.Begin("open_session", wallet, det, "params")
	if err != nil {
		t.Fatal(err)
	}
	codec, _ := cborx.New(cborx.RecordLimits())
	if err := codec.CheckCanonical(au.Message); err != nil {
		t.Fatalf("the message is not canonical: %v", err)
	}
	var m Message
	if err := codec.Unmarshal(au.Message, &m); err != nil {
		t.Fatal(err)
	}
	var gotDet map[string]uint64
	codec.Unmarshal(m.Det, &gotDet)
	if m.Ctx != Context || m.Net != "preprod" || m.Act != "open_session" || m.Wal != string(wallet) ||
		len(m.Chl) != 32 || m.Exp != c.t.Add(DefaultTTL).Unix() || gotDet["seconds"] != 3600 || gotDet["max"] != 50_000_000 {
		t.Errorf("message %+v, det %v", m, gotDet)
	}

	// No wallet and no detail: wal is left out and det is an empty map.
	au2, _ := a.Begin("set_template", "", nil, nil)
	var m2 Message
	codec.Unmarshal(au2.Message, &m2)
	if m2.Wal != "" || string(m2.Det) != "\xa0" || string(m2.Chl) == string(m.Chl) || au2.ID == au.ID {
		t.Errorf("second message %+v", m2)
	}
}

func TestCompleteOnce(t *testing.T) {
	a, c := newAuthorizer()
	au, _ := a.Begin("unfreeze", wallet, nil, "params")
	got, err := a.Complete(au.ID, password(true))
	if err != nil || got.Params != "params" || got.Action != "unfreeze" {
		t.Fatalf("complete: %+v, %v", got, err)
	}
	if _, err := a.Complete(au.ID, password(true)); !errors.Is(err, ErrExpired) {
		t.Errorf("used twice: %v", err)
	}
	if _, err := a.Complete([IDSize]byte{1}, password(true)); !errors.Is(err, ErrExpired) {
		t.Errorf("an unknown id: %v", err)
	}
	au, _ = a.Begin("unfreeze", wallet, nil, nil)
	c.advance(DefaultTTL)
	if _, err := a.Complete(au.ID, password(true)); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: %v", err)
	}
}

// secret stands for params that hold a secret, like restore_wallet's.
type secret struct{ wiped bool }

func (s *secret) Wipe() { s.wiped = true }

// TestUnrunParamsAreWiped: the params of a challenge that expires are wiped,
// wherever the Authorizer notices; those of one that completes are left for
// the action to run with.
func TestUnrunParamsAreWiped(t *testing.T) {
	a, c := newAuthorizer()
	run, opened, checked, swept := &secret{}, &secret{}, &secret{}, &secret{}
	au, _ := a.Begin("restore_wallet", "", nil, run)
	if _, err := a.Complete(au.ID, password(true)); err != nil || run.wiped {
		t.Fatalf("completed: %v, wiped %v", err, run.wiped)
	}
	au, _ = a.Begin("restore_wallet", "", nil, checked)
	expire := func() error { c.advance(DefaultTTL); return nil }
	if _, err := a.Complete(au.ID, expire); !errors.Is(err, ErrExpired) || !checked.wiped {
		t.Errorf("expired during the check: %v, wiped %v", err, checked.wiped)
	}
	au, _ = a.Begin("restore_wallet", "", nil, opened)
	a.Begin("restore_wallet", "", nil, swept)
	c.advance(DefaultTTL)
	if _, err := a.Complete(au.ID, password(true)); !errors.Is(err, ErrExpired) || !opened.wiped {
		t.Errorf("expired: %v, wiped %v", err, opened.wiped)
	}
	if a.Begin("unfreeze", wallet, nil, nil); !swept.wiped {
		t.Error("swept by Begin, not wiped")
	}
}

func TestWrongPasswordDoublesTheWait(t *testing.T) {
	a, c := newAuthorizer()
	au, _ := a.Begin("unfreeze", wallet, nil, nil)
	ran := 0
	check := func(ok bool) func() error {
		return func() error { ran++; return password(ok)() }
	}
	if _, err := a.Complete(au.ID, check(false)); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("first wrong password: %v", err)
	}
	for n, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second} {
		// Too soon: refused without checking, even with the right password.
		ran = 0
		_, err := a.Complete(au.ID, check(true))
		var w *WaitError
		if !errors.As(err, &w) || w.Wait != want || ran != 0 {
			t.Fatalf("attempt %d too soon: %v, ran %d", n, err, ran)
		}
		c.advance(want)
		if n < 3 {
			a.Complete(au.ID, check(false))
		}
	}
	// The challenge stayed open through the wrong passwords.
	if _, err := a.Complete(au.ID, check(true)); err != nil {
		t.Fatalf("right password after waiting: %v", err)
	}
	// Success resets the wait.
	if err := a.Attempt(password(false)); !errors.Is(err, ErrWrongPassword) {
		t.Fatal(err)
	}
	c.advance(time.Second)
	if err := a.Attempt(password(true)); err != nil {
		t.Errorf("after reset: %v", err)
	}
}

func TestWaitIsCapped(t *testing.T) {
	a, c := newAuthorizer()
	for range 40 {
		a.Attempt(password(false))
		c.advance(DefaultMaxWait)
	}
	a.Attempt(password(false))
	err := a.Attempt(password(true))
	var w *WaitError
	if !errors.As(err, &w) || w.Wait != DefaultMaxWait {
		t.Errorf("after 41 wrong passwords: %v", err)
	}
}

func TestOtherErrorsDoNotCount(t *testing.T) {
	a, _ := newAuthorizer()
	other := errors.New("disk failed")
	if err := a.Attempt(func() error { return other }); err != other {
		t.Errorf("%v", err)
	}
	if err := a.Attempt(password(true)); err != nil {
		t.Errorf("an error that is not a wrong password made a wait: %v", err)
	}
}

func TestTooManyOpen(t *testing.T) {
	a, c := newAuthorizer()
	for range DefaultMaxPending {
		if _, err := a.Begin("unfreeze", wallet, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Begin("unfreeze", wallet, nil, nil); !errors.Is(err, ErrTooMany) {
		t.Errorf("one too many: %v", err)
	}
	c.advance(DefaultTTL)
	if _, err := a.Begin("unfreeze", wallet, nil, nil); err != nil {
		t.Errorf("after the others expired: %v", err)
	}
}
