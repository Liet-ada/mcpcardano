// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package authz authorizes what raises the capacity to spend (section 6.2 of
// the specification). BeginAuthorization makes a single-use challenge around
// the canonical message of section 6.3; CompleteAuthorization checks the
// password and hands the action back to be executed once. In H-2 the password
// is the only method; the FIDO2 key, which signs the hash of the same
// message, arrives in H-3.
//
// Every password check, the unlock at start included, goes through Attempt:
// after each wrong password the wait before the next one is accepted doubles.
package authz

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Context is the ctx field of the canonical message, so that a signature over
// it serves no other purpose.
const Context = "mcpcardano-auth-v1"

// Defaults of an Authorizer.
const (
	DefaultTTL        = 5 * time.Minute // how long a challenge stays valid
	DefaultFirstWait  = time.Second     // after the first wrong password
	DefaultMaxWait    = time.Hour       // the doubling stops here
	DefaultMaxPending = 32              // challenges open at once
	IDSize            = 16
	challengeSize     = 32
)

var (
	ErrExpired       = errors.New("authz: the authorization expired or was used")
	ErrWrongPassword = errors.New("authz: wrong password")
	ErrTooMany       = errors.New("authz: too many authorizations open")
)

// WaitError reports a password attempt made before the wait after a wrong
// one is over. The attempt is not checked.
type WaitError struct {
	Wait time.Duration
}

func (e *WaitError) Error() string {
	return fmt.Sprintf("authz: wait %v before trying another password", e.Wait.Round(time.Second))
}

// Message is the canonical message of section 6.3: a canonical CBOR map that
// the wallet builds and keeps, so the CLI never assembles it.
type Message struct {
	Ctx string    `cbor:"ctx"`
	Net string    `cbor:"net"`
	Act string    `cbor:"act"`
	Wal string    `cbor:"wal,omitempty"`
	Det cborx.Raw `cbor:"det"`
	Chl []byte    `cbor:"chl"`
	Exp int64     `cbor:"exp"` // Unix seconds
}

// Authorization is an open challenge.
type Authorization struct {
	ID      [IDSize]byte
	Action  string
	Wallet  model.WalletID // empty for actions of no wallet
	Params  any            // what the action will run with, as the caller gave it
	Message []byte         // the canonical message, encoded
	Expires time.Time
}

// Authorizer keeps the open challenges and the wait between wrong passwords,
// in memory: a restart drops them, which is the safe side (section 7.1).
type Authorizer struct {
	Network    model.Network
	Now        func() time.Time // defaults to time.Now
	TTL        time.Duration
	FirstWait  time.Duration
	MaxWait    time.Duration
	MaxPending int

	codec *cborx.Codec

	mu        sync.Mutex
	pending   map[[IDSize]byte]*Authorization
	failures  int
	notBefore time.Time
}

// New returns an Authorizer with the defaults.
func New(network model.Network) *Authorizer {
	c, err := cborx.New(cborx.RecordLimits())
	if err != nil {
		panic(err) // the limits are constants
	}
	return &Authorizer{
		Network: network, Now: time.Now, TTL: DefaultTTL, FirstWait: DefaultFirstWait,
		MaxWait: DefaultMaxWait, MaxPending: DefaultMaxPending,
		codec: c, pending: make(map[[IDSize]byte]*Authorization),
	}
}

// Begin opens a challenge for action on wallet (empty if the action is of no
// wallet). det is the detail of the action in the canonical message (section
// 6.3), nil for the actions whose detail is empty; params travel with the
// authorization to be run when it completes.
func (a *Authorizer) Begin(action string, wallet model.WalletID, det, params any) (*Authorization, error) {
	if det == nil {
		det = map[string]any{}
	}
	d, err := a.codec.Marshal(det)
	if err != nil {
		return nil, fmt.Errorf("authz: %w", err)
	}
	now := a.Now()
	au := &Authorization{Action: action, Wallet: wallet, Params: params, Expires: now.Add(a.TTL)}
	chl := make([]byte, challengeSize)
	rand.Read(chl)
	rand.Read(au.ID[:])
	au.Message, err = a.codec.Marshal(Message{
		Ctx: Context, Net: string(a.Network), Act: action, Wal: string(wallet),
		Det: d, Chl: chl, Exp: au.Expires.Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("authz: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for id, p := range a.pending {
		if !now.Before(p.Expires) {
			delete(a.pending, id)
		}
	}
	if len(a.pending) >= a.MaxPending {
		return nil, ErrTooMany
	}
	a.pending[au.ID] = au
	return au, nil
}

// Complete checks the password against an open challenge, through Attempt.
// On success the challenge is used up and returned, to be run once; a wrong
// password leaves it open until it expires. An id that is not open, because
// it expired, was used, or the wallet restarted since, gives ErrExpired: to
// the person they are all the same.
func (a *Authorizer) Complete(id [IDSize]byte, check func() error) (*Authorization, error) {
	if !a.open(id) {
		return nil, ErrExpired
	}
	if err := a.Attempt(check); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	au, ok := a.pending[id]
	if !ok || !a.Now().Before(au.Expires) {
		delete(a.pending, id)
		return nil, ErrExpired // used by another connection meanwhile, or expired during the check
	}
	delete(a.pending, id)
	return au, nil
}

func (a *Authorizer) open(id [IDSize]byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	au, ok := a.pending[id]
	if ok && !a.Now().Before(au.Expires) {
		delete(a.pending, id)
		return false
	}
	return ok
}

// Attempt runs a password check unless the wait after the last wrong password
// is not over, in which case it returns *WaitError without running it. check
// returns ErrWrongPassword for a wrong password, which doubles the wait; any
// other error passes through and does not count.
func (a *Authorizer) Attempt(check func() error) error {
	a.mu.Lock()
	if now := a.Now(); now.Before(a.notBefore) {
		wait := a.notBefore.Sub(now)
		a.mu.Unlock()
		return &WaitError{Wait: wait}
	}
	a.mu.Unlock()

	err := check()

	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case err == nil:
		a.failures = 0
		a.notBefore = time.Time{}
	case errors.Is(err, ErrWrongPassword):
		a.failures++
		wait := a.MaxWait
		if a.failures <= 32 {
			if w := a.FirstWait << (a.failures - 1); w > 0 && w < a.MaxWait {
				wait = w
			}
		}
		a.notBefore = a.Now().Add(wait)
	}
	return err
}
