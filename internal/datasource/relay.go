// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package datasource

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// asideFor is how long a source that failed is set aside.
const asideFor = time.Minute

// Relay is a Source made of a list of sources in order of preference
// (decision 136). Each call goes to the first source that is not set aside,
// and passes to the next one when a source is unavailable, gives an invalid
// answer or does not answer that query. A source that is unavailable or
// gives an invalid answer is set aside for a minute: it goes to the end of
// the list, so that its time-outs are paid only when every other source
// fails too. Any other answer, such as ErrNotFound, is the answer.
//
// Submit is the exception: it goes to one source only (decision 78).
//
// Prefer gives a view of the relay with another order, such as the one an
// agent chose for its session (decision 137). The views share which sources
// are set aside: a source that is down is down for every session.
type Relay struct {
	sources []Source // in the order of this view
	all     []Source // as configured
	log     *slog.Logger
	now     func() time.Time
	*health
}

// health is which sources are set aside, shared by a relay and its views.
type health struct {
	mu    sync.Mutex
	aside map[string]time.Time // until when each source is set aside
}

var _ Source = (*Relay)(nil)

// NewRelay returns a relay over sources, in order of preference. They serve
// the same network and have different names. log may be nil.
func NewRelay(sources []Source, log *slog.Logger) (*Relay, error) {
	if len(sources) == 0 {
		return nil, errors.New("datasource: a relay needs a source")
	}
	seen := map[string]bool{}
	for _, s := range sources {
		if s.Network() != sources[0].Network() {
			return nil, fmt.Errorf("datasource: %s serves %s and %s serves %s", sources[0].Name(), sources[0].Network(), s.Name(), s.Network())
		}
		if seen[s.Name()] {
			return nil, fmt.Errorf("datasource: %s twice", s.Name())
		}
		seen[s.Name()] = true
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Relay{sources: sources, all: sources, log: log, now: time.Now, health: &health{aside: map[string]time.Time{}}}, nil
}

// Prefer returns a view of the relay that asks the named sources, in that
// order: one or more of the configured ones, each once. No names gives the
// configured order.
func (r *Relay) Prefer(names []string) (*Relay, error) {
	if len(names) == 0 {
		names = r.Names()
	}
	byName := make(map[string]Source, len(r.all))
	for _, s := range r.all {
		byName[s.Name()] = s
	}
	view := *r
	view.sources = make([]Source, 0, len(names))
	for _, n := range names {
		s, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("datasource: no source %q: there are %s", n, strings.Join(r.Names(), ", "))
		}
		if slices.Contains(view.sources, s) {
			return nil, fmt.Errorf("datasource: %s twice", n)
		}
		view.sources = append(view.sources, s)
	}
	return &view, nil
}

// Names are the names of the configured sources, in the configured order.
func (r *Relay) Names() []string {
	out := make([]string, len(r.all))
	for i, s := range r.all {
		out[i] = s.Name()
	}
	return out
}

// Order are the names of the sources of this view, in its order.
func (r *Relay) Order() []string {
	out := make([]string, len(r.sources))
	for i, s := range r.sources {
		out[i] = s.Name()
	}
	return out
}

// Name implements Source: the names of the sources, in order of preference.
func (r *Relay) Name() string { return strings.Join(r.Order(), ",") }

// Network implements Source.
func (r *Relay) Network() model.Network { return r.sources[0].Network() }

// order is the list the next call goes through: the sources not set aside,
// and then those set aside, each part in order of preference.
func (r *Relay) order() []Source {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	out := make([]Source, 0, len(r.sources))
	var later []Source
	for _, s := range r.sources {
		if until, ok := r.aside[s.Name()]; ok && now.Before(until) {
			later = append(later, s)
			continue
		}
		out = append(out, s)
	}
	return append(out, later...)
}

// passes says whether an error sends the call on to the next source.
func passes(err error) bool {
	return errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInvalidResponse) || errors.Is(err, ErrUnsupported)
}

// note records how a source did: an unavailable source or an invalid answer
// sets it aside, and any other answer brings it back.
func (r *Relay) note(s Source, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInvalidResponse):
		if _, already := r.aside[s.Name()]; !already {
			r.log.Warn("data source set aside", "source", s.Name(), "for", asideFor.String(), "err", err)
		}
		r.aside[s.Name()] = r.now().Add(asideFor)
	case errors.Is(err, ErrUnsupported):
	default:
		if _, was := r.aside[s.Name()]; was {
			r.log.Info("data source answers again", "source", s.Name())
			delete(r.aside, s.Name())
		}
	}
}

// relayed makes a call through the relay and says which source answered.
// When every source fails, the error is that of the most preferred source
// that did not just decline the query.
func relayed[T any](ctx context.Context, r *Relay, call func(Source) (T, error)) (T, string, error) {
	var zero T
	var first, unsupported error
	for _, s := range r.order() {
		v, err := call(s)
		if ctx.Err() != nil {
			// A call cut short says nothing about the source.
			return zero, s.Name(), err
		}
		r.note(s, err)
		if !passes(err) {
			return v, s.Name(), err
		}
		err = fmt.Errorf("%s: %w", s.Name(), err)
		if errors.Is(err, ErrUnsupported) {
			unsupported = cmp.Or(unsupported, err)
		} else {
			first = cmp.Or(first, err)
		}
	}
	return zero, "", cmp.Or(first, unsupported)
}

// CheckNetwork implements Source. It asks every source at once: one that
// serves another network is an error for the whole relay, and one that does
// not answer is set aside.
func (r *Relay) CheckNetwork(ctx context.Context) error {
	errs := make([]error, len(r.sources))
	var wg sync.WaitGroup
	for i, s := range r.sources {
		wg.Go(func() {
			err := s.CheckNetwork(ctx)
			if !errors.Is(err, ErrNetworkMismatch) {
				r.note(s, err)
			}
			if err != nil {
				errs[i] = fmt.Errorf("%s: %w", s.Name(), err)
			}
		})
	}
	wg.Wait()
	for _, err := range errs {
		if errors.Is(err, ErrNetworkMismatch) {
			return err
		}
	}
	return errors.Join(errs...)
}

// Tip implements Source.
func (r *Relay) Tip(ctx context.Context) (Tip, error) {
	v, _, err := relayed(ctx, r, func(s Source) (Tip, error) { return s.Tip(ctx) })
	return v, err
}

// ProtocolParameters implements Source.
func (r *Relay) ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error) {
	v, _, err := relayed(ctx, r, func(s Source) (chain.ProtocolParameters, error) { return s.ProtocolParameters(ctx) })
	return v, err
}

// UTxOs implements Source.
func (r *Relay) UTxOs(ctx context.Context, addr model.Address) ([]chain.UTxO, error) {
	v, _, err := relayed(ctx, r, func(s Source) ([]chain.UTxO, error) { return s.UTxOs(ctx, addr) })
	return v, err
}

// Account implements Source.
func (r *Relay) Account(ctx context.Context, stake string) (Account, error) {
	v, _, err := relayed(ctx, r, func(s Source) (Account, error) { return s.Account(ctx, stake) })
	return v, err
}

// Asset implements Source.
func (r *Relay) Asset(ctx context.Context, id model.AssetID) (Asset, error) {
	v, _, err := relayed(ctx, r, func(s Source) (Asset, error) { return s.Asset(ctx, id) })
	return v, err
}

// AssetByFingerprint implements Source.
func (r *Relay) AssetByFingerprint(ctx context.Context, fingerprint string) (model.AssetID, error) {
	v, _, err := relayed(ctx, r, func(s Source) (model.AssetID, error) { return s.AssetByFingerprint(ctx, fingerprint) })
	return v, err
}

// Transaction implements Source.
func (r *Relay) Transaction(ctx context.Context, id [32]byte) (Transaction, error) {
	v, _, err := relayed(ctx, r, func(s Source) (Transaction, error) { return s.Transaction(ctx, id) })
	return v, err
}

// Confirmations implements Source.
func (r *Relay) Confirmations(ctx context.Context, ids [][32]byte) (map[[32]byte]uint64, error) {
	v, _, err := r.ConfirmationsFrom(ctx, ids)
	return v, err
}

// ConfirmationsFrom is Confirmations, and the name of the source that
// answered: the watcher does not take a transaction for rolled back on the
// word of a source other than the last one (decision 136).
func (r *Relay) ConfirmationsFrom(ctx context.Context, ids [][32]byte) (map[[32]byte]uint64, string, error) {
	return relayed(ctx, r, func(s Source) (map[[32]byte]uint64, error) { return s.Confirmations(ctx, ids) })
}

// Submit implements Source. It sends through the first source of the list
// only, and never passes on to another (decision 78): after an unclear
// answer the caller asks the chain before sending again, and then the
// source that failed is set aside.
func (r *Relay) Submit(ctx context.Context, tx []byte, id [32]byte) error {
	s := r.order()[0]
	err := s.Submit(ctx, tx, id)
	if ctx.Err() == nil {
		r.note(s, err)
	}
	if passes(err) {
		return fmt.Errorf("%s: %w", s.Name(), err)
	}
	return err
}

// Probe is how a source answered a request for its tip.
type Probe struct {
	Name string
	Tip  Tip
	Err  error
}

// ProbeAll asks every source behind src for its tip at once: every
// configured source of a Relay, in the configured order, or src itself. A
// relay takes note of how each one did.
func ProbeAll(ctx context.Context, src Source) []Probe {
	r, ok := src.(*Relay)
	if !ok {
		tip, err := src.Tip(ctx)
		return []Probe{{Name: src.Name(), Tip: tip, Err: err}}
	}
	out := make([]Probe, len(r.all))
	var wg sync.WaitGroup
	for i, s := range r.all {
		wg.Go(func() {
			tip, err := s.Tip(ctx)
			if ctx.Err() == nil {
				r.note(s, err)
			}
			out[i] = Probe{Name: s.Name(), Tip: tip, Err: err}
		})
	}
	wg.Wait()
	return out
}
