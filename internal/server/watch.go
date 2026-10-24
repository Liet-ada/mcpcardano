// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package server

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/datasource"
	"github.com/Liet-ada/mcpcardano/internal/drafts"
	"github.com/Liet-ada/mcpcardano/internal/mcp"
)

const (
	// DefaultConfirmationDepth is how many blocks make a transaction
	// confirmed when the configuration does not say.
	DefaultConfirmationDepth = 3
	// watchEvery is how often the server asks the chain about the
	// transactions it sent.
	watchEvery = 20 * time.Second
	// ttlGrace is how long after the TTL the server waits before it calls a
	// transaction expired: the data source may lag behind the chain.
	ttlGrace = 2 * time.Minute
	// stableDepth is the security parameter k of mainnet and preprod;
	// preview's is smaller. A block that deep can no longer roll back, so a
	// draft confirmed that deep is not asked about again.
	stableDepth = 2160
)

// watcher follows the transactions the server sent until they are deep
// enough, roll back or expire (section 3.4), and a confirmed one until it is
// stableDepth deep. Only the chain moves a draft
// past submitted. It also follows what the wallet process holds: the
// approvals the person gives, and the transactions it signed before the
// server's last start (section 9.5).
type watcher struct {
	store *drafts.Store
	src   *datasource.Relay
	rec   mcp.Recorder
	now   func() time.Time
	depth uint32
	log   *slog.Logger
	srv   *mcp.Server
	// from is the source that answered the last round.
	from string
}

func (w *watcher) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if w.srv != nil {
				w.srv.Sync(ctx)
				w.srv.FollowApprovals(ctx)
				w.srv.FollowOrphans(ctx, w.depth, ttlGrace)
			}
			w.once(ctx)
		}
	}
}

// once asks the chain about every watched draft in one call and applies what
// changed.
func (w *watcher) once(ctx context.Context) {
	watched := slices.DeleteFunc(w.store.Watched(), func(d drafts.Draft) bool {
		return d.State == drafts.StateConfirmed && d.Depth >= stableDepth
	})
	if len(watched) == 0 {
		return
	}
	ids := make([][32]byte, len(watched))
	for i, d := range watched {
		ids[i] = d.Tx.ID
	}
	confirmations, from, err := w.src.ConfirmationsFrom(ctx, ids)
	if err != nil {
		w.log.Warn("watching the chain", "err", err)
		return
	}
	// A source that has just taken over may be a block or two behind the
	// last one: it does not get to roll back a transaction until the next
	// round (decision 136).
	switched := w.from != "" && from != w.from
	w.from = from
	for _, d := range watched {
		n := confirmations[d.Tx.ID]
		gone := w.now().After(d.ExpiresAt.Add(ttlGrace))
		var next drafts.Draft
		var err error
		switch {
		case d.State == drafts.StateSubmitted && n >= uint64(w.depth):
			next, err = w.store.Confirmed(d.ID, uint32(n))
		case d.State == drafts.StateConfirmed && n == 0 && switched:
			continue
		case d.State == drafts.StateConfirmed && n == 0:
			next, err = w.store.RolledBack(d.ID)
		case d.State == drafts.StateConfirmed && n != uint64(d.Depth):
			next, err = w.store.Confirmed(d.ID, uint32(n))
		case d.State == drafts.StateRolledBack && n > 0:
			next, err = w.store.Reentered(d.ID)
		case (d.State == drafts.StateSubmitted || d.State == drafts.StateRolledBack) && n == 0 && gone:
			next, err = w.store.Unconfirmed(d.ID)
		default:
			continue
		}
		if err != nil {
			w.log.Warn("draft state", "draft", d.ID, "err", err)
			continue
		}
		if next.State != d.State {
			w.log.Info("draft state", "draft", d.ID, "from", d.State, "to", next.State, "depth", next.Depth)
			if err := w.rec.Append(ctx, "draft_state", map[string]any{
				"draft_id": string(d.ID), "from": string(d.State), "to": string(next.State), "depth": uint64(next.Depth),
			}); err != nil {
				w.log.Error("audit log", "err", err)
			}
		}
	}
}
