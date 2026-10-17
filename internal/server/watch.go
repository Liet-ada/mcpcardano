// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package server

import (
	"context"
	"log/slog"
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
)

// watcher follows the transactions the server sent until they are deep
// enough, roll back or expire (section 3.4). Only the chain moves a draft
// past submitted.
type watcher struct {
	store *drafts.Store
	src   datasource.Source
	rec   mcp.Recorder
	now   func() time.Time
	depth uint32
	log   *slog.Logger
}

func (w *watcher) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.once(ctx)
		}
	}
}

// once asks the chain about every watched draft in one request and applies
// what changed.
func (w *watcher) once(ctx context.Context) {
	watched := w.store.Watched()
	if len(watched) == 0 {
		return
	}
	ids := make([][32]byte, len(watched))
	for i, d := range watched {
		ids[i] = d.Tx.ID
	}
	confirmations, err := w.src.Confirmations(ctx, ids)
	if err != nil {
		w.log.Warn("watching the chain", "err", err)
		return
	}
	for _, d := range watched {
		n := confirmations[d.Tx.ID]
		gone := w.now().After(d.ExpiresAt.Add(ttlGrace))
		var next drafts.Draft
		var err error
		switch {
		case d.State == drafts.StateSubmitted && n >= uint64(w.depth):
			next, err = w.store.Confirmed(d.ID, uint32(n))
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
