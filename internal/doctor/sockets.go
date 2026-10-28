// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package doctor

import (
	"context"
	"errors"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/mcpclient"
)

// askTimeout bounds what doctor waits for each service.
const askTimeout = 15 * time.Second

// AskWallet asks the wallet, on its admin socket, its version, its status,
// whether its hash chains hold and how its isolation check went at its last
// start. None of that needs an authorization.
func AskWallet(ctx context.Context, socket, version, network string) (Wallet, error) {
	ctx, cancel := context.WithTimeout(ctx, askTimeout)
	defer cancel()
	c, err := ipc.Dial(ctx, socket, ipc.Hello{Software: "mcpcardano doctor " + version, Network: network})
	if err != nil {
		return Wallet{}, err
	}
	defer c.Close()
	w := Wallet{Software: c.Peer.Software}
	if err := c.Call(ctx, ipc.MsgStatus, &ipc.Empty{}, &w.Status); err != nil {
		return w, err
	}
	var e *ipc.Error
	if err := c.Call(ctx, ipc.MsgVerifyAudit, &ipc.Empty{}, &w.Audit); errors.As(err, &e) {
		w.AuditErr = err
		return w, nil
	} else if err != nil {
		return w, err
	}
	w.Isolation, err = lastIsolation(ctx, c, w.Audit.AuditEntries)
	return w, err
}

// maxAuditScan bounds how far back doctor looks for the wallet's last start.
const maxAuditScan = 10 * ipc.MaxAuditPage

var auditCodec = func() *cborx.Codec {
	c, err := cborx.New(cborx.RecordLimits())
	if err != nil {
		panic(err) // constant limits
	}
	return c
}()

// lastIsolation asks the wallet for the pages of its audit log that
// scanIsolation reads.
func lastIsolation(ctx context.Context, c *ipc.Client, entries uint64) (string, error) {
	return scanIsolation(entries, func(from, limit uint64) ([]string, error) {
		var p ipc.AuditPage
		if err := c.Call(ctx, ipc.MsgShowAudit, &ipc.ShowAudit{From: from, Limit: uint32(limit)}, &p); err != nil {
			return nil, err
		}
		types := make([]string, len(p.Entries))
		for i, raw := range p.Entries {
			var e audit.Entry
			if err := auditCodec.Unmarshal(raw, &e); err != nil {
				return nil, err
			}
			types[i] = e.Type
		}
		return types, nil
	})
}

// scanIsolation reads an audit log of entries backwards, a page at a time,
// to the wallet's last start, and returns the type of the entry that follows
// it: how the isolation check went (decision 139). It is "" if the last
// start is further back than maxAuditScan entries. page returns the types of
// limit entries from the one numbered from.
func scanIsolation(entries uint64, page func(from, limit uint64) ([]string, error)) (string, error) {
	following := ""
	for end := entries; end > 0 && entries-end < maxAuditScan; {
		from := uint64(1)
		if end > ipc.MaxAuditPage {
			from = end - ipc.MaxAuditPage + 1
		}
		types, err := page(from, end-from+1)
		if err != nil {
			return "", err
		}
		for i := len(types) - 1; i >= 0; i-- {
			if types[i] == "start" {
				return following, nil
			}
			following = types[i]
		}
		end = from - 1
	}
	return "", nil
}

// AskServer asks the server, on its MCP socket, its version and the state
// of the network, as an agent would.
func AskServer(ctx context.Context, socket, version string) (Server, error) {
	ctx, cancel := context.WithTimeout(ctx, askTimeout)
	defer cancel()
	c, err := mcpclient.Dial(ctx, socket, "doctor "+version)
	if err != nil {
		return Server{}, err
	}
	defer c.Close()
	s := Server{Version: c.ServerVersion}
	return s, c.Call(ctx, "get_network_status", map[string]any{}, &s.Status)
}
