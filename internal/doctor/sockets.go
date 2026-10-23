// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package doctor

import (
	"context"
	"errors"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/mcpclient"
)

// askTimeout bounds what doctor waits for each service.
const askTimeout = 15 * time.Second

// AskWallet asks the wallet, on its admin socket, its version, its status
// and whether its hash chains hold. None of that needs an authorization.
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
	} else if err != nil {
		return w, err
	}
	return w, nil
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
