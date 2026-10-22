// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package mcp

import (
	"context"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

func (s *Server) registerWallets() error {
	return addTool(s, tool{name: "create_wallet",
		description: "Creates a wallet for the agent in the wallet process, with the template the person set: its mode, limits and budget. The keys stay in the wallet process; the agent never sees them nor the recovery phrase. The new wallet starts empty, and the person funds it. Asking again with the same idempotency_key gives back the same wallet. Amounts are lovelace as decimal strings."},
		s.createWallet)
}

type createWalletArg struct {
	Label          string `json:"label" jsonschema:"A name for the wallet: 1 to 64 bytes of visible text."`
	IdempotencyKey string `json:"idempotency_key,omitempty" jsonschema:"Up to 64 bytes of visible text; asking again with the same key gives back the same wallet."`
}

type createdWallet struct {
	Network   string `json:"network"`
	WalletID  string `json:"wallet_id"`
	Label     string `json:"label"`
	Mode      string `json:"mode"`
	Address   string `json:"address"`
	CreatedBy string `json:"created_by"`
	// The template it got: what the agent may do with it.
	Limits           limitsView `json:"limits"`
	OpenDestinations bool       `json:"open_destinations"`
	SessionRequired  bool       `json:"session_required"`
}

func (s *Server) createWallet(ctx context.Context, a createWalletArg) (createdWallet, error) {
	// ipc.Detail keeps exactly the visible text the wallet accepts.
	if n := len(a.Label); n == 0 || n > ipc.MaxLabel || ipc.Detail(a.Label) != a.Label {
		return createdWallet{}, invalid("label must be 1 to %d bytes of visible text", ipc.MaxLabel)
	}
	key := a.IdempotencyKey
	if n := len(key); n > ipc.MaxLabel || ipc.Detail(key) != key {
		return createdWallet{}, invalid("idempotency_key must be up to %d bytes of visible text", ipc.MaxLabel)
	}
	if key == "" {
		key = newIdempotencyKey()
	}
	var res ipc.WalletCreated
	if err := s.d.Wallet.Call(ctx, ipc.MsgCreateWallet, &ipc.CreateWallet{Label: a.Label, IdempotencyKey: key}, &res); err != nil {
		return createdWallet{}, err
	}
	addr, err := chain.AddressFromBytes(res.Wallet.Address)
	if err != nil {
		return createdWallet{}, err
	}
	if err := s.refresh(ctx); err != nil {
		s.d.Logger.Warn("wallet process", "err", err)
	}
	text, err := chain.FormatAddress(addr)
	if err != nil {
		return createdWallet{}, err
	}
	p, f := res.Policy.Model(), model.FormatAmount
	return createdWallet{
		Network: string(s.d.Network), WalletID: res.Wallet.ID, Label: res.Wallet.Label, Mode: res.Wallet.Mode,
		Address: text, CreatedBy: res.Wallet.CreatedBy,
		Limits: limitsView{
			PerTx: f(p.Limits.PerTx), PerHour: f(p.Limits.PerHour), PerDay: f(p.Limits.PerDay),
			Budget: f(p.Limits.Budget), ApprovalThreshold: f(p.Limits.ApprovalThreshold), MaxFee: f(p.Limits.MaxFee),
			TxPerHour: p.Limits.TxPerHour, NewDestinationsPerHour: p.Limits.NewDestinationsPerHour,
			NewDestinationsPerDay: p.Limits.NewDestinationsPerDay, MaxLiveDrafts: p.Limits.MaxLiveDrafts,
			MaxTTLSeconds: p.Limits.MaxTTLSeconds,
		},
		OpenDestinations: p.Destinations.Any, SessionRequired: p.SessionRequired,
	}, nil
}
