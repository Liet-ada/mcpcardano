// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/mcpclient"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The wallet has no network, so what is on the chain comes from the server,
// over its MCP socket, as it would to an agent (decision 142). The view only
// reads, through the tools of readTools, and what it reads is text from
// outside. It costs the server's data sources: list_wallets and list_drafts
// do not touch them, but get_wallet_overview asks for every UTxO of a wallet
// and get_network_status asks each source for its tip, so the view asks those
// for what is on show, and not often.

// readTools are the only tools the view calls. None builds, authorizes or
// sends anything.
var readTools = map[string]bool{
	"list_wallets":        true,
	"get_wallet_overview": true,
	"list_drafts":         true,
	"get_network_status":  true,
}

const (
	serverEvery   = 30 * time.Second       // how often the view asks what costs no quota
	serverWait    = 20 * time.Second       // how long it waits for an answer
	overviewAge   = time.Minute            // how long a wallet's balance is good
	overviewDelay = 400 * time.Millisecond // how long a wallet stays chosen before asking
)

// Server is what the view reads from the server.
type Server interface {
	Wallets(ctx context.Context) ([]ServerWallet, error)
	Overview(ctx context.Context, walletID string) (*Overview, error)
	Drafts(ctx context.Context) ([]Draft, error)
	Network(ctx context.Context) (*ChainStatus, error)
}

// ServerWallet is a wallet as list_wallets gives it.
type ServerWallet struct {
	ID   string `json:"wallet_id"`
	Mode string `json:"mode"`
}

// Overview is a wallet as get_wallet_overview gives it.
type Overview struct {
	WalletID string `json:"wallet_id"`
	Address  string `json:"address"`
	Balance  struct {
		Lovelace    string `json:"lovelace"`
		AssetsCount int    `json:"assets_count"`
	} `json:"balance"`
	UTxOs    int `json:"utxos"`
	Reserved struct {
		UTxOs    int    `json:"utxos"`
		Lovelace string `json:"lovelace"`
	} `json:"reserved"`
	LiveDrafts int `json:"live_drafts"`
	UTxOHealth struct {
		Dust       int    `json:"dust"`
		Suggestion string `json:"suggestion"`
	} `json:"utxo_health"`
}

// Draft is a live draft as list_drafts gives it.
type Draft struct {
	ID        string `json:"draft_id"`
	WalletID  string `json:"wallet_id"`
	State     string `json:"state"`
	Kind      string `json:"kind"`
	Fee       string `json:"fee"`
	NetEffect string `json:"net_effect_lovelace"`
	ExpiresAt string `json:"expires_at"`
}

// ChainStatus is the network as get_network_status gives it.
type ChainStatus struct {
	Network     string         `json:"network"`
	DataSource  SourceStatus   `json:"datasource"`
	DataSources []SourceStatus `json:"datasources"`
	Tip         *struct {
		Slot   string `json:"slot"`
		Height string `json:"height"`
		Epoch  string `json:"epoch"`
		Time   string `json:"time"`
	} `json:"tip"`
}

// SourceStatus is a data source and whether it answers.
type SourceStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// ServerConn is the server's MCP socket as the view uses it: one session,
// opened at the first call and again after a call breaks it.
type ServerConn struct {
	Socket  string
	Version string

	mu     sync.Mutex
	client *mcpclient.Client
}

// call is the only way to the server: a tool out of readTools does not leave
// the view.
func (c *ServerConn) call(ctx context.Context, tool string, args, out any) error {
	if !readTools[tool] {
		return fmt.Errorf("the view does not call %s", tool)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client == nil {
		cl, err := mcpclient.Dial(ctx, c.Socket, c.Version)
		if err != nil {
			return err
		}
		c.client = cl
	}
	err := c.client.Call(ctx, tool, args, out)
	var e *mcpclient.ToolError
	if err != nil && !errors.As(err, &e) {
		c.client.Close()
		c.client = nil
	}
	return err
}

// Close ends the session.
func (c *ServerConn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
}

func (c *ServerConn) Wallets(ctx context.Context) ([]ServerWallet, error) {
	var out struct {
		Wallets []ServerWallet `json:"wallets"`
	}
	err := c.call(ctx, "list_wallets", map[string]any{}, &out)
	return out.Wallets, err
}

func (c *ServerConn) Overview(ctx context.Context, walletID string) (*Overview, error) {
	var out Overview
	if err := c.call(ctx, "get_wallet_overview", map[string]any{"wallet_id": walletID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *ServerConn) Drafts(ctx context.Context) ([]Draft, error) {
	var out struct {
		Drafts []Draft `json:"drafts"`
	}
	err := c.call(ctx, "list_drafts", map[string]any{}, &out)
	return out.Drafts, err
}

func (c *ServerConn) Network(ctx context.Context) (*ChainStatus, error) {
	var out ChainStatus
	if err := c.call(ctx, "get_network_status", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// overviewEntry is a wallet's balance, with when it came. A failure counts as
// an answer: a source that refuses is not asked again at once.
type overviewEntry struct {
	overview *Overview
	at       time.Time // when it last answered
	good     time.Time // when the overview came
	failure  string
	busy     bool
}

// link is what the view knows from the server.
type link struct {
	answered  bool // the server answered, or failed to, at least once
	up        bool
	modeA     int // wallets only the server knows
	drafts    []Draft
	overviews map[string]*overviewEntry
	chain     *ChainStatus
	chainAt   time.Time
	chainErr  string
	chainBusy bool
}

// The messages of the server.
type (
	serverTick struct{}
	serverMsg  struct {
		wallets []ServerWallet
		drafts  []Draft
		err     error
	}
	overviewWanted struct {
		wallet string
		force  bool
	}
	overviewMsg struct {
		wallet   string
		overview *Overview
		err      error
	}
	chainMsg struct {
		status *ChainStatus
		err    error
	}
)

// pollServer asks what costs the data sources nothing. One chain of it runs
// for as long as the view does.
func (m Model) pollServer() tea.Msg {
	ctx, cancel := context.WithTimeout(m.ctx, serverWait)
	defer cancel()
	wallets, err := m.server.Wallets(ctx)
	if err != nil {
		return serverMsg{err: err}
	}
	drafts, err := m.server.Drafts(ctx)
	return serverMsg{wallets: wallets, drafts: drafts, err: err}
}

func (m Model) serverAnswered(msg serverMsg) (Model, tea.Cmd) {
	m.link.answered, m.link.up = true, msg.err == nil
	if msg.err == nil {
		m.link.drafts, m.link.modeA = msg.drafts, 0
		for _, w := range msg.wallets {
			if w.Mode == string(model.ModeA) {
				m.link.modeA++
			}
		}
	}
	next := tea.Tick(serverEvery, func(time.Time) tea.Msg { return serverTick{} })
	return m, tea.Batch(next, m.wantOverview(false))
}

// chosen is the wallet on show in the wallets' tab, if any.
func (m Model) chosen() (ipc.Wallet, bool) {
	if m.tab != tabWallets || m.status == nil || len(m.status.Wallets) == 0 {
		return ipc.Wallet{}, false
	}
	return m.status.Wallets[m.wallets.at].Wallet, true
}

// wantOverview asks for the balance of the wallet on show once it has stayed
// on show for a moment, so that walking down the list asks nothing.
func (m Model) wantOverview(force bool) tea.Cmd {
	w, ok := m.chosen()
	if !ok || m.server == nil {
		return nil
	}
	if force {
		return func() tea.Msg { return overviewWanted{w.ID, true} }
	}
	return tea.Tick(overviewDelay, func(time.Time) tea.Msg { return overviewWanted{w.ID, false} })
}

func (m Model) overviewAsked(msg overviewWanted) (Model, tea.Cmd) {
	w, ok := m.chosen()
	if !ok || w.ID != msg.wallet || m.link.answered && !m.link.up && !msg.force {
		return m, nil
	}
	e := m.link.overviews[w.ID]
	if e == nil {
		e = &overviewEntry{}
		m.link.overviews[w.ID] = e
	}
	if e.busy || !msg.force && !e.at.IsZero() && m.now().Sub(e.at) < overviewAge {
		return m, nil
	}
	e.busy = true
	return m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, serverWait)
		defer cancel()
		o, err := m.server.Overview(ctx, w.ID)
		return overviewMsg{w.ID, o, err}
	}
}

func (m Model) overviewCame(msg overviewMsg) (Model, tea.Cmd) {
	e := m.link.overviews[msg.wallet]
	if e == nil {
		return m, nil
	}
	e.busy, e.at, e.failure = false, m.now(), ""
	if msg.err != nil {
		var te *mcpclient.ToolError
		e.failure = "the server did not answer"
		if errors.As(msg.err, &te) {
			e.failure = te.Code
		}
		return m, nil
	}
	e.overview, e.good = msg.overview, e.at
	return m, nil
}

// wantChain asks how the network is. force is the person asking.
func (m Model) wantChain(force bool) (Model, tea.Cmd) {
	if m.server == nil || m.link.chainBusy || !force && !m.link.chainAt.IsZero() && m.now().Sub(m.link.chainAt) < overviewAge {
		return m, nil
	}
	m.link.chainBusy = true
	return m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, serverWait)
		defer cancel()
		s, err := m.server.Network(ctx)
		return chainMsg{s, err}
	}
}

func (m Model) chainCame(msg chainMsg) (Model, tea.Cmd) {
	m.link.chainBusy, m.link.chainAt, m.link.chainErr = false, m.now(), ""
	if msg.err != nil {
		m.link.chainErr = "the server did not answer"
		var te *mcpclient.ToolError
		if errors.As(msg.err, &te) {
			m.link.chainErr = te.Code
		}
		return m, nil
	}
	m.link.chain = msg.status
	return m, nil
}

// balance is the line of a wallet's balance. The server is outside the
// wallet: a balance of another address is not shown as this wallet's.
func (m Model) balance(wl ipc.Wallet) string {
	name := paint(sDim, fmt.Sprintf("%-9s", "BALANCE"))
	if m.server == nil || !m.link.up && m.link.answered {
		return name + paint(sDim, "the server does not answer")
	}
	e := m.link.overviews[wl.ID]
	if e == nil || e.overview == nil && e.failure == "" {
		return name + paint(sDim, "asking the server…")
	}
	if e.overview == nil {
		return name + paint(sOrange, "unavailable: "+e.failure)
	}
	o := e.overview
	if o.WalletID != wl.ID || o.Address != (model.Address{Raw: wl.Address}).Bech32() {
		return name + paint(sRed, "! the server names another address for this wallet")
	}
	lovelace, err := model.ParseAmount(o.Balance.Lovelace)
	if err != nil {
		return name + paint(sRed, "! the server gave no amount")
	}
	// What warns goes first: a narrow screen cuts the end of the line.
	line := name + paint(sBold, ada(lovelace))
	if e.failure != "" {
		line += paint(sOrange, "  as of "+e.good.Format(time.TimeOnly)+", "+e.failure)
	}
	if o.UTxOHealth.Suggestion == "consolidate" {
		line += paint(sOrange, "  ▲ consolidate")
	}
	line += paint(sDim, fmt.Sprintf("  %d UTxO  %d %s", o.UTxOs, o.LiveDrafts, plural(o.LiveDrafts, "draft", "drafts")))
	if n := o.Balance.AssetsCount; n > 0 {
		line += paint(sDim, fmt.Sprintf("  %d %s", n, plural(n, "token", "tokens")))
	}
	return line
}

// draftsView lists the live drafts: they are the agent's, and the view only
// shows them.
func (m Model) draftsView() []string {
	if len(m.link.drafts) == 0 {
		return nil
	}
	out := []string{"", sp(2) + section("DRAFTS OF THE AGENT"), "",
		sp(4) + paint(sDim, fmt.Sprintf("%-14s %-16s %-18s %-14s %12s %14s  %s", "DRAFT", "WALLET", "STATE", "KIND", "FEE", "NET", "EXPIRES"))}
	for _, d := range m.link.drafts {
		out = append(out, sp(4)+paint(sBase, fmt.Sprintf("%-14s %-16s %-18s %-14s %12s %14s  %s", truncate(d.ID, 14), truncate(m.walletName(d.WalletID), 16),
			truncate(d.State, 18), truncate(d.Kind, 14), lovelaceText(d.Fee), lovelaceText(d.NetEffect), truncate(d.ExpiresAt, 19))))
	}
	return out
}

// lovelaceText writes an amount the server gave, or what it was if it is not
// one.
func lovelaceText(s string) string {
	if n, err := model.ParseAmount(s); err == nil {
		return adaShort(n)
	}
	return truncate(s, 14)
}

// serverView is the section of the system tab.
func (m Model) serverView() []string {
	kv := func(k, v string) string { return sp(4) + paint(sDim, fmt.Sprintf("%-12s", k)) + v }
	out := []string{"", sp(2) + section("SERVER") + sp(2) + keyHint("n", "ask for the network")}
	switch {
	case m.server == nil || m.link.answered && !m.link.up:
		return append(out, kv("STATE", paint(sOrange, "● DOES NOT ANSWER")+paint(sDim, ": no balances or drafts")))
	case !m.link.answered:
		return append(out, kv("STATE", paint(sDim, "asking…")))
	}
	out = append(out, kv("STATE", paint(sGreen, "● ANSWERS")))
	if m.link.chainErr != "" {
		out = append(out, kv("NETWORK", paint(sOrange, "unavailable: "+m.link.chainErr)))
	}
	if c := m.link.chain; c != nil {
		if c.Tip != nil {
			out = append(out, kv("TIP", paint(sBase, "slot "+c.Tip.Slot+", height "+c.Tip.Height+", epoch "+c.Tip.Epoch)+paint(sDim, "  "+truncate(c.Tip.Time, 25))))
		}
		sources := ""
		for _, s := range c.DataSources {
			st := sGreen
			if s.Status != "ok" {
				st = sOrange
			}
			sources += paint(st, s.Name+" "+s.Status) + sp(2)
		}
		out = append(out, kv("SOURCES", sources), kv("IN USE", paint(sBase, c.DataSource.Name)))
	}
	return out
}
