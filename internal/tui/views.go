// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

func ansiCut(s string, w int) string { return ansi.Truncate(s, w, "…") }

// label is a wallet's label for the lists, upper case as the frame.
func label(w ipc.Wallet) string { return strings.ToUpper(w.Label) }

// walletName finds a wallet's label by its id, for the approvals.
func (m Model) walletName(id string) string {
	for _, w := range m.status.Wallets {
		if w.Wallet.ID == id {
			return label(w.Wallet)
		}
	}
	return id
}

func modeBadge(mode string) string { return badge(mode, modeColor(mode)) }

func (m Model) overview(w int) []string {
	st := m.status
	var spent uint64
	sessions, frozen := 0, 0
	for _, ws := range st.Wallets {
		if ps := m.policies[ws.Wallet.ID]; ps != nil {
			spent += ps.SpentDay
		}
		if ws.Session != nil {
			sessions++
		}
		if ws.Wallet.Frozen {
			frozen++
		}
	}
	state := paint(sGreen, "● UNLOCKED")
	if !st.Unlocked {
		state = paint(sOrange, "● LOCKED")
	}
	kv := func(k, v string) string { return sp(4) + paint(sDim, fmt.Sprintf("%-12s", k)) + v }
	out := []string{"", sp(2) + section("WALLET"),
		kv("STATE", state),
		kv("KEYS", paint(sBold, fmt.Sprint(len(st.Keys)))+paint(sDim, " registered")),
		kv("SPENT TODAY", paint(sBold, adaShort(spent))+paint(sDim, " ADA, every wallet")),
		kv("APPROVALS", countText(len(st.Approvals), "waiting", "waiting", sOrange)),
		kv("SESSIONS", countText(sessions, "open", "open", sOrange)),
		kv("FROZEN", countText(frozen, "wallet", "wallets", sCyan)),
		"", sp(2) + section("WALLETS")}
	if len(st.Wallets) == 0 {
		out = append(out, sp(4)+paint(sDim, "None yet: mcpcardano wallet create, or create_wallet from the agent."))
	}
	for _, ws := range st.Wallets {
		row := sp(4) + paint(sBold, fmt.Sprintf("%-16s", truncate(label(ws.Wallet), 15))) + modeBadge(ws.Wallet.Mode) + sp(2)
		if ws.Wallet.Frozen {
			row += paint(sCyan, "❄ FROZEN  ")
		}
		if ws.OpenDestinations {
			row += paint(sOrange, "▲ OPEN DESTINATIONS  ")
		}
		if s := ws.Session; s != nil {
			row += paint(sOrange, "▲ SESSION ") + paint(sDim, adaShort(s.Remaining)+" ADA left, ends "+clock(s.ExpiresAt))
		}
		out = append(out, row)
	}
	if notes := m.notices(); len(notes) > 0 {
		out = append(out, "", sp(2)+section("NOTICES"))
		out = append(out, notes...)
	}
	return out
}

func countText(n int, one, many string, st lipgloss.Style) string {
	if n == 0 {
		return paint(sDim, "none")
	}
	return paint(st, fmt.Sprint(n)) + paint(sDim, " "+plural(n, one, many))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// notices are what the person should know before acting.
func (m Model) notices() []string {
	st := m.status
	var out []string
	note := func(st lipgloss.Style, mark, text string) {
		out = append(out, sp(4)+paint(st, mark+" ")+paint(sBase, text))
	}
	if st.Recovery != nil {
		note(sRed, "!", "A recovery without keys is waiting: at "+clock(st.Recovery.EndsAt)+
			" the keys are removed. If you did not start it: mcpcardano recover cancel")
	}
	if !st.Unlocked {
		note(sOrange, "!", "The wallet is locked: unlock it with mcpcardano unlock.")
	}
	if len(st.Keys) == 0 {
		note(sOrange, "!", "No security key is registered: for relevant funds, mcpcardano key add.")
	}
	if n := len(st.Approvals); n > 0 {
		note(sOrange, "!", fmt.Sprintf("%d %s waiting: tab 3.", n, plural(n, "approval is", "approvals are")))
	}
	return out
}

// listWidth is the width of the list on the left of the wallets.
const listWidth = 30

func (m Model) walletsView(w, height int) []string {
	st := m.status
	left := []string{section("WALLETS"), ""}
	from, to := m.wallets.window(len(st.Wallets), height-5)
	for i := from; i < to; i++ {
		ws := st.Wallets[i].Wallet
		name := fmt.Sprintf(" %s %-14s", map[bool]string{true: "▸", false: " "}[i == m.wallets.at], truncate(label(ws), 14))
		row := paint(sBase, name)
		if i == m.wallets.at {
			row = paint(sSelected, name)
		}
		row += sp(1) + modeBadge(ws.Mode)
		if ws.Frozen {
			row += paint(sCyan, " ❄")
		}
		left = append(left, row)
	}
	if len(st.Wallets) == 0 {
		left = append(left, paint(sDim, " none yet"))
	}
	left = append(left, "", paint(sDim, fmt.Sprintf(" %d %s", len(st.Wallets), plural(len(st.Wallets), "wallet", "wallets"))),
		sp(1)+keyHint("c", "create")+sp(2)+keyHint("R", "restore"))

	var right []string
	if len(st.Wallets) > 0 {
		right = m.walletDetail(st.Wallets[m.wallets.at], w-listWidth-5)
	}
	out := []string{""}
	for i := 0; i < max(len(left), len(right)); i++ {
		l, r := "", ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		out = append(out, sp(1)+fit(l, listWidth)+m.frame().Render("│")+sp(2)+r)
	}
	return out
}

// walletDetail is one wallet: what it is, its limits with what it spent,
// its session and its destinations.
func (m Model) walletDetail(ws ipc.WalletStatus, w int) []string {
	wl := ws.Wallet
	frozen := paint(sGreen, "NOT FROZEN")
	if wl.Frozen {
		frozen = paint(sCyan, "❄ FROZEN")
	}
	out := []string{
		paint(sYellow, label(wl)) + sp(2) + paint(sDim, wl.ID),
		paint(sDim, "MODE ") + modeBadge(wl.Mode) + paint(sDim, "  CREATED BY ") + paint(sBold, strings.ToUpper(wl.CreatedBy)) + paint(sDim, "  ·  ") + frozen,
		paint(sCyan, truncate(model.Address{Raw: wl.Address}.Bech32(), max(w, 10))),
		walletKeys(ws),
	}
	ps := m.policies[wl.ID]
	if ps == nil {
		return append(out, paint(sDim, "The wallet did not give its limits."))
	}
	l := ps.Policy.Limits
	const cells = 16
	row := func(name string, limit uint64, bar string, used string) string {
		return paint(sDim, fmt.Sprintf("%-14s", name)) + paint(sBase, fmt.Sprintf("%12s", adaShort(limit))) + sp(2) + bar + used
	}
	used := func(spent, limit uint64) string {
		st := sDim
		switch {
		case limit > 0 && spent*10 >= limit*9:
			st = sRed
		case limit > 0 && spent*10 >= limit*7:
			st = sOrange
		}
		return paint(st, fmt.Sprintf("  %12s", adaShort(spent)))
	}
	out = append(out, paint(sHUD, "── ")+paint(sYellow, "LIMITS")+paint(sDim, " ADA")+paint(sHUD, " "+strings.Repeat("─", max(w-15, 0))),
		row("PER TX", l.PerTx, "", ""),
		row("PER HOUR", l.PerHour, gauge(ps.SpentHour, l.PerHour, cells), used(ps.SpentHour, l.PerHour)),
		row("PER DAY", l.PerDay, gauge(ps.SpentDay, l.PerDay, cells), used(ps.SpentDay, l.PerDay)))
	if ps.Mode == "C" {
		spent := l.Budget - min(ps.BudgetRemaining, l.Budget)
		out = append(out, row("BUDGET", l.Budget, gauge(spent, l.Budget, cells), used(spent, l.Budget)))
	}
	if ps.Mode == "B" {
		out = append(out, row("APPROVE ABOVE", l.ApprovalThreshold, "", ""))
	}
	count := func(name string, n, limit uint32) string {
		return paint(sDim, fmt.Sprintf("%-14s", name)) + paint(sBase, fmt.Sprintf("%12d", limit)) + sp(2) +
			gauge(uint64(n), uint64(limit), cells) + paint(sDim, fmt.Sprintf("  %12d", n))
	}
	out = append(out,
		count("TX / HOUR", ps.TxHour, l.TxPerHour),
		count("NEW DEST / H", ps.NewDestinationsHour, l.NewDestinationsPerHour),
		count("NEW DEST / DAY", ps.NewDestinationsDay, l.NewDestinationsPerDay),
		paint(sDim, fmt.Sprintf("%-14s", "MAX FEE"))+paint(sBase, fmt.Sprintf("%12s", adaShort(l.MaxFee))),
		"")
	session := paint(sDim, "none")
	if s := ws.Session; s != nil {
		session = paint(sOrange, "▲ OPEN ") + paint(sDim, adaShort(s.Remaining)+" ADA left, ends "+clock(s.ExpiresAt))
	} else if ps.Policy.SessionRequired {
		session = paint(sDim, "none, and the wallet requires one to spend")
	}
	dest := paint(sBase, fmt.Sprintf("%d listed", len(ps.Policy.Destinations.Allowed)))
	if ps.Policy.Destinations.Any {
		dest = paint(sOrange, "▲ ANY ADDRESS")
	}
	out = append(out,
		paint(sDim, fmt.Sprintf("%-14s", "SESSION"))+session,
		paint(sDim, fmt.Sprintf("%-14s", "DESTINATIONS"))+dest,
		paint(sDim, fmt.Sprintf("%-14s", "TOKENS"))+paint(sBase, tokenCaps(ps.Policy.Assets)),
		paint(sDim, fmt.Sprintf("%-14s", "NETWORKS"))+paint(sBase, strings.Join(ps.Policy.Networks, ", ")))
	if len(ps.Pending) > 0 {
		out = append(out, paint(sDim, fmt.Sprintf("%-14s", "IN FLIGHT"))+paint(sOrange, fmt.Sprintf("%d signed transactions may still reach the chain", len(ps.Pending))))
	}
	return out
}

// walletKeys are the keys of a wallet, those that apply to it as it is.
func walletKeys(ws ipc.WalletStatus) string {
	freeze, session := keyHint("F", "freeze"), keyHint("s", "open session")
	if ws.Wallet.Frozen {
		freeze = keyHint("u", "unfreeze")
	}
	if ws.Session != nil {
		session = keyHint("s", "close session")
	}
	return strings.Join([]string{freeze, session, keyHint("b", "budget"), keyHint("p", "phrase")}, sp(2))
}

func tokenCaps(caps []ipc.AssetCap) string {
	if len(caps) == 0 {
		return "none may leave"
	}
	return fmt.Sprintf("%d kinds may leave", len(caps))
}

func (m Model) approvalsView(w, height int) []string {
	st := m.status
	out := []string{"", sp(2) + section("APPROVALS"), ""}
	if len(st.Approvals) == 0 {
		return append(out, sp(4)+paint(sDim, "No approval is waiting."))
	}
	out = append(out, sp(4)+paint(sDim, fmt.Sprintf("%-30s %-16s %18s  %s", "APPROVAL", "WALLET", "SPENDS", "UNTIL")))
	from, to := m.approvals.window(len(st.Approvals), height-5)
	for i := from; i < to; i++ {
		ap := st.Approvals[i]
		text := fmt.Sprintf("%-30s %-16s %18s  %s", ap.ID, truncate(m.walletName(ap.WalletID), 16), ada(ap.Spend.Lovelace), clock(ap.ExpiresAt))
		if len(ap.Spend.Assets) > 0 {
			text += fmt.Sprintf("  + %d kinds of tokens", len(ap.Spend.Assets))
		}
		if i == m.approvals.at {
			out = append(out, sp(2)+paint(sSelected, "▸ "+text+" "))
		} else {
			out = append(out, sp(4)+paint(sBase, text))
		}
	}
	return out
}

func (m Model) keysView(w, height int) []string {
	st := m.status
	out := []string{"", sp(2) + section("SECURITY KEYS"), ""}
	if len(st.Keys) == 0 {
		return append(out, sp(4)+paint(sOrange, "! ")+paint(sBase, "No security key is registered: for relevant funds, mcpcardano key add."))
	}
	out = append(out, sp(4)+paint(sDim, fmt.Sprintf("%-32s %-6s  %s", "NAME", "ALG", "ADDED")))
	from, to := m.keyList.window(len(st.Keys), height-6)
	for i := from; i < to; i++ {
		k := st.Keys[i]
		alg := map[int]string{-7: "ES256", -8: "EdDSA"}[k.Alg]
		text := fmt.Sprintf("%-32s %-6s  %s", truncate(k.Name, 32), alg, time.Unix(k.Added, 0).Format(time.DateOnly))
		if i == m.keyList.at {
			out = append(out, sp(2)+paint(sSelected, "▸ "+text+" "))
		} else {
			out = append(out, sp(4)+paint(sBase, text))
		}
	}
	return append(out, "", sp(4)+paint(sDim, "With keys, the password only unlocks and starts a recovery."))
}
