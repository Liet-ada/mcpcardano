// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The frame around every tab: the header, the tabs and a rule above the
// body, and a rule and the footer below it.
const (
	chrome   = 5
	minWidth = 60
)

// View draws the view on the terminal's alternate screen.
func (m Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	return v
}

// size is the screen, or a sensible one before the terminal says.
func (m Model) size() (w, h int) {
	w, h = m.width, m.height
	if w == 0 || h == 0 {
		w, h = 100, 30
	}
	return max(w, minWidth), max(h, chrome+4)
}

// frame is the colour of the frame lines: the HUD's red, or the colour of
// danger on mainnet.
func (m Model) frame() lipgloss.Style {
	if m.network == string(model.Mainnet) {
		return sRed
	}
	return sHUD
}

// render draws the whole screen, every line filled with the background.
func (m Model) render() string {
	w, h := m.size()
	body := m.body(w, h-chrome)
	lines := append(m.header(w), body...)
	for len(lines) < h-2 {
		lines = append(lines, "")
	}
	lines = append(lines[:h-2], rule("", w, m.frame()), m.footer(w))
	for i, l := range lines {
		lines[i] = fit(l, w)
	}
	return strings.Join(lines, "\n")
}

func (m Model) header(w int) []string {
	net := paint(sCyan, " "+strings.ToUpper(m.network))
	if m.network == string(model.Mainnet) {
		net = sp(1) + badge("MAINNET", cRed)
	}
	left := sp(1) + badge("MCPCARDANO", cYellow) + sp(1) + m.frame().Render("//") + net
	state := paint(sDim, "CONNECTING")
	if st := m.status; st != nil {
		switch {
		case st.Recovery != nil:
			state = paint(sRed, "! RECOVERY ENDS "+clock(st.Recovery.EndsAt))
		case st.Unlocked:
			state = paint(sGreen, "● UNLOCKED")
		default:
			state = paint(sOrange, "● LOCKED")
		}
		state += paint(sDim, "  │  ") + paint(sBold, fmt.Sprint(len(st.Keys))) + paint(sDim, plural(len(st.Keys), " KEY", " KEYS"))
	}
	right := state + paint(sDim, "  │  ") + paint(sCyan, m.now().Format(time.TimeOnly)) + sp(1)

	var t strings.Builder
	t.WriteString(sp(1))
	for i, name := range tabNames {
		label := fmt.Sprintf("%d %s", i+1, name)
		if tab(i) == m.tab {
			t.WriteString(paint(sSelected, " "+label+" ") + sBase.Foreground(cCyan).Render("◤"))
		} else {
			t.WriteString(paint(sDim, " "+label+" "))
		}
		if tab(i) == tabApprovals && m.status != nil && len(m.status.Approvals) > 0 {
			t.WriteString(badge(fmt.Sprint(len(m.status.Approvals)), cRed))
		}
		t.WriteString(sp(2))
	}
	return []string{spread(left, right, w), t.String(), rule("", w, m.frame())}
}

// footer shows the error that last happened, what last happened, or the
// keys of what is on show.
func (m Model) footer(w int) string {
	switch {
	case m.note != "" && m.failed:
		return sp(1) + badge("ERROR", cRed) + sp(1) + paint(sRed, m.note)
	case m.note != "":
		return sp(1) + paint(sYellow, "▸ ") + paint(sBase, m.note)
	}
	var hints []string
	switch {
	case m.auth != nil:
		switch m.auth.stage {
		case reading:
			hints = []string{keyHint("a", "authorize")}
			if m.auth.approval != "" {
				hints = append(hints, keyHint("r", "reject"))
			}
			hints = append(hints, keyHint("esc", "back"))
		case typing:
			hints = []string{keyHint("enter", "send"), keyHint("esc", "decline")}
		case touching:
			hints = []string{keyHint("ctrl+c", "quit")}
		}
	case m.overlay == helpOverlay:
		hints = []string{keyHint("any key", "close")}
	case m.overlay == paletteOverlay:
		hints = []string{keyHint("↑↓", "choose"), keyHint("enter", "run"), keyHint("esc", "close")}
	default:
		hints = []string{keyHint("1-4", "tabs")}
		switch m.tab {
		case tabWallets:
			hints = append(hints, keyHint("↑↓", "choose"))
			if st := m.status; st != nil && len(st.Wallets) > 0 {
				if st.Wallets[m.wallets.at].Wallet.Frozen {
					hints = append(hints, keyHint("u", "unfreeze"))
				} else {
					hints = append(hints, keyHint("F", "freeze this"))
				}
			}
		case tabKeys:
			hints = append(hints, keyHint("↑↓", "choose"))
		case tabApprovals:
			hints = append(hints, keyHint("↑↓", "choose"), keyHint("enter", "read"), keyHint("r", "reject"))
		}
		hints = append(hints, keyHint(":", "commands"), keyHint("f", "freeze all"), keyHint("?", "help"), keyHint("q", "quit"))
	}
	return sp(1) + strings.Join(hints, sp(3))
}

// body draws what is on show in height lines.
func (m Model) body(w, height int) []string {
	switch {
	case m.auth != nil:
		return m.authView(w)
	case m.overlay == helpOverlay:
		return m.helpView()
	case m.overlay == paletteOverlay:
		return m.paletteView(w, height)
	case m.status == nil:
		return []string{"", sp(2) + paint(sDim, "Asking the wallet…")}
	}
	switch m.tab {
	case tabWallets:
		return m.walletsView(w, height)
	case tabApprovals:
		return m.approvalsView(w, height)
	case tabKeys:
		return m.keysView(w, height)
	}
	return m.overview(w)
}

// authView is the dialog of an authorization: what the wallet says, as it
// says it, the time left, and the password, the PIN or the key.
func (m Model) authView(w int) []string {
	a := m.auth
	dw := min(w-6, 96)
	left := max(time.Unix(a.ch.ExpiresAt, 0).Sub(m.now()), 0).Round(time.Second)
	title := m.frame().Render("┏━ ") + badge("AUTHORIZE", cHUD) + sp(1)
	if a.title != "" {
		title += paint(sDim, a.title+" ")
	}
	timer := paint(sOrange, fmt.Sprintf(" %d:%02d ", int(left.Minutes()), int(left.Seconds())%60)) + m.frame().Render("━┓")
	top := title + m.frame().Render(strings.Repeat("━", max(dw+3-lipgloss.Width(title)-lipgloss.Width(timer), 0))) + timer

	inner := []string{paint(sPanel.Foreground(cYellow).Bold(true), "WHAT THE WALLET SAYS")}
	for _, l := range a.ch.Summary {
		inner = append(inner, paint(sPanel, l))
	}
	inner = append(inner, paint(sPanel, ""))
	how := "TOUCH OF A REGISTERED KEY"
	if a.ch.Methods[0] == ipc.MethodPassword {
		how = "PASSWORD"
	}
	switch a.stage {
	case reading:
		inner = append(inner, paint(sPanel.Foreground(cDim), "AUTHORIZE WITH  ")+paint(sPanel.Foreground(cCyan), how))
	case typing:
		inner = append(inner, paint(sPanel.Foreground(cDim), a.asking+"  ")+
			paint(sPanel.Foreground(cYellow), strings.Repeat("•", len([]rune(string(a.secret)))))+paint(sPanel.Foreground(cCyan), "▌"))
	case touching:
		what := "CHECKING…"
		if a.ch.Methods[0] != ipc.MethodPassword {
			what = "INSERT AND TOUCH A REGISTERED SECURITY KEY"
		}
		inner = append(inner, paint(sPanel.Foreground(cCyan), spinner[m.spin%len(spinner)]+" "+what))
	}
	out := []string{"", sp(2) + top}
	for _, s := range inner {
		s = sPanel.Render("  ") + s
		if lipgloss.Width(s) > dw+1 {
			s = ansiCut(s, dw+1)
		}
		out = append(out, sp(2)+m.frame().Render("┃")+s+sPanel.Render(strings.Repeat(" ", max(dw+1-lipgloss.Width(s), 0)))+m.frame().Render("┃"))
	}
	return append(out, sp(2)+m.frame().Render("┗"+strings.Repeat("━", dw+1)+"◢"))
}

func (m Model) helpView() []string {
	rows := [][2]string{
		{"1 to 4, tab, shift+tab", "change tabs"},
		{"↑ ↓, j k", "choose in a list"},
		{"enter", "open what is chosen"},
		{"esc", "go back, or clear the last note"},
		{":", "the commands, with their CLI equivalent"},
		{"f", "freeze every wallet, with no authorization"},
		{"?", "this help"},
		{"q, ctrl+c", "quit"},
		{"", ""},
		{"u / F", "in a wallet: unfreeze it / freeze it"},
		{"a / r", "in an authorization: authorize / reject an approval"},
	}
	out := []string{"", sp(2) + section("HELP"), ""}
	for _, r := range rows {
		out = append(out, sp(4)+paint(sYellow, fmt.Sprintf("%-26s", r[0]))+paint(sBase, r[1]))
	}
	return append(out, "", sp(4)+paint(sDim, "Everything here is also a command: mcpcardano with no arguments lists them."))
}
