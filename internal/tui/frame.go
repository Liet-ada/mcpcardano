// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"fmt"
	"slices"
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
			state = paint(sRed, "! RECOVERY IN "+countdown(st.Recovery.EndsAt, m.now()))
		case st.Unlocked:
			state = paint(sGreen, "● UNLOCKED")
		default:
			state = paint(sOrange, "● LOCKED")
		}
		state += paint(sDim, "  │  ") + paint(sBold, fmt.Sprint(len(st.Keys))) + paint(sDim, plural(len(st.Keys), " KEY", " KEYS"))
	}
	right := state + paint(sDim, "  │  ") + m.serverState() + paint(sDim, "  │  ") + paint(sCyan, m.now().Format(time.TimeOnly)) + sp(1)

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

// serverState says in the frame whether the server answers, without which
// the view has no balances.
func (m Model) serverState() string {
	switch {
	case m.server == nil || m.link.answered && !m.link.up:
		return paint(sOrange, "NO SERVER")
	case !m.link.answered:
		return paint(sDim, "SERVER?")
	}
	return paint(sGreen, "SERVER")
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
			if m.authOverflow() > 0 {
				hints = append(hints, keyHint("↑↓", "read it all"))
			}
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
	case m.overlay == formOverlay:
		hints = []string{keyHint("tab", "next"), keyHint("enter", "go on"), keyHint("esc", "back")}
	case m.overlay == keyOverlay:
		hints = []string{keyHint("esc", "cancel")}
		if m.adding.stage == addPIN || m.adding.stage == addSwap {
			hints = []string{keyHint("enter", "go on"), keyHint("esc", "cancel")}
		}
	case m.overlay == unlockOverlay:
		hints = []string{keyHint("enter", "unlock"), keyHint("esc", "see the wallet locked")}
	case m.overlay == filterOverlay:
		hints = []string{keyHint("enter", "keep the filter"), keyHint("esc", "clear it")}
	case m.overlay == detailOverlay:
		hints = []string{keyHint("any key", "close")}
	case m.overlay == editorOverlay:
		hints = []string{keyHint("↑↓", "choose"), keyHint("enter", "open or switch"), keyHint("x", "remove from a list"), keyHint("ctrl+r", "review"), keyHint("esc", "discard")}
	case m.overlay == budgetOverlay:
		hints = []string{keyHint("↑↓", "choose"), keyHint("space", "mark"), keyHint("a", "mark all"), keyHint("enter", "release"), keyHint("esc", "back")}
	case m.overlay == restoreOverlay:
		hints = []string{keyHint("enter", "next word"), keyHint("backspace", "go back"), keyHint("ctrl+r", "show or hide"), keyHint("esc", "cancel")}
	case m.overlay == phraseOverlay:
		hints = []string{keyHint("space", "show or hide the words"), keyHint("esc", "hide and go back")}
	default:
		hints = []string{keyHint("1-6", "tabs")}
		if m.tab == tabAudit { // to fit its own keys
			hints = nil
		}
		switch m.tab {
		case tabWallets:
			hints = append(hints, keyHint("↑↓", "choose"))
		case tabKeys:
			hints = append(hints, keyHint("↑↓", "choose"), keyHint("a", "add"), keyHint("d", "remove"))
		case tabAudit:
			hints = append(hints, keyHint("↑↓", "choose"), keyHint("enter", "detail"), keyHint("/", "filter"), keyHint("m", "older"), keyHint("v", "verify"))
		case tabSystem:
			hints = append(hints, keyHint("↑↓", "scroll"))
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
		return m.authView(w, height)
	case m.overlay == helpOverlay:
		return m.helpView()
	case m.overlay == paletteOverlay:
		return m.paletteView(w, height)
	case m.overlay == formOverlay:
		return m.formView()
	case m.overlay == editorOverlay:
		return m.editorView(w, height)
	case m.overlay == keyOverlay:
		return m.keyAddView(w)
	case m.overlay == unlockOverlay:
		return m.unlockView(w)
	case m.overlay == detailOverlay:
		return m.detailView(w)
	case m.overlay == budgetOverlay:
		return m.budgetView(height)
	case m.overlay == restoreOverlay:
		return m.restoreView(w)
	case m.overlay == phraseOverlay:
		return m.phraseView(w)
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
	case tabAudit:
		return m.auditView(w, height)
	case tabSystem:
		return m.systemView(height)
	}
	return m.overview(w)
}

// authBody is what there is to read in an authorization: what the person
// changed, as the editor sees it, and below it what the wallet says, as it
// says it and whole.
func (m Model) authBody(w int) []string {
	a := m.auth
	var out []string
	if len(a.changes) > 0 {
		out = append(out, paint(sPanel.Foreground(cYellow).Bold(true), "WHAT YOU CHANGED"))
		for _, c := range byWay(a.changes) {
			out = append(out, changeLine(c))
		}
		for _, warning := range a.warnings {
			for _, l := range wrap("! "+warning, panelWidth(w)-1) {
				out = append(out, paint(sPanel.Foreground(cOrange), l))
			}
		}
		out = append(out, paint(sPanel, ""))
	}
	out = append(out, paint(sPanel.Foreground(cYellow).Bold(true), "WHAT THE WALLET SAYS"))
	for _, s := range a.ch.Summary {
		for _, l := range wrap(s, panelWidth(w)-1) {
			out = append(out, paint(sPanel, l))
		}
	}
	return out
}

// authOverflow is how many lines of the dialog do not fit: its frame, a blank
// line, the way to authorize, the keys and the line that says there is more
// take seven.
func (m Model) authOverflow() int {
	w, h := m.size()
	return max(len(m.authBody(w))-(h-chrome-7), 0)
}

// authView is the dialog of an authorization: what there is to read, the time
// left, and the password, the PIN or the key.
func (m Model) authView(w, height int) []string {
	a := m.auth
	left := max(time.Unix(a.ch.ExpiresAt, 0).Sub(m.now()), 0).Round(time.Second)
	title := badge("AUTHORIZE", cHUD) + sp(1)
	if a.title != "" {
		title += paint(sDim, a.title+" ")
	}
	timer := paint(sOrange, fmt.Sprintf(" %d:%02d ", int(left.Minutes()), int(left.Seconds())%60))

	inner := m.authBody(w)
	if over := m.authOverflow(); over > 0 {
		at := min(m.scroll, over)
		more := paint(sPanel.Foreground(cCyan), fmt.Sprintf("↓ %d more lines: ↑↓ to read them", over-at))
		if at == over {
			more = paint(sPanel.Foreground(cDim), "↑ that is all")
		}
		inner = append(slices.Clone(inner[at:len(inner)-over+at]), more)
	}
	inner = append(inner, paint(sPanel, ""))
	how := "TOUCH OF A REGISTERED KEY"
	if a.ch.Methods[0] == ipc.MethodPassword {
		how = "PASSWORD"
	}
	switch a.stage {
	case reading:
		inner = append(inner, paint(sPanel.Foreground(cDim), "AUTHORIZE WITH  ")+paint(sPanel.Foreground(cCyan), how))
		if a.approval != "" {
			inner = append(inner, pressLine(sPanel, "a", "CONTINUE", "r", "REJECT", "esc", "GO BACK"))
		} else {
			inner = append(inner, pressLine(sPanel, "a", "CONTINUE", "esc", "GO BACK"))
		}
	case typing:
		inner = append(inner, paint(sPanel.Foreground(cDim), a.asking+"  ")+
			paint(sPanel.Foreground(cYellow), strings.Repeat("•", len([]rune(string(a.secret)))))+paint(sPanel.Foreground(cCyan), "▌"),
			pressLine(sPanel, "enter", "SEND", "esc", "DECLINE"))
	case touching:
		what := "CHECKING…"
		if a.ch.Methods[0] != ipc.MethodPassword {
			what = "INSERT AND TOUCH A REGISTERED SECURITY KEY"
		}
		inner = append(inner, paint(sPanel.Foreground(cCyan), spinner[m.spin%len(spinner)]+" "+what))
	}
	return m.panel(w, title, timer, inner)
}

func panelWidth(w int) int { return min(w-6, 96) }

// panel is a dialog over the tab: a frame with a title, what stands at its
// right, and its lines cut to its width.
func (m Model) panel(w int, title, right string, inner []string) []string {
	dw := panelWidth(w)
	title = m.frame().Render("┏━ ") + title
	right += m.frame().Render("━┓")
	top := title + m.frame().Render(strings.Repeat("━", max(dw+3-lipgloss.Width(title)-lipgloss.Width(right), 0))) + right
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
		{"1 to 6, tab, shift+tab", "change tabs"},
		{"↑ ↓, j k", "choose in a list"},
		{"enter", "open what is chosen"},
		{"esc", "go back, or clear the last note"},
		{":", "the commands, with their CLI equivalent"},
		{"f", "freeze every wallet, with no authorization"},
		{"?", "this help"},
		{"q, ctrl+c", "quit"},
		{"u / F", "in a wallet: unfreeze it / freeze it"},
		{"s", "in a wallet: open its session, or close it"},
		{"e / r", "in a wallet: edit its policy / ask for its balance now"},
		{"b / p", "in a wallet: release its budget / see its recovery phrase"},
		{"c / R", "in the wallets: create one / restore one"},
		{"a / r", "in an authorization: authorize / reject an approval"},
		{"a / d", "in the keys: add one / remove one"},
		{"/ m v", "in the audit: filter / load older entries / verify the chain"},
		{"u r x t d n", "in the system: unlock / recover / cancel / template / doctor / network"},
	}
	out := []string{"", sp(2) + section("HELP"), ""}
	for _, r := range rows {
		out = append(out, sp(4)+paint(sYellow, fmt.Sprintf("%-26s", r[0]))+paint(sBase, r[1]))
	}
	return out
}
