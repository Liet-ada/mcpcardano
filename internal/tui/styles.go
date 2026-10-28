// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// The palette of decision 142, after the interface of Cyberpunk 2077: neon
// yellow for the accent, cyan for information and the selection, a hot pink
// for danger and the red of its HUD for the frame lines, on a dark background
// the view paints itself. Every colour reaches 4.5:1 against the background
// and the dialogs' panel (TestContrast). Bubbletea brings it down to 256 or
// 16 colours on terminals without truecolor, and NO_COLOR removes it.
var (
	cBg      = lipgloss.Color("#0A0B10")
	cPanel   = lipgloss.Color("#12141C")
	cText    = lipgloss.Color("#D9F7FF")
	cDim     = lipgloss.Color("#7D8A99")
	cYellow  = lipgloss.Color("#FCEE0A")
	cCyan    = lipgloss.Color("#00F0FF")
	cRed     = lipgloss.Color("#FF003C")
	cHUD     = lipgloss.Color("#E8505B")
	cGreen   = lipgloss.Color("#00FF9F")
	cOrange  = lipgloss.Color("#FF9E1B")
	cMagenta = lipgloss.Color("#FF2A6D")
	cBlack   = lipgloss.Color("#000000")
)

// Every style paints the background: the view fills the whole screen.
var (
	sBase   = lipgloss.NewStyle().Background(cBg).Foreground(cText)
	sDim    = sBase.Foreground(cDim)
	sBold   = sBase.Bold(true)
	sYellow = sBase.Foreground(cYellow).Bold(true)
	sCyan   = sBase.Foreground(cCyan)
	sRed    = sBase.Foreground(cRed).Bold(true)
	sHUD    = sBase.Foreground(cHUD)
	sGreen  = sBase.Foreground(cGreen)
	sOrange = sBase.Foreground(cOrange).Bold(true)

	// sSelected paints the chosen row edge to edge, so the cursor reads as a
	// selection and not as one more line.
	sSelected = lipgloss.NewStyle().Background(cCyan).Foreground(cBlack).Bold(true)

	sPanel = lipgloss.NewStyle().Background(cPanel).Foreground(cText)
)

// modeColor is the colour of a mode's badge.
func modeColor(mode string) color.Color {
	switch mode {
	case "A":
		return cCyan
	case "B":
		return cMagenta
	}
	return cYellow
}

// paint writes text in a style, after visible: whatever the text is, the
// only control sequences in the view are the ones lipgloss makes.
func paint(st lipgloss.Style, text string) string { return st.Render(visible(text)) }

// sp is n spaces of the background.
func sp(n int) string { return sBase.Render(strings.Repeat(" ", max(n, 0))) }

// badge is a filled label whose right edge is cut on the diagonal.
func badge(text string, bg color.Color) string {
	return lipgloss.NewStyle().Background(bg).Foreground(cBlack).Bold(true).Render(" "+visible(text)+" ") +
		sBase.Foreground(bg).Render("◤")
}

// keyHint is one "key action" pair of the footer: the key stands out, the
// word stays quiet.
func keyHint(key, desc string) string { return paint(sYellow, key) + paint(sDim, " "+desc) }

// spread puts left and right on one line of width w, at least one space
// apart.
func spread(left, right string, w int) string {
	return left + sp(max(w-lipgloss.Width(left)-lipgloss.Width(right), 1)) + right
}

// fit cuts a drawn line to width w and fills it with the background.
func fit(s string, w int) string {
	if lipgloss.Width(s) > w {
		s = ansi.Truncate(s, w, "…")
	}
	return s + sp(w-lipgloss.Width(s))
}

// rule is a frame line with an optional label, in the colour of the frame.
func rule(label string, w int, frame lipgloss.Style) string {
	head := frame.Render("━━")
	if label != "" {
		head += paint(sYellow, " "+label+" ")
	}
	return head + frame.Render(strings.Repeat("━", max(w-lipgloss.Width(head)-1, 0))) + frame.Render("◆")
}

// section is a heading inside a view, as "// WALLETS".
func section(title string) string { return paint(sHUD, "// ") + paint(sYellow, title) }

// gauge draws what was used of a limit in cells segments: cyan, orange from
// 70% and pink from 90%.
func gauge(used, limit uint64, cells int) string {
	if limit == 0 {
		return paint(sDim, strings.Repeat("▱", cells))
	}
	n := int(min(used, limit) * uint64(cells) / limit)
	if used > 0 && n == 0 {
		n = 1
	}
	st := sCyan
	switch {
	case used*10 >= limit*9:
		st = sRed
	case used*10 >= limit*7:
		st = sOrange
	}
	return st.Render(strings.Repeat("▰", n)) + paint(sDim, strings.Repeat("▱", cells-n))
}

// truncate cuts plain text to width runes, with an ellipsis.
func truncate(s string, width int) string {
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width < 2 {
		return string(r[:max(width, 0)])
	}
	return string(r[:width-1]) + "…"
}
