// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Liet-ada/mcpcardano/internal/actions"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
)

// The audit log. The wallet reads and checks the whole file for each page,
// under the lock that signing takes, so the view never walks it: checking the
// chains gives the number of entries, and the view asks for the last page,
// and for older ones when the person asks. The filter works on what is loaded.

// auditLog is the audit tab.
type auditLog struct {
	lines   []actions.AuditEntry // by seq, the newest last
	total   uint64
	checked time.Time // when the chains were last found whole
	busy    bool
	cursor  cursor // over what the filter leaves, the newest first
	filter  []rune
	detail  *actions.AuditEntry
}

// shown is what the filter leaves, the newest first.
func (m Model) shown() []actions.AuditEntry {
	f := strings.ToLower(string(m.audit.filter))
	var out []actions.AuditEntry
	for _, e := range slices.Backward(m.audit.lines) {
		if strings.Contains(strings.ToLower(e.Type+" "+m.auditWallet(e)+" "+e.Body), f) {
			out = append(out, e)
		}
	}
	return out
}

func (m Model) auditWallet(e actions.AuditEntry) string {
	if e.Wallet == "" || m.status == nil {
		return e.Wallet
	}
	return m.walletName(e.Wallet)
}

// loadAudit checks the chains and asks for the newest entries.
func (m Model) loadAudit() tea.Cmd {
	return func() tea.Msg {
		c, err := m.w.VerifyAudit(m.ctx)
		if err != nil {
			return auditLoaded{err: err}
		}
		lines, err := m.auditPage(firstOfPage(c.AuditEntries + 1))
		return auditLoaded{check: c, lines: lines, err: err}
	}
}

// firstOfPage is the first seq of the page that ends before seq.
func firstOfPage(seq uint64) uint64 {
	if seq <= ipc.MaxAuditPage {
		return 1
	}
	return seq - ipc.MaxAuditPage
}

func (m Model) auditPage(from uint64) ([]actions.AuditEntry, error) {
	p, err := m.w.ShowAudit(m.ctx, from, ipc.MaxAuditPage)
	if err != nil {
		return nil, err
	}
	out := make([]actions.AuditEntry, 0, len(p.Entries))
	for _, raw := range p.Entries {
		e, err := actions.ReadAudit(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// loadOlder asks for the page before what is loaded.
func (m Model) loadOlder() tea.Cmd {
	first := m.audit.lines[0].Seq
	return func() tea.Msg {
		lines, err := m.auditPage(firstOfPage(first))
		if err != nil {
			return auditLoaded{err: err}
		}
		return auditLoaded{older: true, lines: slices.DeleteFunc(lines, func(e actions.AuditEntry) bool { return e.Seq >= first })}
	}
}

func (m Model) auditArrived(msg auditLoaded) (Model, tea.Cmd) {
	m.audit.busy = false
	switch {
	case msg.err != nil:
		m.audit.checked = time.Time{}
		return m.refuse(msg.err.Error())
	case msg.older:
		m.audit.lines = append(msg.lines, m.audit.lines...)
	default:
		m.audit.lines, m.audit.total, m.audit.checked = msg.lines, msg.check.AuditEntries, m.now()
		m.audit.cursor = cursor{}
	}
	return m, nil
}

func (m Model) auditKey(s string, delta int) (Model, tea.Cmd) {
	found := m.shown()
	m.audit.cursor.move(delta, len(found))
	switch s {
	case "/":
		m.overlay = filterOverlay
	case "v":
		m.audit.busy = true
		return m, m.loadAudit()
	case "m":
		if len(m.audit.lines) == 0 || m.audit.lines[0].Seq <= 1 {
			m.note, m.failed = "That is the first entry of the log.", false
			return m, nil
		}
		return m, m.loadOlder()
	case "enter":
		if len(found) > 0 {
			m.audit.detail, m.overlay = &found[m.audit.cursor.at], detailOverlay
		}
	}
	return m, nil
}

// filterKey edits the filter; enter keeps it and esc clears it.
func (m Model) filterKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		m.audit.filter = nil
		m.overlay = noOverlay
	case "enter":
		m.overlay = noOverlay
	default:
		m.audit.filter = edit(m.audit.filter, k)
	}
	m.audit.cursor = cursor{}
	return m, nil
}

func (m Model) auditView(w, height int) []string {
	a := &m.audit
	chain := paint(sDim, "checking the chain…")
	if !a.busy && !a.checked.IsZero() {
		chain = paint(sGreen, "chain ✓ ") + paint(sDim, fmt.Sprintf("verified %s (%d entries)", a.checked.Format(time.TimeOnly), a.total))
	} else if !a.busy {
		chain = paint(sRed, "chain not verified")
	}
	head := sp(2) + section("AUDIT")
	if m.overlay == filterOverlay || len(a.filter) > 0 {
		caret := ""
		if m.overlay == filterOverlay {
			caret = paint(sCyan, "▌")
		}
		head += sp(2) + paint(sHUD, "[ ") + paint(sCyan, string(a.filter)) + caret + paint(sHUD, " ]")
	}
	out := []string{"", spread(head, chain+sp(2), w), ""}
	if len(a.lines) == 0 {
		return append(out, sp(4)+paint(sDim, "Nothing to show yet."))
	}
	out = append(out, sp(4)+paint(sDim, fmt.Sprintf("%-7s %-19s %-24s %-14s %s", "SEQ", "TIME", "EVENT", "WALLET", "DETAIL")))
	found := m.shown()
	from, to := a.cursor.window(len(found), height-len(out)-1)
	for i := from; i < to; i++ {
		e := found[i]
		text := fmt.Sprintf("%-7d %-19s %-24s %-14s %s", e.Seq, when(e.Time, m.now()), truncate(e.Type, 24), truncate(m.auditWallet(e), 14), e.Body)
		if i == a.cursor.at {
			out = append(out, sp(2)+paint(sSelected, "▸ "+truncate(text, max(w-6, 10))+" "))
		} else {
			out = append(out, sp(4)+paint(sBase, text))
		}
	}
	return append(out, sp(4)+paint(sDim, fmt.Sprintf("%d of the %d loaded, from entry %d", len(found), len(a.lines), a.lines[0].Seq)))
}

func (m Model) detailView(w int) []string {
	e := m.audit.detail
	var pretty bytes.Buffer
	if json.Indent(&pretty, []byte(e.Body), "", "  ") != nil {
		pretty.Reset()
		pretty.WriteString(e.Body)
	}
	inner := []string{paint(sPanel.Foreground(cDim), when(e.Time, m.now())+"  ") + paint(sPanel.Foreground(cYellow), e.Type), paint(sPanel, "")}
	for _, l := range strings.Split(pretty.String(), "\n") {
		for _, part := range wrap(l, panelWidth(w)-1) {
			inner = append(inner, paint(sPanel, part))
		}
	}
	return m.panel(w, badge(fmt.Sprintf("ENTRY %d", e.Seq), cHUD)+sp(1), "", inner)
}
