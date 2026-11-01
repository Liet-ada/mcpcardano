// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"context"
	"fmt"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/Liet-ada/mcpcardano/internal/doctor"
)

// Doctor runs mcpcardano doctor, for the system tab.
type Doctor func(ctx context.Context) (doctor.Report, error)

// system is the system tab.
type system struct {
	report doctor.Report
	ran    bool
	busy   bool
	scroll int
}

// sudo is what only sudo does: the view shows the command, for another
// terminal.
var sudo = []string{
	"sudo mcpcardano install",
	"sudo mcpcardano uninstall",
	"sudo mcpcardano apikey set <name>",
	"sudo mcpcardano apikey remove <name>",
}

func (m Model) runDoctor() (Model, tea.Cmd) {
	if m.doctor == nil {
		return m.refuse("This view cannot run doctor: mcpcardano doctor.")
	}
	m.tab, m.sys.busy = tabSystem, true
	return m, func() tea.Msg {
		r, err := m.doctor(m.ctx)
		return doctorDone{report: r, err: err}
	}
}

func (m Model) systemKey(s string, delta int) (Model, tea.Cmd) {
	m.sys.scroll = max(m.sys.scroll+delta, 0)
	switch s {
	case "u":
		if m.status.Unlocked {
			m.note, m.failed = "The wallet is unlocked.", false
			return m, nil
		}
		return m.askUnlock()
	case "r":
		switch {
		case m.status.Recovery != nil:
			m.note, m.failed = "A recovery is already waiting.", false
			return m, nil
		case len(m.status.Keys) == 0:
			m.note, m.failed = "No key is registered: the password already authorizes.", false
			return m, nil
		}
		return m.startRecovery()
	case "x":
		if m.status.Recovery == nil {
			m.note, m.failed = "No recovery is waiting.", false
			return m, nil
		}
		return m.cancelRecovery()
	case "t":
		return m.editTemplate()
	case "d":
		return m.runDoctor()
	}
	return m, nil
}

func levelStyle(l doctor.Level) lipgloss.Style {
	switch l {
	case doctor.Fail:
		return sRed
	case doctor.Warn:
		return sOrange
	}
	return sGreen
}

func (m Model) systemView(height int) []string {
	st := m.status
	kv := func(k, v string) string { return sp(4) + paint(sDim, fmt.Sprintf("%-12s", k)) + v }
	state := paint(sGreen, "● UNLOCKED")
	if !st.Unlocked {
		state = paint(sOrange, "● LOCKED") + sp(2) + keyHint("u", "unlock")
	}
	out := []string{"", sp(2) + section("WALLET"), kv("STATE", state), "", sp(2) + section("RECOVERY WITHOUT KEYS")}
	if r := st.Recovery; r != nil {
		out = append(out, kv("ENDS", paint(sRed, when(r.EndsAt, m.now()))+paint(sDim, ", in "+countdown(r.EndsAt, m.now()))+sp(2)+keyHint("x", "cancel it, with a key")),
			sp(4)+paint(sBase, "Then the keys are removed and the password authorizes again. If you did not start it, cancel it now."))
	} else {
		out = append(out, kv("WAITING", paint(sDim, "none")+sp(2)+keyHint("r", "start it, with the password; it freezes every wallet")))
	}
	out = append(out, "", sp(2)+section("TEMPLATE OF THE AGENT'S WALLETS"), sp(4)+keyHint("t", "edit it"),
		"", sp(2)+section("ONLY WITH SUDO, IN ANOTHER TERMINAL"))
	for _, c := range sudo {
		out = append(out, sp(4)+paint(sBase, c))
	}
	out = append(out, "", sp(2)+section("DOCTOR")+sp(2)+keyHint("d", "run it"))
	switch {
	case m.sys.busy:
		out = append(out, sp(4)+paint(sDim, "Checking…"))
	case m.sys.ran:
		for _, r := range m.sys.report {
			out = append(out, sp(4)+paint(levelStyle(r.Level), r.Level.String())+sp(2)+paint(sBase, r.Detail))
		}
	}
	from := min(m.sys.scroll, max(len(out)-height, 0))
	return out[from:]
}
