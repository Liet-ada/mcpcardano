// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Liet-ada/mcpcardano/internal/actions"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
)

// What the person does on a wallet from its tab: unfreeze it, its session,
// its budget and creating one. Each action takes what section 6.2 asks of it,
// through the dialog of an authorization; closing a session reduces the risk
// and takes none. The recovery phrase is in phrase.go.

// refuse says what is wrong and leaves what is on show as it is.
func (m Model) refuse(note string) (Model, tea.Cmd) {
	m.note, m.failed = note, true
	return m, nil
}

func (m Model) unfreeze(ws ipc.WalletStatus) (Model, tea.Cmd) {
	w := ws.Wallet
	if !w.Frozen {
		m.note, m.failed = "Wallet "+w.Label+" is not frozen.", false
		return m, nil
	}
	return m, m.begin(actions.Unfreeze(w.ID),
		&authorization{title: "UNFREEZE " + label(w), finish: say("Wallet " + w.Label + " is unfrozen.")})
}

// sessionForm asks how long a session lasts and how much it may spend. The
// amount is in ADA, as the view writes every amount.
func (m Model) sessionForm(ws ipc.WalletStatus) (Model, tea.Cmd) {
	w := ws.Wallet
	if ws.Session != nil {
		m.note, m.failed = "Wallet "+w.Label+" already has a session.", false
		return m, nil
	}
	m.overlay = formOverlay
	m.form = &form{title: "OPEN A SESSION ON " + label(w),
		fields: []field{{name: "LASTS", hint: "as 30m or 2h", value: []rune("1h")}, {name: "UP TO", hint: "ADA"}},
		submit: func(m Model, v []string) (Model, tea.Cmd) {
			length, err := time.ParseDuration(v[0])
			if err != nil {
				return m.refuse("A session lasts a duration such as 30m or 2h.")
			}
			most, err := actions.ParseADA(v[1])
			if err != nil {
				return m.refuse("The maximum is an amount of ADA, as 40 or 12.5.")
			}
			act, err := actions.OpenSession(w.ID, length, most)
			if err != nil {
				return m.refuse(sentence(err))
			}
			return m, m.begin(act, &authorization{title: "SESSION ON " + label(w), finish: say("Session open on wallet " + w.Label + ".")})
		}}
	return m, nil
}

// sentence writes an error of the actions as a line of the footer.
func sentence(err error) string {
	s := err.Error()
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

// closeSession takes no authorization: it reduces the risk.
func (m Model) closeSession(ws ipc.WalletStatus) (Model, tea.Cmd) {
	w := ws.Wallet
	if ws.Session == nil {
		m.note, m.failed = "Wallet "+w.Label+" has no session.", false
		return m, nil
	}
	return m, func() tea.Msg {
		if err := m.w.CloseSession(m.ctx, w.ID); err != nil {
			return done{err: err}
		}
		return done{note: "Session closed on wallet " + w.Label + "."}
	}
}

func (m Model) createForm() (Model, tea.Cmd) {
	m.overlay = formOverlay
	m.form = &form{title: "CREATE A WALLET",
		fields: []field{{name: "LABEL", hint: "a name for it"}},
		submit: func(m Model, v []string) (Model, tea.Cmd) {
			act, err := actions.CreateWallet(v[0])
			if err != nil {
				return m.refuse(sentence(err))
			}
			return m, m.begin(act, &authorization{title: "CREATE " + strings.ToUpper(v[0]),
				finish: decoded(new(ipc.Wallet), func(w *ipc.Wallet) done {
					return done{note: "Wallet " + w.Label + " created: write down its phrase with p."}
				})})
		}}
	return m, nil
}

// budget is the list of a wallet's expired_unconfirmed entries, with those
// the person marked to release.
type budget struct {
	wallet  ipc.Wallet
	entries []ipc.Expired
	marked  []bool
	cursor  cursor
}

// expired asks for what the wallet may release.
func (m Model) expired(w ipc.Wallet) tea.Cmd {
	return func() tea.Msg {
		entries, err := m.w.Expired(m.ctx, w.ID)
		return expiredMsg{wallet: w, entries: entries, err: err}
	}
}

func (m Model) expiredList(msg expiredMsg) (Model, tea.Cmd) {
	switch {
	case msg.err != nil:
		return m.refuse(msg.err.Error())
	case len(msg.entries) == 0:
		m.note, m.failed = "Wallet "+msg.wallet.Label+" has nothing to release.", false
		return m, nil
	}
	m.overlay = budgetOverlay
	m.budget = &budget{wallet: msg.wallet, entries: msg.entries, marked: make([]bool, len(msg.entries))}
	return m, nil
}

func (m Model) budgetKey(s string) (tea.Model, tea.Cmd) {
	m.note, m.failed = "", false
	b := m.budget
	switch s {
	case "esc":
		m.close()
	case "up", "k":
		b.cursor.move(-1, len(b.entries))
	case "down", "j":
		b.cursor.move(1, len(b.entries))
	case "space":
		b.marked[b.cursor.at] = !b.marked[b.cursor.at]
	case "a":
		all := !allMarked(b.marked)
		for i := range b.marked {
			b.marked[i] = all
		}
	case "enter":
		return m.release()
	}
	return m, nil
}

func allMarked(marked []bool) bool {
	for _, on := range marked {
		if !on {
			return false
		}
	}
	return true
}

// release asks to release what is marked, for the wallet to add it up.
func (m Model) release() (Model, tea.Cmd) {
	b := m.budget
	var ids [][]byte
	for i, e := range b.entries {
		if b.marked[i] {
			ids = append(ids, e.BodyHash)
		}
	}
	if len(ids) == 0 {
		return m.refuse("Mark what to release with space, or all of it with a.")
	}
	w := b.wallet
	return m, m.begin(actions.ReleaseBudget(w.ID, ids), &authorization{title: "RELEASE ON " + label(w),
		finish: decoded(new(ipc.Released), func(r *ipc.Released) done {
			return done{note: "Released " + ada(r.Lovelace) + " of the budget of wallet " + w.Label + "."}
		})})
}

func (m Model) budgetView(height int) []string {
	b := m.budget
	out := []string{"", sp(2) + section("RELEASE THE BUDGET OF "+label(b.wallet)), "",
		sp(4) + paint(sBase, "The wallet signed these and their time to live passed, by its clock. They count as spent until you"),
		sp(4) + paint(sBase, "release them. ") + paint(sOrange, "First check on the chain that none of them entered it."), ""}
	from, to := b.cursor.window(len(b.entries), height-len(out))
	for i := from; i < to; i++ {
		e := b.entries[i]
		mark := "[ ]"
		if b.marked[i] {
			mark = "[x]"
		}
		text := fmt.Sprintf("%s %16s  signed %s  until slot %d  %x", mark, ada(e.Spend.Lovelace), clock(e.Time), e.TTL, e.BodyHash)
		if n := len(e.Spend.Assets); n > 0 {
			text = fmt.Sprintf("%s %16s + %d %s  signed %s  until slot %d  %x", mark, ada(e.Spend.Lovelace), n, plural(n, "token", "tokens"), clock(e.Time), e.TTL, e.BodyHash)
		}
		if i == b.cursor.at {
			out = append(out, sp(2)+paint(sSelected, "▸ "+text+" "))
		} else {
			out = append(out, sp(4)+paint(sBase, text))
		}
	}
	return out
}
