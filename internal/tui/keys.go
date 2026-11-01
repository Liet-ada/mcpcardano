// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Liet-ada/mcpcardano/internal/actions"
	"github.com/Liet-ada/mcpcardano/internal/fido"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
)

// Registering a security key, step by step as key add does it: its name, the
// touch on the new key that makes the credential, and the authorization. With
// keys registered, the authorization takes one of them, so the person swaps
// keys before it. Removing a key and the recovery without keys are the rest of
// what the person does on them.

// rpID is the relying party of the wallet's keys.
const rpID = "mcpcardano"

// keyWait is how long the view waits for a key to be inserted.
const keyWait = 2 * time.Minute

type addStage int

const (
	addInsert addStage = iota // waiting for the new key, or for its touch
	addPIN                    // the PIN of the new key, to make its credential
	addSwap                   // the registered key goes in its place
)

// keyAdding is a security key on its way to being registered.
type keyAdding struct {
	name    string
	stage   addStage
	key     fido.Key // the new key, once open, until Register takes it
	info    fido.Info
	pin     []byte // never drawn
	data    []byte // what it said when it made its credential
	touched bool   // Register is waiting for the touch
	ctx     context.Context
	cancel  context.CancelFunc // lets go of a key that waits for its touch
}

// stop lets go of the key and wipes the PIN.
func (a *keyAdding) stop() {
	a.cancel()
	clear(a.pin)
	a.pin = nil
	if a.key != nil {
		a.key.Close()
		a.key = nil
	}
}

func (m Model) addKeyForm() (Model, tea.Cmd) {
	m.overlay = formOverlay
	m.form = &form{title: "REGISTER A SECURITY KEY",
		fields: []field{{name: "NAME", hint: "as YubiKey 5C"}},
		submit: func(m Model, v []string) (Model, tea.Cmd) {
			if err := actions.CheckKeyName(v[0]); err != nil {
				return m.refuse(sentence(err))
			}
			ctx, cancel := context.WithTimeout(m.ctx, keyWait)
			m.close()
			m.overlay = keyOverlay
			m.adding = &keyAdding{name: v[0], ctx: ctx, cancel: cancel}
			return m, tea.Batch(m.openNewKey(), spinAfter())
		}}
	return m, nil
}

// openNewKey waits for the new key and asks it about its PIN.
func (m Model) openNewKey() tea.Cmd {
	a := m.adding
	return func() tea.Msg {
		k, err := m.keys(a.ctx)
		for errors.Is(err, fido.ErrNoKey) {
			select {
			case <-a.ctx.Done():
				return keyOpened{adding: a, err: errors.New("no security key was inserted")}
			case <-time.After(500 * time.Millisecond):
			}
			k, err = m.keys(a.ctx)
		}
		if err != nil {
			return keyOpened{adding: a, err: err}
		}
		info, err := k.Info(a.ctx)
		if err != nil {
			k.Close()
			return keyOpened{adding: a, err: err}
		}
		return keyOpened{adding: a, key: k, info: info}
	}
}

func (m Model) keyOpen(msg keyOpened) (Model, tea.Cmd) {
	a := m.adding
	switch {
	case a == nil || a != msg.adding: // the person left while it waited
		if msg.key != nil {
			msg.key.Close()
		}
		return m, nil
	case msg.err != nil:
		m.close()
		return m.refuse(msg.err.Error())
	case !msg.info.PIN:
		name := msg.key.Name()
		msg.key.Close()
		m.close()
		return m.refuse(name + " has no PIN, and policies, keys and recovery phrases take one: set it with its maker's tool.")
	}
	a.key, a.info = msg.key, msg.info
	if msg.info.PINToRegister {
		a.stage = addPIN
		return m, nil
	}
	return m, m.register("")
}

// register has the new key make its credential, after its touch. From here
// the command holds the key, and closes it.
func (m Model) register(pin string) tea.Cmd {
	a := m.adding
	k := a.key
	a.key, a.touched, a.stage = nil, true, addInsert
	return func() tea.Msg {
		defer k.Close()
		data, err := k.Register(a.ctx, rpID, pin)
		if err != nil {
			return keyRegistered{adding: a, err: fmt.Errorf("%w: %v", errKey, err)}
		}
		return keyRegistered{adding: a, data: data}
	}
}

func (m Model) keyMade(msg keyRegistered) (Model, tea.Cmd) {
	a := m.adding
	switch {
	case a == nil || a != msg.adding:
		return m, nil
	case msg.err != nil:
		m.close()
		return m.refuse(msg.err.Error())
	}
	a.data = msg.data
	if m.status != nil && len(m.status.Keys) > 0 {
		a.stage = addSwap
		return m, nil
	}
	return m.authorizeKey()
}

// authorizeKey asks the wallet to register the key.
func (m Model) authorizeKey() (Model, tea.Cmd) {
	a := m.adding
	act, err := actions.AddKey(a.name, a.data)
	if err != nil {
		return m.refuse(sentence(err))
	}
	note := "The security key " + a.name + " is registered."
	if m.status != nil && len(m.status.Keys) == 0 {
		note += " From now on the wallet asks for its touch. Register a second one as a backup."
	}
	return m, m.begin(act, &authorization{title: "REGISTER " + strings.ToUpper(a.name), finish: say(note)})
}

func (m Model) keyAddKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	m.note, m.failed = "", false
	a := m.adding
	s := k.String()
	if s == "esc" {
		m.close()
		return m, nil
	}
	switch a.stage {
	case addPIN:
		switch s {
		case "backspace":
			if n := len(a.pin); n > 0 {
				a.pin[n-1] = 0
				a.pin = a.pin[:n-1]
			}
		case "enter":
			if len(a.pin) == 0 {
				m.close()
				return m, nil
			}
			pin := string(a.pin)
			clear(a.pin)
			a.pin = nil
			return m, tea.Batch(m.register(pin), spinAfter())
		default:
			a.pin = append(a.pin, k.Text...)
		}
	case addSwap:
		if s == "enter" {
			return m.authorizeKey()
		}
	}
	return m, nil
}

func (m Model) keyAddView(w int) []string {
	a := m.adding
	var inner []string
	switch a.stage {
	case addPIN:
		if a.info.Retries <= 3 {
			inner = append(inner, paint(sPanel.Foreground(cOrange), fmt.Sprintf("It locks after %d more wrong PINs.", a.info.Retries)))
		}
		inner = append(inner, paint(sPanel.Foreground(cDim), "PIN OF THE NEW KEY  ")+
			paint(sPanel.Foreground(cYellow), strings.Repeat("•", len([]rune(string(a.pin)))))+paint(sPanel.Foreground(cCyan), "▌"),
			pressLine(sPanel, "enter", "GO ON", "esc", "CANCEL"))
	case addSwap:
		inner = append(inner, paint(sPanel, "The new key made its credential."),
			paint(sPanel.Foreground(cCyan), "Now insert a registered key in its place."), paint(sPanel, ""),
			pressLine(sPanel, "enter", "CONTINUE", "esc", "CANCEL"))
	default:
		what := "INSERT THE NEW SECURITY KEY"
		if a.touched {
			what = "TOUCH THE NEW SECURITY KEY"
		}
		inner = append(inner, paint(sPanel.Foreground(cCyan), spinner[m.spin%len(spinner)]+" "+what))
	}
	return m.panel(w, badge("REGISTER A KEY", cHUD)+sp(1)+paint(sDim, strings.ToUpper(a.name)+" "), "", inner)
}

func (m Model) removeKey(k ipc.KeyInfo) (Model, tea.Cmd) {
	return m, m.begin(actions.RemoveKey(k.CredentialID),
		&authorization{title: "REMOVE " + strings.ToUpper(k.Name), finish: say("The security key " + k.Name + " is removed.")})
}

// unlocking is the screen of the password while the wallet is locked.
type unlocking struct {
	secret []byte // never drawn
	busy   bool   // the wallet is checking it
}

func (m Model) askUnlock() (Model, tea.Cmd) {
	m.close()
	m.overlay, m.unlock = unlockOverlay, &unlocking{}
	return m, nil
}

func (m Model) unlockKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	u := m.unlock
	if u.busy {
		return m, nil // the wallet answers on its own
	}
	m.note, m.failed = "", false
	switch k.String() {
	case "esc":
		m.close()
		m.unlockSkipped = true
	case "backspace":
		if n := len(u.secret); n > 0 {
			u.secret[n-1] = 0
			u.secret = u.secret[:n-1]
		}
	case "enter":
		if len(u.secret) == 0 {
			m.close()
			m.unlockSkipped = true
			return m, nil
		}
		secret := append([]byte(nil), u.secret...)
		clear(u.secret)
		u.secret, u.busy = nil, true
		return m, tea.Batch(func() tea.Msg {
			defer clear(secret)
			return unlocked{err: m.w.Unlock(m.ctx, secret)}
		}, spinAfter())
	default:
		u.secret = append(u.secret, k.Text...)
	}
	return m, nil
}

func (m Model) unlockView(w int) []string {
	u := m.unlock
	inner := []string{paint(sPanel, "The wallet keeps its keys sealed until you unlock it."), paint(sPanel, "")}
	if u.busy {
		inner = append(inner, paint(sPanel.Foreground(cCyan), spinner[m.spin%len(spinner)]+" CHECKING…"))
	} else {
		inner = append(inner, paint(sPanel.Foreground(cDim), "PASSWORD  ")+
			paint(sPanel.Foreground(cYellow), strings.Repeat("•", len([]rune(string(u.secret)))))+paint(sPanel.Foreground(cCyan), "▌"),
			pressLine(sPanel, "enter", "UNLOCK", "esc", "SEE IT LOCKED"))
	}
	return m.panel(w, badge("LOCKED", cOrange)+sp(1), "", inner)
}

func (m Model) startRecovery() (Model, tea.Cmd) {
	return m, m.begin(actions.StartRecovery(), &authorization{title: "RECOVERY WITHOUT KEYS",
		finish: decoded(new(ipc.Recovery), func(r *ipc.Recovery) done {
			return done{note: "The recovery started: every wallet is frozen, and at " + when(r.EndsAt, m.now()) + " the registered keys will be removed."}
		})})
}

func (m Model) cancelRecovery() (Model, tea.Cmd) {
	return m, m.begin(actions.CancelRecovery(), &authorization{title: "CANCEL THE RECOVERY",
		finish: say("The recovery is cancelled. The wallets stay frozen until you unfreeze them.")})
}

// when writes a Unix time as the time of day, with its date if it is not
// today: a recovery waits for days.
func when(unix int64, now time.Time) string {
	t := time.Unix(unix, 0)
	if t.Format(time.DateOnly) != now.Format(time.DateOnly) {
		return t.Format(time.DateTime)
	}
	return t.Format(time.TimeOnly)
}

// countdown writes the time until a Unix time, in hours.
func countdown(unix int64, now time.Time) string {
	d := max(time.Unix(unix, 0).Sub(now), 0).Round(time.Second)
	return fmt.Sprintf("%d:%02d:%02d", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
}
