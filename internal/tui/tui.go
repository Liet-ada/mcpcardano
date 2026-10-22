// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package tui is the interactive view of the CLI (section 6.4; decision
// 125): the wallet's status as it changes, the approvals as they arrive with
// the summary the wallet computed, approving or rejecting them with a
// registered key's touch or the password, and freezing every wallet with one
// key. It talks only to the wallet's admin socket, through Wallet, and opens
// no port. Everything it draws goes through visible first.
package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	tea "charm.land/bubbletea/v2"

	"github.com/Liet-ada/mcpcardano/internal/fido"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Wallet is what the view asks of the wallet's admin socket.
type Wallet interface {
	Status(ctx context.Context) (*ipc.StatusReport, error)
	Begin(ctx context.Context, action string, params ipc.Body) (*ipc.Challenge, error)
	Complete(ctx context.Context, c *ipc.CompleteAuthorization) error
	Reject(ctx context.Context, approvalID string) error
	FreezeAll(ctx context.Context) error
}

// refresh is how often the view asks for the status.
const refresh = 2 * time.Second

// Run shows the view on a terminal until the person quits.
func Run(ctx context.Context, w Wallet, keys fido.Opener, network string, in io.Reader, out io.Writer) error {
	p := tea.NewProgram(New(ctx, w, keys, network), tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out))
	_, err := p.Run()
	// An interruption from outside, as Ctrl-C to the CLI, is a way to quit;
	// anything else, a panic included, is an error to report.
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// stage is what the view is doing.
type stage int

const (
	browsing stage = iota // the status and the approvals
	reading               // an approval's summary, from BeginAuthorization
	typing                // the password, or the key's PIN
	touching              // waiting for the key
)

// Model is the view, as bubbletea runs it.
type Model struct {
	ctx     context.Context
	w       Wallet
	keys    fido.Opener
	network string

	status   *ipc.StatusReport
	cursor   int // the approval chosen
	stage    stage
	ch       *ipc.Challenge // the authorization open while reading
	approval string         // its approval
	secret   []byte         // what is typed, never drawn
	asking   string         // "the password" or "the key's PIN"
	note     string         // what last happened
	failed   bool           // whether the note is an error
}

// New returns the view before its first status.
func New(ctx context.Context, w Wallet, keys fido.Opener, network string) Model {
	return Model{ctx: ctx, w: w, keys: keys, network: network}
}

// The messages of the view's commands.
type (
	tick      struct{}
	statusMsg struct {
		st  *ipc.StatusReport
		err error
	}
	challenged struct {
		ch       *ipc.Challenge
		approval string
		err      error
	}
	done struct {
		note string
		err  error
	}
)

func (m Model) Init() tea.Cmd { return m.fetch }

func (m Model) fetch() tea.Msg {
	st, err := m.w.Status(m.ctx)
	return statusMsg{st, err}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tick:
		return m, m.fetch
	case statusMsg:
		if msg.err != nil {
			m.note, m.failed = msg.err.Error(), true
		} else {
			m.status = msg.st
			m.cursor = min(m.cursor, max(len(m.status.Approvals)-1, 0))
		}
		return m, tea.Tick(refresh, func(time.Time) tea.Msg { return tick{} })
	case challenged:
		if msg.err != nil {
			m.stage, m.note, m.failed = browsing, msg.err.Error(), true
			return m, nil
		}
		m.stage, m.ch, m.approval, m.note = reading, msg.ch, msg.approval, ""
		return m, nil
	case done:
		m.forget()
		m.note, m.failed = msg.note, msg.err != nil
		if msg.err != nil {
			m.note = msg.err.Error()
			// A wrong password or PIN leaves the authorization open.
			var e *ipc.Error
			if m.ch != nil && (errors.As(msg.err, &e) && e.Code == ipc.AuthFailed || errors.Is(msg.err, errKey)) {
				m.stage = reading
				return m, m.fetch
			}
		}
		m.stage, m.ch, m.approval = browsing, nil, ""
		return m, m.fetch
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	return m, nil
}

// key handles what the person presses.
func (m Model) key(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if k.String() == "ctrl+c" {
		m.forget()
		return m, tea.Quit
	}
	switch m.stage {
	case typing:
		return m.typed(k)
	case touching:
		return m, nil // the key answers, or gives up, on its own
	}
	switch k.String() {
	case "q":
		m.forget()
		return m, tea.Quit
	case "f":
		m.stage, m.ch, m.approval = browsing, nil, ""
		return m, func() tea.Msg {
			if err := m.w.FreezeAll(m.ctx); err != nil {
				return done{err: err}
			}
			return done{note: "Every wallet is frozen."}
		}
	}
	if m.stage == reading {
		switch k.String() {
		case "a":
			return m.approve()
		case "r":
			return m, m.reject(m.approval)
		case "esc":
			m.stage, m.ch, m.approval = browsing, nil, ""
		}
		return m, nil
	}
	n := 0
	if m.status != nil {
		n = len(m.status.Approvals)
	}
	switch k.String() {
	case "up", "k":
		m.cursor = max(m.cursor-1, 0)
	case "down", "j":
		m.cursor = min(m.cursor+1, max(n-1, 0))
	case "enter":
		if n > 0 {
			id := m.status.Approvals[m.cursor].ID
			m.note = ""
			return m, func() tea.Msg {
				ch, err := m.w.Begin(m.ctx, ipc.ActApproveDraft, &ipc.ApproveDraft{ApprovalID: id})
				return challenged{ch, id, err}
			}
		}
	case "r":
		if n > 0 {
			return m, m.reject(m.status.Approvals[m.cursor].ID)
		}
	}
	return m, nil
}

func (m Model) reject(id string) tea.Cmd {
	return func() tea.Msg {
		if err := m.w.Reject(m.ctx, id); err != nil {
			return done{err: err}
		}
		return done{note: "Rejected " + id + "."}
	}
}

// approve asks for what the authorization takes: the password, or the key
// with its PIN if the action needs it.
func (m Model) approve() (tea.Model, tea.Cmd) {
	switch {
	case m.ch.Methods[0] == ipc.MethodPassword:
		m.stage, m.asking = typing, "the password"
	case m.ch.PIN:
		m.stage, m.asking = typing, "the key's PIN"
	default:
		m.stage = touching
		return m, m.touch("")
	}
	return m, nil
}

// typed collects the password or the PIN without drawing it. Enter sends
// it; Esc, or Enter with nothing typed, declines.
func (m Model) typed(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "esc":
		m.forget()
		m.stage = reading
	case "backspace":
		if len(m.secret) > 0 {
			m.secret[len(m.secret)-1] = 0
			m.secret = m.secret[:len(m.secret)-1]
		}
	case "enter":
		if len(m.secret) == 0 {
			m.stage = reading
			return m, nil
		}
		secret := model.Secret(append([]byte(nil), m.secret...))
		m.forget()
		if m.ch.Methods[0] == ipc.MethodPassword {
			m.stage = touching // nothing to touch, but the wallet is working
			ch := m.ch
			return m, func() tea.Msg {
				defer clear(secret)
				err := m.w.Complete(m.ctx, &ipc.CompleteAuthorization{AuthID: ch.AuthID, Password: secret})
				return approved(err)
			}
		}
		m.stage = touching
		pin := string(secret)
		clear(secret)
		return m, m.touch(pin)
	default:
		m.secret = append(m.secret, k.Text...)
	}
	return m, nil
}

// errKey marks what the key refused, which leaves the authorization open.
var errKey = errors.New("the security key refused")

// touch waits for a registered key until the authorization expires, has it
// sign, and completes the authorization with its assertion.
func (m Model) touch(pin string) tea.Cmd {
	ch := m.ch
	return func() tea.Msg {
		ctx, cancel := context.WithDeadline(m.ctx, time.Unix(ch.ExpiresAt, 0))
		defer cancel()
		k, err := m.keys(ctx)
		for errors.Is(err, fido.ErrNoKey) {
			select {
			case <-ctx.Done():
				return done{err: errors.New("no security key was inserted")}
			case <-time.After(500 * time.Millisecond):
			}
			k, err = m.keys(ctx)
		}
		if err != nil {
			return done{err: err}
		}
		defer k.Close()
		a, err := k.Assert(ctx, ch.RPID, ch.ClientDataHash, ch.Credentials, pin)
		if err != nil {
			return done{err: fmt.Errorf("%w: %v", errKey, err)}
		}
		return approved(m.w.Complete(m.ctx, &ipc.CompleteAuthorization{AuthID: ch.AuthID,
			Assertion: &ipc.Assertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, Signature: a.Signature}}))
	}
}

func approved(err error) tea.Msg {
	if err != nil {
		return done{err: err}
	}
	return done{note: "Approved: the server sends the transaction."}
}

// forget wipes what was typed.
func (m *Model) forget() {
	clear(m.secret)
	m.secret = nil
}

// View draws the view on the terminal's alternate screen.
func (m Model) View() tea.View {
	v := tea.NewView(m.content())
	v.AltScreen = true
	return v
}

func (m Model) content() string {
	var b strings.Builder
	line := func(format string, args ...any) { b.WriteString(visible(fmt.Sprintf(format, args...)) + "\n") }
	st := m.status
	state := "connecting"
	if st != nil {
		state = "locked: unlock it with mcpcardano unlock"
		if st.Unlocked {
			state = "unlocked"
		}
	}
	line("mcpcardano · %s · %s        [f] freeze all  [q] quit", m.network, state)
	line("%s", strings.Repeat("─", 64))
	if st != nil && st.Recovery != nil {
		line("A RECOVERY WITHOUT KEYS IS WAITING: at %s the keys are removed. If you did not start it: mcpcardano recover cancel", clock(st.Recovery.EndsAt))
	}
	switch m.stage {
	case browsing:
		m.browse(line)
	default:
		m.read(line)
	}
	if m.note != "" {
		mark := ""
		if m.failed {
			mark = "! "
		}
		line("")
		line("%s%s", mark, m.note)
	}
	return b.String()
}

func (m Model) browse(line func(string, ...any)) {
	st := m.status
	if st == nil {
		return
	}
	line("Wallets")
	if len(st.Wallets) == 0 {
		line("  none yet")
	}
	for _, w := range st.Wallets {
		frozen := ""
		if w.Wallet.Frozen {
			frozen = "  FROZEN"
		}
		line("  %s  %s  mode %s%s", w.Wallet.ID, w.Wallet.Label, w.Wallet.Mode, frozen)
		if s := w.Session; s != nil {
			line("    session until %s, %s left", clock(s.ExpiresAt), ada(s.Remaining))
		}
	}
	line("")
	if len(st.Approvals) == 0 {
		line("No approval is waiting.")
		return
	}
	line("Approvals waiting")
	for i, a := range st.Approvals {
		mark := " "
		if i == m.cursor {
			mark = "▸"
		}
		line("%s %s  wallet %s  spends %s  until %s", mark, a.ID, a.WalletID, ada(a.Spend.Lovelace), clock(a.ExpiresAt))
	}
	line("  [enter] read  [r] reject  [↑↓] choose")
}

func (m Model) read(line func(string, ...any)) {
	line("The wallet asks you to confirm %s:", m.approval)
	for _, l := range m.ch.Summary {
		line("  %s", l)
	}
	line("")
	how := "touch of a registered key"
	if m.ch.Methods[0] == ipc.MethodPassword {
		how = "password"
	}
	switch m.stage {
	case reading:
		line("Until %s.  [a] approve (%s)  [r] reject  [esc] back", clock(m.ch.ExpiresAt), how)
	case typing:
		line("Type %s and press Enter (Esc declines): %s", m.asking, strings.Repeat("•", len([]rune(string(m.secret)))))
	case touching:
		if m.ch.Methods[0] == ipc.MethodPassword {
			line("Checking…")
		} else {
			line("Insert and touch a registered security key before %s.", clock(m.ch.ExpiresAt))
		}
	}
}

// visible keeps what a terminal shows as text and puts "?" for anything
// else: the view never writes a control sequence it did not make.
func visible(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == ' ' || unicode.IsGraphic(r) && !unicode.IsSpace(r) {
			return r
		}
		return '?'
	}, s)
}

func clock(unix int64) string { return time.Unix(unix, 0).Format(time.TimeOnly) }

func ada(lovelace uint64) string {
	return fmt.Sprintf("%d.%06d ADA", lovelace/1_000_000, lovelace%1_000_000)
}
