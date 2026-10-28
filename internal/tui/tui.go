// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package tui is the interactive view of the CLI (section 6.4; decisions
// 125, 126 and 142): the wallet as it changes, its wallets with their limits
// and what they spent, the approvals as they arrive with the summary the
// wallet computed, approving or rejecting them with a registered key's touch
// or the password, the security keys, and freezing every wallet with one
// key. It talks only to the wallet's admin socket, through Wallet, and opens
// no port. Every text it draws goes through visible first.
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
	PolicyStatus(ctx context.Context, walletID string) (*ipc.PolicyStatus, error)
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

// tab is one of the view's tabs.
type tab int

const (
	tabOverview tab = iota
	tabWallets
	tabApprovals
	tabKeys
	tabs
)

var tabNames = [tabs]string{"OVERVIEW", "WALLETS", "APPROVALS", "KEYS"}

// overlay is what covers the tab, if anything.
type overlay int

const (
	noOverlay overlay = iota
	helpOverlay
	paletteOverlay
)

// stage is where an authorization is.
type stage int

const (
	reading  stage = iota + 1 // the wallet's summary, from BeginAuthorization
	typing                    // the password, or the key's PIN
	touching                  // waiting for the key, or for the wallet
)

// authorization is an action waiting for the person: what the wallet said
// about it and how far it got.
type authorization struct {
	ch       *ipc.Challenge
	approval string // the approval it decides, which r rejects
	success  string // what to say once it is done
	stage    stage
	asking   string // "PASSWORD" or "PIN"
	secret   []byte // what is typed, never drawn
}

// Model is the view, as bubbletea runs it.
type Model struct {
	ctx     context.Context
	w       Wallet
	keys    fido.Opener
	network string
	now     func() time.Time

	width, height int

	status   *ipc.StatusReport
	policies map[string]*ipc.PolicyStatus // by wallet, when the wallet gave it

	tab       tab
	wallets   cursor
	approvals cursor
	keyList   cursor

	overlay overlay
	palette paletteState

	auth *authorization
	spin int

	note   string // what last happened
	failed bool   // whether the note is an error
}

// New returns the view before its first status.
func New(ctx context.Context, w Wallet, keys fido.Opener, network string) Model {
	return Model{ctx: ctx, w: w, keys: keys, network: network, now: time.Now}
}

// The messages of the view's commands.
type (
	tick      struct{}
	spinTick  struct{}
	statusMsg struct {
		st       *ipc.StatusReport
		policies map[string]*ipc.PolicyStatus
		err      error
	}
	challenged struct {
		auth *authorization
		err  error
	}
	done struct {
		note string
		err  error
	}
)

func (m Model) Init() tea.Cmd { return m.fetch }

// fetch asks for the status and, for each wallet, its policy with what it
// spent. A wallet that does not answer for its policy is drawn without it.
func (m Model) fetch() tea.Msg {
	st, err := m.w.Status(m.ctx)
	if err != nil {
		return statusMsg{err: err}
	}
	policies := make(map[string]*ipc.PolicyStatus, len(st.Wallets))
	for _, w := range st.Wallets {
		if ps, err := m.w.PolicyStatus(m.ctx, w.Wallet.ID); err == nil {
			policies[w.Wallet.ID] = ps
		}
	}
	return statusMsg{st: st, policies: policies}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tick:
		return m, m.fetch
	case spinTick:
		if m.auth == nil || m.auth.stage != touching {
			return m, nil
		}
		m.spin++
		return m, spinAfter()
	case statusMsg:
		if msg.err != nil {
			m.note, m.failed = msg.err.Error(), true
		} else {
			m.status, m.policies = msg.st, msg.policies
			m.wallets.clamp(len(m.status.Wallets))
			m.approvals.clamp(len(m.status.Approvals))
			m.keyList.clamp(len(m.status.Keys))
		}
		return m, tea.Tick(refresh, func(time.Time) tea.Msg { return tick{} })
	case challenged:
		if msg.err != nil {
			m.note, m.failed = msg.err.Error(), true
			return m, nil
		}
		m.auth, m.note = msg.auth, ""
		return m, nil
	case done:
		m.forget()
		m.note, m.failed = msg.note, msg.err != nil
		if msg.err != nil {
			m.note = msg.err.Error()
			// A wrong password or PIN leaves the authorization open.
			var e *ipc.Error
			if m.auth != nil && (errors.As(msg.err, &e) && e.Code == ipc.AuthFailed || errors.Is(msg.err, errKey)) {
				a := *m.auth
				a.stage, m.auth = reading, &a
				return m, m.fetch
			}
		}
		m.auth = nil
		return m, m.fetch
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	return m, nil
}

func spinAfter() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return spinTick{} })
}

// key handles what the person presses.
func (m Model) key(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	s := k.String()
	if s == "ctrl+c" {
		m.forget()
		return m, tea.Quit
	}
	if m.auth != nil {
		switch m.auth.stage {
		case typing:
			return m.typed(k)
		case touching:
			return m, nil // the key answers, or gives up, on its own
		}
	}
	switch m.overlay {
	case helpOverlay:
		m.overlay = noOverlay
		return m, nil
	case paletteOverlay:
		return m.paletteKey(k)
	}
	switch s {
	case "q":
		m.forget()
		return m, tea.Quit
	case "f":
		m.auth = nil
		return m, m.freezeAll()
	}
	if m.auth != nil {
		switch s {
		case "a":
			return m.authorize()
		case "r":
			if m.auth.approval != "" {
				return m, m.reject(m.auth.approval)
			}
		case "esc":
			m.auth = nil
		}
		return m, nil
	}
	switch s {
	case "?":
		m.overlay = helpOverlay
		return m, nil
	case ":":
		m.overlay, m.palette = paletteOverlay, paletteState{}
		return m, nil
	case "tab":
		m.tab = (m.tab + 1) % tabs
		return m, nil
	case "shift+tab":
		m.tab = (m.tab + tabs - 1) % tabs
		return m, nil
	case "esc":
		m.note, m.failed = "", false
		return m, nil
	}
	if len(s) == 1 && s[0] >= '1' && s[0] < '1'+byte(tabs) {
		m.tab = tab(s[0] - '1')
		return m, nil
	}
	return m.tabKey(s)
}

// tabKey handles the keys of the tab on show.
func (m Model) tabKey(s string) (tea.Model, tea.Cmd) {
	delta := map[string]int{"up": -1, "k": -1, "down": 1, "j": 1}[s]
	st := m.status
	if st == nil {
		return m, nil
	}
	switch m.tab {
	case tabWallets:
		m.wallets.move(delta, len(st.Wallets))
	case tabKeys:
		m.keyList.move(delta, len(st.Keys))
	case tabApprovals:
		m.approvals.move(delta, len(st.Approvals))
		if len(st.Approvals) == 0 {
			return m, nil
		}
		ap := st.Approvals[m.approvals.at]
		switch s {
		case "enter":
			return m, m.begin(ipc.ActApproveDraft, &ipc.ApproveDraft{ApprovalID: ap.ID},
				&authorization{approval: ap.ID, success: "Approved: the server sends the transaction."})
		case "r":
			return m, m.reject(ap.ID)
		}
	}
	return m, nil
}

// begin asks the wallet for the summary of an action, and opens the
// authorization with it.
func (m Model) begin(action string, params ipc.Body, a *authorization) tea.Cmd {
	return func() tea.Msg {
		ch, err := m.w.Begin(m.ctx, action, params)
		if err != nil {
			return challenged{err: err}
		}
		a.ch, a.stage = ch, reading
		return challenged{auth: a}
	}
}

func (m Model) reject(id string) tea.Cmd {
	return func() tea.Msg {
		if err := m.w.Reject(m.ctx, id); err != nil {
			return done{err: err}
		}
		return done{note: "Rejected " + id + "."}
	}
}

func (m Model) freezeAll() tea.Cmd {
	return func() tea.Msg {
		if err := m.w.FreezeAll(m.ctx); err != nil {
			return done{err: err}
		}
		return done{note: "Every wallet is frozen."}
	}
}

// authorize asks for what the authorization takes: the password, or the key
// with its PIN if the action needs it.
func (m Model) authorize() (tea.Model, tea.Cmd) {
	a := *m.auth
	m.auth = &a
	switch {
	case a.ch.Methods[0] == ipc.MethodPassword:
		a.stage, a.asking = typing, "PASSWORD"
	case a.ch.PIN:
		a.stage, a.asking = typing, "PIN"
	default:
		a.stage = touching
		return m, tea.Batch(m.touch(""), spinAfter())
	}
	return m, nil
}

// typed collects the password or the PIN without drawing it. Enter sends
// it; Esc, or Enter with nothing typed, declines.
func (m Model) typed(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	a := *m.auth
	m.auth = &a
	switch k.String() {
	case "esc":
		m.forget()
		a.stage = reading
	case "backspace":
		if len(a.secret) > 0 {
			a.secret[len(a.secret)-1] = 0
			a.secret = a.secret[:len(a.secret)-1]
		}
	case "enter":
		if len(a.secret) == 0 {
			a.stage = reading
			return m, nil
		}
		secret := model.Secret(append([]byte(nil), a.secret...))
		m.forget()
		a.stage = touching // nothing to touch with the password, but the wallet is working
		if a.ch.Methods[0] == ipc.MethodPassword {
			ch, success := a.ch, a.success
			return m, tea.Batch(func() tea.Msg {
				defer clear(secret)
				return finished(m.w.Complete(m.ctx, &ipc.CompleteAuthorization{AuthID: ch.AuthID, Password: secret}), success)
			}, spinAfter())
		}
		pin := string(secret)
		clear(secret)
		return m, tea.Batch(m.touch(pin), spinAfter())
	default:
		a.secret = append(a.secret, k.Text...)
	}
	return m, nil
}

// errKey marks what the key refused, which leaves the authorization open.
var errKey = errors.New("the security key refused")

// touch waits for a registered key until the authorization expires, has it
// sign, and completes the authorization with its assertion.
func (m Model) touch(pin string) tea.Cmd {
	ch, success := m.auth.ch, m.auth.success
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
		return finished(m.w.Complete(m.ctx, &ipc.CompleteAuthorization{AuthID: ch.AuthID,
			Assertion: &ipc.Assertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, Signature: a.Signature}}), success)
	}
}

func finished(err error, success string) tea.Msg {
	if err != nil {
		return done{err: err}
	}
	return done{note: success}
}

// forget wipes what was typed.
func (m *Model) forget() {
	if m.auth != nil {
		clear(m.auth.secret)
		m.auth.secret = nil
	}
}

// visible keeps what a terminal shows as text and puts "?" for anything
// else: the view never writes a control sequence it did not make.
func visible(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || unicode.IsGraphic(r) && !unicode.IsSpace(r) {
			return r
		}
		return '?'
	}, s)
}

func clock(unix int64) string { return time.Unix(unix, 0).Format(time.TimeOnly) }

// ada writes lovelace as ADA with six decimals, as the wallet's summaries do.
func ada(lovelace uint64) string {
	return fmt.Sprintf("%d.%06d ADA", lovelace/1_000_000, lovelace%1_000_000)
}

// adaShort writes lovelace as ADA with two decimals and thousands, for the
// columns.
func adaShort(lovelace uint64) string {
	whole := fmt.Sprint(lovelace / 1_000_000)
	var b strings.Builder
	for i, r := range whole {
		if i > 0 && (len(whole)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return fmt.Sprintf("%s.%02d", b.String(), lovelace%1_000_000/10_000)
}
