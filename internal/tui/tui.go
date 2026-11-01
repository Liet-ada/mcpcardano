// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package tui is the interactive view of the CLI (section 6.4; decisions
// 125, 126 and 142): the wallet as it changes, its wallets with their limits
// and what they spent, the approvals as they arrive with the summary the
// wallet computed, approving or rejecting them with a registered key's touch
// or the password, what the person does on a wallet, the security keys, and
// freezing every wallet with one key. It talks only to the wallet's admin
// socket, through Wallet, and opens no port. Every text it draws goes through
// visible first.
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

	"github.com/Liet-ada/mcpcardano/internal/actions"
	"github.com/Liet-ada/mcpcardano/internal/doctor"
	"github.com/Liet-ada/mcpcardano/internal/fido"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Wallet is what the view asks of the wallet's admin socket.
type Wallet interface {
	Status(ctx context.Context) (*ipc.StatusReport, error)
	PolicyStatus(ctx context.Context, walletID string) (*ipc.PolicyStatus, error)
	Begin(ctx context.Context, action string, params ipc.Body) (*ipc.Challenge, error)
	// Complete returns the action's result, which the caller wipes: it may
	// carry a recovery phrase.
	Complete(ctx context.Context, c *ipc.CompleteAuthorization) ([]byte, error)
	Reject(ctx context.Context, approvalID string) error
	// Freeze freezes a wallet, or every wallet if walletID is empty.
	Freeze(ctx context.Context, walletID string) error
	CloseSession(ctx context.Context, walletID string) error
	// Expired lists a wallet's expired_unconfirmed entries (section 9.2).
	Expired(ctx context.Context, walletID string) ([]ipc.Expired, error)
	ShowPolicy(ctx context.Context, walletID string) (*ipc.WalletPolicy, error)
	ShowTemplate(ctx context.Context) (*ipc.Template, error)
	Unlock(ctx context.Context, password []byte) error
	ShowAudit(ctx context.Context, from uint64, limit uint32) (*ipc.AuditPage, error)
	VerifyAudit(ctx context.Context) (*ipc.AuditCheck, error)
}

// refresh is how often the view asks for the status.
const refresh = 2 * time.Second

// Run shows the view on a terminal until the person quits.
func Run(ctx context.Context, w Wallet, keys fido.Opener, network string, check Doctor, in io.Reader, out io.Writer) error {
	m := New(ctx, w, keys, network)
	m.doctor = check
	p := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out))
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
	tabAudit
	tabSystem
	tabs
)

var tabNames = [tabs]string{"OVERVIEW", "WALLETS", "APPROVALS", "KEYS", "AUDIT", "SYSTEM"}

// overlay is what covers the tab, if anything.
type overlay int

const (
	noOverlay overlay = iota
	helpOverlay
	paletteOverlay
	formOverlay
	budgetOverlay
	restoreOverlay
	phraseOverlay
	editorOverlay
	keyOverlay
	unlockOverlay
	filterOverlay
	detailOverlay
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
	title    string // what it is about, for the dialog
	approval string // the approval it decides, which r rejects
	stage    stage
	finish   func(result []byte) done // what comes of the wallet's result
	changes  []change                 // from the editor, shown above the summary
	warnings []string
	asking   string // "PASSWORD" or "PIN"
	secret   []byte // what is typed, never drawn
}

// Model is the view, as bubbletea runs it.
type Model struct {
	ctx     context.Context
	w       Wallet
	keys    fido.Opener
	network string
	doctor  Doctor
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
	form    *form
	budget  *budget
	restore *restore
	phrase  *phrase
	editor  *editor
	adding  *keyAdding
	unlock  *unlocking

	unlockSkipped bool // the person chose to see the wallet locked
	audit         auditLog
	sys           system

	auth   *authorization
	scroll int // how far the dialog of the authorization was read
	spin   int

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
		poll     bool // from the refresh, which then waits for the next
		st       *ipc.StatusReport
		policies map[string]*ipc.PolicyStatus
		err      error
	}
	challenged struct {
		auth *authorization
		err  error
	}
	done struct {
		note   string
		err    error
		phrase *phrase // the screen to open with it
	}
	expiredMsg struct {
		wallet  ipc.Wallet
		entries []ipc.Expired
		err     error
	}
	editorMsg struct {
		editor *editor
		err    error
	}
	keyOpened struct {
		adding *keyAdding // whom it answers
		key    fido.Key
		info   fido.Info
		err    error
	}
	keyRegistered struct {
		adding *keyAdding
		data   []byte
		err    error
	}
	unlocked    struct{ err error }
	auditLoaded struct {
		check *ipc.AuditCheck
		lines []actions.AuditEntry
		older bool
		err   error
	}
	doctorDone struct {
		report doctor.Report
		err    error
	}
	phraseTick struct{}
)

func (m Model) Init() tea.Cmd { return m.poll }

// poll is the refresh: one chain of it runs, every refresh, for as long as
// the view does. An action asks for the status with fetch, out of the chain.
func (m Model) poll() tea.Msg {
	msg := m.fetch().(statusMsg)
	msg.poll = true
	return msg
}

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
		return m, m.poll
	case spinTick:
		waiting := m.auth != nil && m.auth.stage == touching
		waiting = waiting || m.adding != nil && m.adding.stage == addInsert || m.unlock != nil && m.unlock.busy
		if !waiting {
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
			if m.status.Unlocked {
				m.unlockSkipped = false
			} else if !m.unlockSkipped && m.overlay == noOverlay && m.auth == nil {
				m.overlay, m.unlock = unlockOverlay, &unlocking{}
			}
		}
		if !msg.poll {
			return m, nil
		}
		return m, tea.Tick(refresh, func(time.Time) tea.Msg { return tick{} })
	case challenged:
		if msg.err != nil {
			m.note, m.failed = msg.err.Error(), true
			return m, nil
		}
		if m.overlay != editorOverlay { // the editor stays, to go back to it
			m.close()
		}
		m.auth, m.note, m.failed, m.scroll = msg.auth, "", false, 0
		return m, nil
	case editorMsg:
		if msg.err != nil {
			return m.refuse(msg.err.Error())
		}
		m.overlay, m.editor = editorOverlay, msg.editor
		return m, nil
	case expiredMsg:
		return m.expiredList(msg)
	case keyOpened:
		return m.keyOpen(msg)
	case keyRegistered:
		return m.keyMade(msg)
	case unlocked:
		if m.unlock == nil {
			return m, nil
		}
		if msg.err != nil {
			m.unlock.busy = false
			return m.refuse(msg.err.Error())
		}
		m.close()
		m.note, m.failed = "The wallet is unlocked.", false
		return m, m.fetch
	case auditLoaded:
		return m.auditArrived(msg)
	case doctorDone:
		m.sys.busy = false
		if msg.err != nil {
			return m.refuse(msg.err.Error())
		}
		m.sys.report, m.sys.ran, m.sys.scroll = msg.report, true, 0
		return m, nil
	case phraseTick:
		return m.phraseTimer()
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
		if msg.err == nil && m.overlay == editorOverlay {
			m.close()
		}
		if msg.phrase != nil {
			return m.showPhrase(msg.phrase)
		}
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
		m.close()
		return m, tea.Quit
	}
	// What went well was read once a key is pressed; an error stays until
	// esc.
	if !m.failed {
		m.note = ""
	}
	if m.auth != nil {
		switch m.auth.stage {
		case typing:
			return m.typed(k)
		case touching:
			return m, nil // the key answers, or gives up, on its own
		}
	}
	if m.auth == nil {
		switch m.overlay {
		case helpOverlay:
			m.overlay = noOverlay
			return m, nil
		case paletteOverlay:
			return m.paletteKey(k)
		case formOverlay:
			return m.formKey(k)
		case editorOverlay:
			return m.editorKey(k)
		case keyOverlay:
			return m.keyAddKey(k)
		case unlockOverlay:
			return m.unlockKey(k)
		case filterOverlay:
			return m.filterKey(k)
		case detailOverlay:
			m.overlay, m.audit.detail = noOverlay, nil
			return m, nil
		case restoreOverlay:
			return m.restoreKey(k)
		case budgetOverlay:
			if s != "q" && s != "f" {
				return m.budgetKey(s)
			}
		case phraseOverlay:
			m.phrase.until = m.now().Add(phraseIdle)
			if s != "q" && s != "f" {
				return m.phraseKey(s)
			}
		}
	}
	switch s {
	case "q":
		m.forget()
		m.close()
		return m, tea.Quit
	case "f":
		m.auth = nil
		m.close()
		return m, m.freeze("")
	}
	if m.auth != nil {
		switch s {
		case "a":
			return m.authorize()
		case "r":
			if m.auth.approval != "" {
				return m, m.reject(m.auth.approval)
			}
		case "up":
			m.scroll = max(m.scroll-1, 0)
		case "down":
			m.scroll = min(m.scroll+1, m.authOverflow())
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
		return m.show((m.tab + 1) % tabs)
	case "shift+tab":
		return m.show((m.tab + tabs - 1) % tabs)
	case "esc":
		m.note, m.failed = "", false
		return m, nil
	}
	if len(s) == 1 && s[0] >= '1' && s[0] < '1'+byte(tabs) {
		return m.show(tab(s[0] - '1'))
	}
	return m.tabKey(s)
}

// show goes to a tab. The audit tab reads the log as it opens.
func (m Model) show(t tab) (Model, tea.Cmd) {
	m.tab = t
	if t == tabAudit && !m.audit.busy {
		m.audit.busy = true
		return m, m.loadAudit()
	}
	return m, nil
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
		switch s {
		case "c":
			return m.createForm()
		case "R":
			return m.restoreForm()
		}
		if len(st.Wallets) == 0 {
			return m, nil
		}
		ws := st.Wallets[m.wallets.at]
		switch s {
		case "u":
			return m.unfreeze(ws)
		case "F":
			return m, m.freeze(ws.Wallet.ID)
		case "s":
			if ws.Session != nil {
				return m.closeSession(ws)
			}
			return m.sessionForm(ws)
		case "b":
			return m, m.expired(ws.Wallet)
		case "e":
			return m.editPolicy(ws)
		case "p":
			return m.askPhrase(ws)
		}
	case tabKeys:
		m.keyList.move(delta, len(st.Keys))
		switch {
		case s == "a":
			return m.addKeyForm()
		case s == "d" && len(st.Keys) > 0:
			return m.removeKey(st.Keys[m.keyList.at])
		}
	case tabAudit:
		return m.auditKey(s, delta)
	case tabSystem:
		return m.systemKey(s, delta)
	case tabApprovals:
		m.approvals.move(delta, len(st.Approvals))
		if len(st.Approvals) == 0 {
			return m, nil
		}
		ap := st.Approvals[m.approvals.at]
		switch s {
		case "enter":
			return m, m.begin(actions.ApproveDraft(ap.ID),
				&authorization{title: ap.ID, approval: ap.ID, finish: say("Approved: the server sends the transaction.")})
		case "r":
			return m, m.reject(ap.ID)
		}
	}
	return m, nil
}

// begin asks the wallet for the summary of an action, and opens the
// authorization with it.
func (m Model) begin(act actions.Action, a *authorization) tea.Cmd {
	return func() tea.Msg {
		if p, ok := act.Params.(*ipc.RestoreWallet); ok {
			defer p.Wipe() // the wallet holds it from here on
		}
		ch, err := m.w.Begin(m.ctx, act.Name, act.Params)
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

// freeze freezes a wallet, or every wallet if walletID is empty: it
// reduces the risk, so it takes no authorization.
func (m Model) freeze(walletID string) tea.Cmd {
	note := "Every wallet is frozen."
	if walletID != "" {
		note = "Wallet " + m.walletName(walletID) + " is frozen."
	}
	return func() tea.Msg {
		if err := m.w.Freeze(m.ctx, walletID); err != nil {
			return done{err: err}
		}
		return done{note: note}
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
			ch, finish := a.ch, a.finish
			return m, tea.Batch(func() tea.Msg {
				defer clear(secret)
				result, err := m.w.Complete(m.ctx, &ipc.CompleteAuthorization{AuthID: ch.AuthID, Password: secret})
				return finished(result, err, finish)
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
	ch, finish := m.auth.ch, m.auth.finish
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
		result, err := m.w.Complete(m.ctx, &ipc.CompleteAuthorization{AuthID: ch.AuthID,
			Assertion: &ipc.Assertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, Signature: a.Signature}})
		return finished(result, err, finish)
	}
}

// finished is what comes of a completed authorization. The result goes no
// further than finish, which keeps what it needs.
func finished(result []byte, err error, finish func([]byte) done) tea.Msg {
	defer clear(result)
	if err != nil {
		return done{err: err}
	}
	return finish(result)
}

// say is the finish of an action whose result says nothing new.
func say(note string) func([]byte) done {
	return func([]byte) done { return done{note: note} }
}

// decoded is the finish of an action with a result: then gets it decoded
// into body.
func decoded[B ipc.Body](body B, then func(B) done) func([]byte) done {
	return func(result []byte) done {
		if err := ipc.NewCodec().DecodeBody(result, body); err != nil {
			return done{err: err}
		}
		return then(body)
	}
}

// forget wipes what was typed.
func (m *Model) forget() {
	if m.auth != nil {
		clear(m.auth.secret)
		m.auth.secret = nil
	}
}

// close uncovers the tab, and wipes what the overlay held.
func (m *Model) close() {
	if m.restore != nil {
		m.restore.typed.Wipe()
	}
	if m.phrase != nil {
		m.phrase.words.Wipe()
	}
	if m.adding != nil {
		m.adding.stop()
	}
	if m.unlock != nil {
		clear(m.unlock.secret)
	}
	m.form, m.budget, m.restore, m.phrase, m.editor, m.adding, m.unlock = nil, nil, nil, nil, nil, nil, nil
	m.overlay = noOverlay
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
