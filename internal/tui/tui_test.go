// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"context"
	"flag"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/test/softkey"
)

var update = flag.Bool("update", false, "write the snapshots of testdata again")

func TestMain(m *testing.M) {
	// The view writes times in the local zone; the snapshots are in UTC.
	time.Local = time.UTC
	os.Exit(m.Run())
}

// fakeWallet answers as the wallet would, and keeps what it was asked.
type fakeWallet struct {
	mu        sync.Mutex
	st        *ipc.StatusReport
	policies  map[string]*ipc.PolicyStatus
	ch        *ipc.Challenge
	completed []*ipc.CompleteAuthorization
	rejected  []string
	frozen    int
	refuse    error // what Complete answers
}

func (f *fakeWallet) Status(context.Context) (*ipc.StatusReport, error) { return f.st, nil }
func (f *fakeWallet) PolicyStatus(_ context.Context, id string) (*ipc.PolicyStatus, error) {
	if ps, ok := f.policies[id]; ok {
		return ps, nil
	}
	return nil, &ipc.Error{Code: ipc.NotFound}
}
func (f *fakeWallet) Begin(context.Context, string, ipc.Body) (*ipc.Challenge, error) {
	return f.ch, nil
}
func (f *fakeWallet) Complete(_ context.Context, c *ipc.CompleteAuthorization) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *c
	cp.Password = append([]byte(nil), c.Password...)
	f.completed = append(f.completed, &cp)
	return f.refuse
}
func (f *fakeWallet) Reject(_ context.Context, id string) error {
	f.rejected = append(f.rejected, id)
	return nil
}
func (f *fakeWallet) FreezeAll(context.Context) error { f.frozen++; return nil }

const (
	approvalID = "ap_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	walletA    = "w_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	walletB    = "w_bbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// at is the view's clock in the tests and the snapshots.
var at = time.Date(2026, 10, 28, 14, 32, 8, 0, time.UTC)

func newFake(method string) *fakeWallet {
	exp := at.Add(5 * time.Minute).Unix()
	limits := ipc.Limits{PerTx: 350_000_000, PerHour: 10_000_000_000, PerDay: 10_000_000_000, Budget: 20_000_000_000,
		MaxFee: 2_000_000, TxPerHour: 1000, NewDestinationsPerHour: 1000, NewDestinationsPerDay: 2000}
	return &fakeWallet{
		st: &ipc.StatusReport{Unlocked: true,
			Wallets: []ipc.WalletStatus{
				{Wallet: ipc.Wallet{ID: walletA, Label: "agente", Mode: "C", CreatedBy: "agent", Address: make([]byte, 57)},
					Session: &ipc.Session{ExpiresAt: at.Add(38 * time.Minute).Unix(), Remaining: 40_000_000}, OpenDestinations: true},
				{Wallet: ipc.Wallet{ID: walletB, Label: "nueva2", Mode: "B", CreatedBy: "person", Address: make([]byte, 57), Frozen: true}},
			},
			Approvals: []ipc.Approval{{ID: approvalID, WalletID: walletB, Spend: ipc.Spend{Lovelace: 4_000_000}, ExpiresAt: exp}},
			Keys:      []ipc.KeyInfo{{Name: "YubiKey 5C", Alg: -8, Added: at.Add(-6 * 24 * time.Hour).Unix()}}},
		policies: map[string]*ipc.PolicyStatus{
			walletA: {Mode: "C", Policy: ipc.Policy{Networks: []string{"preprod"}, Limits: limits, Destinations: ipc.Destinations{Any: true}},
				SpentHour: 120_000_000, SpentDay: 7_400_000_000, TxHour: 3, BudgetRemaining: 1_100_000_000},
		},
		ch: &ipc.Challenge{AuthID: make([]byte, 16), Summary: []string{"Pay 4.000000 ADA to addr_test1qz..."}, Methods: []string{method},
			ExpiresAt: exp, RPID: "mcpcardano", ClientDataHash: make([]byte, 32)},
	}
}

// drive feeds a message to the view and runs what it asks for, but for the
// ticks that wait for the next refresh or turn the spinner.
func drive(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	queue := []tea.Msg{msg}
	for len(queue) > 0 {
		msg, queue = queue[0], queue[1:]
		if msg == nil {
			continue
		}
		if batch, ok := msg.(tea.BatchMsg); ok {
			for _, cmd := range batch {
				queue = append(queue, run(cmd))
			}
			continue
		}
		next, cmd := m.Update(msg)
		m = next.(Model)
		queue = append(queue, run(cmd))
	}
	return m
}

// run runs a command, giving up on the ticks.
func run(cmd tea.Cmd) tea.Msg {
	if cmd == nil {
		return nil
	}
	out := make(chan tea.Msg, 1)
	go func() { out <- cmd() }()
	select {
	case msg := <-out:
		switch msg.(type) {
		case tick, spinTick, tea.QuitMsg:
			return nil
		}
		return msg
	case <-time.After(300 * time.Millisecond):
		return nil
	}
}

func press(t *testing.T, m Model, keys ...string) Model {
	t.Helper()
	for _, k := range keys {
		var msg tea.KeyPressMsg
		switch k {
		case "enter":
			msg = tea.KeyPressMsg{Code: tea.KeyEnter}
		case "esc":
			msg = tea.KeyPressMsg{Code: tea.KeyEscape}
		case "backspace":
			msg = tea.KeyPressMsg{Code: tea.KeyBackspace}
		case "down":
			msg = tea.KeyPressMsg{Code: tea.KeyDown}
		case "tab":
			msg = tea.KeyPressMsg{Code: tea.KeyTab}
		default:
			msg = tea.KeyPressMsg{Code: []rune(k)[0], Text: k}
		}
		m = drive(t, m, msg)
	}
	return m
}

func start(t *testing.T, f *fakeWallet, slot *softkey.Slot) Model {
	m := New(context.Background(), f, slot.Open, "preprod")
	m.now = func() time.Time { return at }
	m = drive(t, m, tea.WindowSizeMsg{Width: 110, Height: 32})
	return drive(t, m, m.Init()())
}

// plain is what the view draws, without its colours.
func plain(m Model) string { return ansi.Strip(m.render()) }

// TestApproveWithPassword: the summary is the wallet's, the password is
// never drawn, it goes to the wallet once and is wiped.
func TestApproveWithPassword(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := press(t, start(t, f, &softkey.Slot{}), "3")
	if v := plain(m); !strings.Contains(v, approvalID) || !strings.Contains(v, "4.000000 ADA") || !strings.Contains(v, "NUEVA2") {
		t.Fatalf("the approvals:\n%s", v)
	}
	m = press(t, m, "enter")
	if v := plain(m); !strings.Contains(v, "Pay 4.000000 ADA to addr_test1qz...") || !strings.Contains(v, "AUTHORIZE WITH  PASSWORD") {
		t.Fatalf("the summary:\n%s", v)
	}
	m = press(t, m, "a", "s", "e", "c", "r", "x", "backspace", "e", "t")
	if v := plain(m); strings.Contains(v, "secret") || !strings.Contains(v, "PASSWORD  ••••••") {
		t.Fatalf("while typing:\n%s", v)
	}
	m = press(t, m, "enter")
	if len(f.completed) != 1 || string(f.completed[0].Password) != "secret" || f.completed[0].Assertion != nil {
		t.Fatalf("completed %+v", f.completed)
	}
	if m.auth != nil || !strings.Contains(plain(m), "Approved") {
		t.Errorf("after approving:\n%s", plain(m))
	}
}

// TestWrongPassword: the authorization stays open, and Esc and an empty
// answer decline without asking the wallet.
func TestWrongPassword(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.refuse = &ipc.Error{Code: ipc.AuthFailed, Detail: "wrong password"}
	m := press(t, start(t, f, &softkey.Slot{}), "3", "enter", "a", "x", "enter")
	if m.auth == nil || m.auth.stage != reading || !strings.Contains(plain(m), "ERROR ◤ ipc: AUTH_FAILED: wrong password") {
		t.Errorf("after a wrong password:\n%s", plain(m))
	}
	m = press(t, m, "a", "y", "esc", "a", "enter")
	if len(f.completed) != 1 || m.auth == nil || m.auth.stage != reading {
		t.Errorf("declined: %d completions", len(f.completed))
	}
	m = press(t, m, "esc")
	if m.auth != nil {
		t.Error("esc did not close the authorization")
	}
}

// TestApproveWithKey: with a key registered, the view waits for one and
// sends its assertion; with the PIN when the action takes it.
func TestApproveWithKey(t *testing.T) {
	f := newFake(ipc.MethodKey)
	key := softkey.New("YubiKey", "1234")
	f.ch.Credentials = [][]byte{key.Credential.CredentialID()}
	slot := &softkey.Slot{}
	slot.Insert(key)
	m := press(t, start(t, f, slot), "3", "enter")
	if !strings.Contains(plain(m), "AUTHORIZE WITH  TOUCH OF A REGISTERED KEY") {
		t.Fatalf("the summary:\n%s", plain(m))
	}
	m = press(t, m, "a")
	if len(f.completed) != 1 || f.completed[0].Password != nil || f.completed[0].Assertion == nil {
		t.Fatalf("completed %+v", f.completed)
	}

	f.ch.PIN = true
	m = press(t, m, "enter", "a", "1", "2", "3", "4", "enter")
	if len(f.completed) != 2 || key.Retries != 8 {
		t.Errorf("with the PIN: %d completions, %d tries left", len(f.completed), key.Retries)
	}
	m = press(t, m, "enter", "a", "0", "0", "0", "0", "enter")
	if len(f.completed) != 2 || m.auth == nil || m.auth.stage != reading || !strings.Contains(plain(m), "PIN was wrong") {
		t.Errorf("a wrong PIN: %d completions\n%s", len(f.completed), plain(m))
	}
}

// TestNoKey: with no key inserted, the view says so once the authorization
// expires.
func TestNoKey(t *testing.T) {
	f := newFake(ipc.MethodKey)
	f.ch.ExpiresAt = time.Now().Add(time.Second).Unix()
	f.ch.Credentials = [][]byte{{1}}
	m := press(t, start(t, f, &softkey.Slot{}), "3", "enter")
	next, cmd := m.Update(tea.KeyPressMsg{Code: 'a', Text: "a"})
	if !strings.Contains(plain(next.(Model)), "INSERT AND TOUCH A REGISTERED SECURITY KEY") {
		t.Errorf("while waiting:\n%s", plain(next.(Model)))
	}
	for _, c := range cmd().(tea.BatchMsg) {
		if msg := c(); msg != nil {
			if _, spin := msg.(spinTick); !spin {
				m = drive(t, next.(Model), msg)
			}
		}
	}
	if !strings.Contains(plain(m), "no security key was inserted") || len(f.completed) != 0 {
		t.Errorf("after the wait:\n%s", plain(m))
	}
}

// TestRejectAndFreeze: rejecting and freezing take no authorization.
func TestRejectAndFreeze(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := press(t, start(t, f, &softkey.Slot{}), "3", "r", "f")
	if len(f.rejected) != 1 || f.rejected[0] != approvalID || f.frozen != 1 || !strings.Contains(plain(m), "Every wallet is frozen") {
		t.Errorf("rejected %v, frozen %d\n%s", f.rejected, f.frozen, plain(m))
	}
	if _, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"}); cmd == nil || cmd() != tea.Quit() {
		t.Error("q does not quit")
	}
}

// TestOneRefresh: the status after an action asks for no refresh of its
// own; only the refresh does, so one chain of it runs however many actions
// the person takes.
func TestOneRefresh(t *testing.T) {
	m := start(t, newFake(ipc.MethodPassword), &softkey.Slot{})
	next, cmd := m.Update(tea.KeyPressMsg{Code: 'f', Text: "f"})
	next, cmd = next.Update(cmd()) // done, which asks for the status
	if _, cmd = next.Update(cmd()); cmd != nil {
		t.Error("the status after an action asked for another refresh")
	}
	if _, cmd = next.Update(m.poll()); cmd == nil {
		t.Error("the refresh did not ask for the next one")
	}
}

// TestPalette: the palette filters as the person types, and runs what is
// chosen; q there is text, not quitting.
func TestPalette(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := press(t, start(t, f, &softkey.Slot{}), ":", "q", "u")
	if v := plain(m); !strings.Contains(v, "Quit") || strings.Contains(v, "Freeze every wallet") {
		t.Fatalf("filtered by \"qu\":\n%s", v)
	}
	m = press(t, m, "backspace", "backspace", "f", "r", "e", "e", "z", "e", "enter")
	if f.frozen != 1 || m.overlay != noOverlay {
		t.Errorf("frozen %d, overlay %d", f.frozen, m.overlay)
	}
	m = press(t, m, ":", "k", "e", "y", "enter")
	if m.tab != tabKeys {
		t.Errorf("the palette did not go to the keys: tab %d", m.tab)
	}
}

// sgr matches the colour sequences lipgloss writes, the only ones the view
// may write.
var sgr = regexp.MustCompile("\x1b\\[[0-9;:]*m")

// TestVisible: what the view draws has no control sequence but its own
// colours, whatever the wallet or a key sent.
func TestVisible(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.st.Wallets[0].Wallet.Label = "evil\x1b[2J\x1b]0;owned\x07"
	f.st.Keys[0].Name = "key\x1b[31m\u202e"
	f.ch.Summary = []string{"bidi \u202egnp.exe", "bell\x07"}
	m := start(t, f, &softkey.Slot{})
	var views []string
	for _, k := range []string{"1", "2", "4", "3", "enter"} {
		m = press(t, m, k)
		views = append(views, m.render())
	}
	all := strings.Join(views, "\n")
	bare := sgr.ReplaceAllString(all, "")
	for _, bad := range []string{"\x1b", "\x07", "\u202e"} {
		if strings.Contains(bare, bad) {
			t.Errorf("the view draws %q", bad)
		}
	}
	if !strings.Contains(bare, "EVIL?[2J?]0;OW") || !strings.Contains(bare, "bidi ?gnp.exe") || !strings.Contains(bare, "key?[31m?") {
		t.Errorf("views:\n%s", ansi.Strip(all))
	}
}

// TestSnapshots compares each tab with its snapshot in testdata, without
// colours; go test -run Snapshots -update writes them again.
func TestSnapshots(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := start(t, f, &softkey.Slot{})
	for _, c := range []struct{ name, keys string }{
		{"overview", "1"}, {"wallets", "2"}, {"approvals", "3"}, {"keys", "4"}, {"authorize", "3\n"}, {"help", "?"}, {"palette", ":"},
	} {
		v := m
		for _, k := range strings.Split(c.keys, "") {
			if k == "\n" {
				k = "enter"
			}
			v = press(t, v, k)
		}
		got := plain(v)
		path := filepath.Join("testdata", c.name+".golden")
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s differs from %s:\n%s", c.name, path, got)
		}
	}
}

// TestMainnet: on mainnet the network is a badge in the colour of danger.
func TestMainnet(t *testing.T) {
	m := start(t, newFake(ipc.MethodPassword), &softkey.Slot{})
	m.network = "mainnet"
	if v := plain(m); !strings.Contains(v, "MAINNET ◤") {
		t.Errorf("mainnet:\n%s", v)
	}
}

// TestContrast: every colour of text reaches 4.5:1 against the background
// and the dialogs' panel (WCAG 2.1, AA).
func TestContrast(t *testing.T) {
	lum := func(hex string) float64 {
		var rgb [3]float64
		for i := range rgb {
			var v int
			for _, c := range hex[1+2*i : 3+2*i] {
				v = v*16 + strings.IndexRune("0123456789ABCDEF", c)
			}
			c := float64(v) / 255
			if c <= 0.03928 {
				rgb[i] = c / 12.92
			} else {
				rgb[i] = math.Pow((c+0.055)/1.055, 2.4)
			}
		}
		return 0.2126*rgb[0] + 0.7152*rgb[1] + 0.0722*rgb[2]
	}
	ratio := func(a, b string) float64 {
		la, lb := lum(a), lum(b)
		return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)
	}
	hexOf := func(c interface{ RGBA() (r, g, b, a uint32) }) string {
		r, g, b, _ := c.RGBA()
		const digits = "0123456789ABCDEF"
		out := []byte{'#'}
		for _, v := range []uint32{r >> 8, g >> 8, b >> 8} {
			out = append(out, digits[v>>4], digits[v&15])
		}
		return string(out)
	}
	for name, c := range map[string]interface{ RGBA() (r, g, b, a uint32) }{
		"text": cText, "dim": cDim, "yellow": cYellow, "cyan": cCyan, "red": cRed,
		"hud": cHUD, "green": cGreen, "orange": cOrange, "magenta": cMagenta,
	} {
		for bgName, bg := range map[string]interface{ RGBA() (r, g, b, a uint32) }{"background": cBg, "panel": cPanel} {
			if r := ratio(hexOf(c), hexOf(bg)); r < 4.5 {
				t.Errorf("%s on the %s: %.2f:1", name, bgName, r)
			}
		}
	}
	// The badges and the selection: black on their colour.
	for name, c := range map[string]interface{ RGBA() (r, g, b, a uint32) }{"cyan": cCyan, "red": cRed, "hud": cHUD, "magenta": cMagenta, "yellow": cYellow} {
		if r := ratio("#000000", hexOf(c)); r < 4.5 {
			t.Errorf("black on %s: %.2f:1", name, r)
		}
	}
}
