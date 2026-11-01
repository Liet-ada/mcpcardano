// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"slices"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/test/softkey"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

// rowName is the text a row starts with, to find it.
func rowName(m Model, r row) string {
	e := m.editor
	f, _ := e.edited()
	line := strings.TrimSpace(ansi.Strip(e.line(r, false, &f, nil)))
	return strings.TrimLeft(line, "▸▾ ")
}

// goToRow moves the cursor to the row that starts with name, a field before
// a section of the same name.
func goToRow(t *testing.T, m Model, name string) Model {
	t.Helper()
	found := -1
	for i, r := range m.editor.rows() {
		if strings.HasPrefix(rowName(m, r), name) && (found < 0 || r.kind != rowHead) {
			found = i
		}
	}
	if found >= 0 {
		m.editor.at.at = found
		return m
	}
	t.Fatalf("no row %q:\n%s", name, plain(m))
	return m
}

// onRow goes to rows by name and presses other keys, in order.
func onRow(t *testing.T, m Model, steps ...string) Model {
	t.Helper()
	for _, s := range steps {
		if s == "enter" {
			m = press(t, m, s)
		} else {
			m = goToRow(t, m, s)
		}
	}
	return m
}

// rewrite replaces what the chosen number says.
func rewrite(t *testing.T, m Model, text string) Model {
	t.Helper()
	m = press(t, m, strings.Split(strings.Repeat("\b", 20), "")...)
	return press(t, m, strings.Split(text, "")...)
}

func openEditor(t *testing.T, f *fakeWallet) Model {
	t.Helper()
	return press(t, start(t, f, &softkey.Slot{}), "2", "e")
}

// TestEditorMarks: each change says which way it moves the policy, in the
// field and on its closed section.
func TestEditorMarks(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := openEditor(t, f)
	if v := plain(m); !strings.Contains(v, "POLICY OF AGENTE") || !strings.Contains(v, "[ 350.000000▌ ] ADA") {
		t.Fatalf("the editor:\n%s", v)
	}
	m = rewrite(t, goToRow(t, m, "PER TRANSACTION"), "60")
	if v := plain(m); !strings.Contains(v, "was 350.000000  ↓ tighter") {
		t.Fatalf("lowering a limit:\n%s", v)
	}
	m = rewrite(t, m, "400.5")
	if v := plain(m); !strings.Contains(v, "was 350.000000  ↑ looser") {
		t.Fatalf("raising a limit:\n%s", v)
	}
	m = rewrite(t, m, "350")
	if v := plain(m); strings.Contains(v, "was 350") {
		t.Fatalf("the same value is no change:\n%s", v)
	}
	m = rewrite(t, m, "400")
	m = onRow(t, m, "UTXO", "enter", "DUST BELOW")
	m = rewrite(t, m, "3")
	if v := plain(m); !strings.Contains(v, "was 0.000000  ← changed") {
		t.Fatalf("what steers the wallet is neither:\n%s", v)
	}
	m = onRow(t, m, "LIMITS", "enter")
	if v := plain(m); !strings.Contains(v, "400.00 per tx") || !strings.Contains(v, "↑ looser 1") {
		t.Errorf("a closed section:\n%s", v)
	}
	m = onRow(t, m, "STRUCTURE", "enter", "MINT", "enter")
	if v := plain(m); !strings.Contains(v, "was no  ↑ looser") {
		t.Errorf("allowing mint:\n%s", v)
	}
	m = onRow(t, m, "MODE", "enter", "SESSION REQUIRED", "enter")
	if v := plain(m); !strings.Contains(v, "was no  ↓ tighter") {
		t.Errorf("requiring a session:\n%s", v)
	}
	m = onRow(t, m, "MODE", "enter")
	if v := plain(m); !strings.Contains(v, "was C  ↑ looser") {
		t.Errorf("changing the mode:\n%s", v)
	}
	if m = press(t, m, "esc"); m.editor != nil || m.overlay != noOverlay {
		t.Error("esc did not discard the editor")
	}
	if len(f.begun) != 0 {
		t.Errorf("the editor asked the wallet: %v", f.begun)
	}
}

// TestEditorInvalid: a field that is not a number is marked, and keeps from
// reviewing.
func TestEditorInvalid(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := rewrite(t, goToRow(t, openEditor(t, f), "PER DAY"), "1.2.3")
	if v := plain(m); !strings.Contains(v, "invalid") {
		t.Fatalf("not a number:\n%s", v)
	}
	m = press(t, m, "ctrl+r")
	if len(f.begun) != 0 || !strings.Contains(plain(m), "PER DAY is not valid") {
		t.Fatalf("reviewing: began %v\n%s", f.begun, plain(m))
	}
	m = rewrite(t, goToRow(t, m, "PER DAY"), "9999999999999999")
	if !strings.Contains(plain(m), "invalid") {
		t.Errorf("an amount too large:\n%s", plain(m))
	}
	m = rewrite(t, goToRow(t, rewrite(t, m, "10000"), "TX PER HOUR"), "4294967296")
	if !strings.Contains(plain(m), "invalid") {
		t.Errorf("a count too large:\n%s", plain(m))
	}
	m = rewrite(t, m, "1000")
	m = press(t, m, "ctrl+r")
	if len(f.begun) != 0 || !strings.Contains(plain(m), "Nothing changed.") {
		t.Errorf("no change: began %v\n%s", f.begun, plain(m))
	}
}

// TestEditorReview: the dialog puts what loosens first and the wallet's
// summary below; esc goes back to the edits, and authorizing closes them.
func TestEditorReview(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.ch.Summary = []string{"Change the policy of wallet agente to:", "Mode C"}
	f.result = encoded(t, &ipc.PolicyHash{Hash: make([]byte, 32)})
	m := openEditor(t, f)
	m = rewrite(t, m, "60")
	m = rewrite(t, goToRow(t, m, "PER HOUR"), "20000")
	m = press(t, m, "ctrl+r")
	v := plain(m)
	if !strings.Contains(v, "WHAT YOU CHANGED") || !strings.Contains(v, "WHAT THE WALLET SAYS") || !strings.Contains(v, "Change the policy of wallet agente") {
		t.Fatalf("the dialog:\n%s", v)
	}
	if strings.Index(v, "↑ looser") > strings.Index(v, "↓ tighter") || strings.Index(v, "↓ tighter") > strings.Index(v, "WHAT THE WALLET SAYS") {
		t.Errorf("the order of the dialog:\n%s", v)
	}
	if !strings.Contains(v, "PER HOUR  10000.000000 → 20000.000000") {
		t.Errorf("before and after:\n%s", v)
	}
	if p := f.params.(*ipc.WalletPolicy); p.WalletID != walletA || p.Policy.Limits.PerTx != 60_000_000 || p.Policy.Limits.PerHour != 20_000_000_000 {
		t.Fatalf("sent %+v", p)
	}
	m = press(t, m, "esc")
	if m.auth != nil || m.editor == nil || !strings.Contains(plain(m), "[ 20000▌ ] ADA") {
		t.Fatalf("esc did not go back to the edits:\n%s", plain(m))
	}
	m = press(t, m, "ctrl+r", "a", "p", "w", "enter")
	if m.editor != nil || m.overlay != noOverlay || !strings.Contains(plain(m), "Policy of wallet agente changed") {
		t.Errorf("after authorizing:\n%s", plain(m))
	}
}

// TestEditorWarnings: what forbids every payment is said in the review, as
// policy set says it.
func TestEditorWarnings(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := rewrite(t, openEditor(t, f), "0")
	m = onRow(t, m, "MODE", "enter", "PREPROD", "enter")
	m = press(t, m, "ctrl+r")
	v := plain(m)
	if !strings.Contains(v, "limits.per_tx is zero") || !strings.Contains(v, "networks does not include preprod") {
		t.Errorf("the warnings:\n%s", v)
	}
}

// TestEditorStale: the wallet takes a policy whole, so the editor reads it
// again before asking: a freeze since it opened stays, and a change since it
// opened is not overwritten.
func TestEditorStale(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	m := rewrite(t, openEditor(t, f), "60")
	f.policies[walletA].Policy.Frozen = true
	m = press(t, m, "ctrl+r")
	if p, ok := f.params.(*ipc.WalletPolicy); !ok || !p.Policy.Frozen {
		t.Fatalf("a freeze meanwhile was undone: %+v", f.params)
	}
	m = press(t, m, "esc")

	f.begun, f.params = nil, nil
	f.policies[walletA].Policy.Limits.PerDay = 1
	m = press(t, m, "ctrl+r")
	if len(f.begun) != 0 || m.auth != nil || !strings.Contains(plain(m), "The policy changed while you edited it") {
		t.Errorf("a change meanwhile: began %v\n%s", f.begun, plain(m))
	}
}

// TestEditorLists: addresses of the network are added once and removed, and
// any address drops the list; tokens are added and removed.
func TestEditorLists(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	shop := model.Address{Raw: walletkit.Address(6, 7, 0)}.Bech32()
	m := onRow(t, openEditor(t, f), "DESTINATIONS", "enter", "ANY ADDRESS", "enter", "ADD AN ADDRESS")
	if v := plain(m); !strings.Contains(v, "was yes  ↓ tighter") {
		t.Fatalf("closing the destinations:\n%s", v)
	}
	m = press(t, m, "n", "o", "enter")
	if !strings.Contains(plain(m), "not an address of preprod") {
		t.Fatalf("a bad address:\n%s", plain(m))
	}
	m = press(t, m, "backspace", "backspace")
	m = press(t, m, strings.Split(shop, "")...)
	m = press(t, m, "enter")
	if !strings.Contains(plain(m), "LISTED") {
		t.Fatalf("the address:\n%s", plain(m))
	}
	m = goToRow(t, m, "ADD AN ADDRESS")
	m = press(t, m, strings.Split(shop, "")...)
	m = press(t, m, "enter")
	if !strings.Contains(plain(m), "already listed") || len(m.editor.cur.Destinations.Allowed) != 1 {
		t.Fatalf("listed twice:\n%s", plain(m))
	}
	const id = "aabbccddeeff00112233445566778899aabbccddeeff001122334455.6d6961"
	m = onRow(t, m, "TOKENS", "enter", "ADD A TOKEN")
	m = press(t, m, strings.Split(id, "")...)
	m = press(t, m, "enter")
	if !strings.Contains(plain(m), "Write the token as") {
		t.Fatalf("no cap:\n%s", plain(m))
	}
	m = press(t, m, "space", "5", "enter")
	if m.editor.cur.Assets[id] != "5" {
		t.Fatalf("the token: %v\n%s", m.editor.cur.Assets, plain(m))
	}
	m = press(t, m, "ctrl+r")
	p := f.params.(*ipc.WalletPolicy)
	if p.Policy.Destinations.Any || len(p.Policy.Destinations.Allowed) != 1 || len(p.Policy.Assets) != 1 || p.Policy.Assets[0].Cap != 5 {
		t.Fatalf("sent %+v", p.Policy)
	}
	m = press(t, m, "esc")
	m = press(t, goToRow(t, m, "UP TO"), "x")
	if len(m.editor.cur.Assets) != 0 {
		t.Fatalf("x left the token: %v", m.editor.cur.Assets)
	}
	// With any address the list stays in the editor but not in the policy.
	m = onRow(t, m, "ANY ADDRESS", "enter")
	if strings.Contains(plain(m), "ADD AN ADDRESS") {
		t.Fatalf("the list with any address:\n%s", plain(m))
	}
	m = press(t, rewrite(t, goToRow(t, m, "PER TRANSACTION"), "1"), "ctrl+r")
	p = f.params.(*ipc.WalletPolicy)
	if !p.Policy.Destinations.Any || len(p.Policy.Destinations.Allowed) != 0 {
		t.Errorf("any with a list, which the wallet refuses: %+v", p.Policy.Destinations)
	}
	m = onRow(t, press(t, m, "esc"), "ANY ADDRESS", "enter", "LISTED")
	if m = press(t, m, "x"); len(m.editor.cur.Destinations.Allowed) != 0 {
		t.Errorf("x left the address")
	}
}

// ways are the changes on show, by name.
func ways(m Model) map[string]direction {
	f, _ := m.editor.edited()
	out := map[string]direction{}
	for _, c := range m.editor.changes(&f) {
		out[c.name] = c.way
	}
	return out
}

// TestEditorListMarks: adding to a list loosens the policy and taking from
// it tightens it, for addresses, tokens and networks; going from any address
// to a list is what tightens, and what it lists is no further loosening.
func TestEditorListMarks(t *testing.T) {
	const token = "aabbccddeeff00112233445566778899aabbccddeeff001122334455.6d6961"
	id, err := model.ParseAssetID(token)
	if err != nil {
		t.Fatal(err)
	}
	listed := walletkit.Address(6, 7, 0)
	other := model.Address{Raw: walletkit.Address(6, 9, 0)}.Bech32()
	f := newFake(ipc.MethodPassword)
	p := &f.policies[walletA].Policy
	p.Destinations = ipc.Destinations{Allowed: [][]byte{listed}}
	p.Assets = []ipc.AssetCap{{Policy: id.Policy[:], Name: []byte(id.Name), Cap: 5}}
	p.Networks = []string{"preprod", "preview"}
	m := onRow(t, openEditor(t, f), "DESTINATIONS", "enter", "ADD AN ADDRESS")
	m = press(t, m, strings.Split(other, "")...)
	m = press(t, m, "enter")
	if way, ok := ways(m)[other]; !ok || way != looser {
		t.Errorf("adding an address: %v, %v", way, ok)
	}
	before := model.Address{Raw: listed}.Bech32()
	m.editor.at.at = slices.IndexFunc(m.editor.rows(), func(r row) bool { return r.key == before })
	m = press(t, m, "x")
	if w := ways(m); len(w) != 2 || w[other] != looser || w[before] != tighter {
		t.Errorf("removing an address: %v", w)
	}
	m = onRow(t, m, "TOKENS", "enter", "ADD A TOKEN")
	m = press(t, m, strings.Split(token+" 9", "")...)
	m = press(t, m, "enter")
	if way, ok := ways(m)[token]; !ok || way != looser {
		t.Errorf("raising a cap: %v, %v", way, ok)
	}
	m = press(t, m, strings.Split(token+" 2", "")...)
	m = press(t, m, "enter")
	if way, ok := ways(m)[token]; !ok || way != tighter {
		t.Errorf("lowering a cap: %v, %v", way, ok)
	}
	m = press(t, goToRow(t, m, "UP TO"), "x")
	if way, ok := ways(m)[token]; !ok || way != tighter {
		t.Errorf("removing a token: %v, %v", way, ok)
	}
	m = goToRow(t, m, "ADD A TOKEN")
	m = press(t, m, strings.Split(strings.Replace(token, "6d6961", "6d", 1)+" 1", "")...)
	m = press(t, m, "enter")
	if way, ok := ways(m)[strings.Replace(token, "6d6961", "6d", 1)]; !ok || way != looser {
		t.Errorf("adding a token: %v, %v", way, ok)
	}
	m = onRow(t, m, "MODE", "enter", "PREVIEW", "enter", "MAINNET", "enter")
	if w := ways(m); w["PREVIEW"] != tighter || w["MAINNET"] != looser {
		t.Errorf("the networks: %v", w)
	}

	f = newFake(ipc.MethodPassword)
	m = onRow(t, openEditor(t, f), "DESTINATIONS", "enter", "ANY ADDRESS", "enter", "ADD AN ADDRESS")
	m = press(t, m, strings.Split(other, "")...)
	m = press(t, m, "enter")
	if w := ways(m); w["ANY ADDRESS"] != tighter || w[other] != changed {
		t.Errorf("from any address to a list: %v", w)
	}
}

// TestEditorModeA: those policies live in the server's config.json.
func TestEditorModeA(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	f.policies[walletA].Mode = "A"
	m := openEditor(t, f)
	if m.editor != nil || !strings.Contains(plain(m), "Mode A wallets live in the server's config.json.") {
		t.Errorf("mode A:\n%s", plain(m))
	}
}

// TestDialogReadsWhole: a summary longer or wider than the screen is wrapped
// and read with the arrows: nothing of what the wallet says is cut.
func TestDialogReadsWhole(t *testing.T) {
	f := newFake(ipc.MethodPassword)
	long := "addr_test1" + strings.Repeat("q", 200) + "end"
	f.ch.Summary = []string{"Per transaction 350.000000 ADA, per hour 10000.000000 ADA, per day 10000.000000 ADA, budget 20000.000000 ADA, the end"}
	for i := range 60 {
		f.ch.Summary = append(f.ch.Summary, "line "+string(rune('a'+i%26))+strings.Repeat("x", i%3))
	}
	f.ch.Summary = append(f.ch.Summary, long)
	m := press(t, start(t, f, &softkey.Slot{}), "3", "enter")
	seen := plain(m)
	if !strings.Contains(seen, "more lines") || !strings.Contains(seen, "read it all") {
		t.Fatalf("the dialog says nothing of the rest:\n%s", seen)
	}
	if !strings.Contains(seen, "the end") {
		t.Fatalf("a wide line was cut:\n%s", seen)
	}
	for range m.authOverflow() + 3 {
		m = press(t, m, "down")
		seen += plain(m)
	}
	if !strings.Contains(seen, "that is all") || !strings.Contains(seen, "end") || !strings.Contains(seen, strings.Repeat("q", 40)) {
		t.Errorf("the end of the summary:\n%s", plain(m))
	}
	if m = press(t, m, "a", "p", "w", "enter"); len(f.completed) != 1 {
		t.Errorf("scrolling got in the way: %d completions", len(f.completed))
	}
}

func TestWrap(t *testing.T) {
	for _, c := range []struct {
		text  string
		width int
		want  []string
	}{
		{"short", 10, []string{"short"}},
		{"one two three", 7, []string{"one two", "three"}},
		{"abcdefghij", 4, []string{"abcd", "efgh", "ij"}},
		{"a  b", 1, []string{"a", "b"}},
		{"", 5, []string{""}},
	} {
		if got := wrap(c.text, c.width); strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("wrap(%q, %d) = %q", c.text, c.width, got)
		}
	}
}
