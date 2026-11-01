// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"bytes"
	_ "embed"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Liet-ada/mcpcardano/internal/actions"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The recovery phrase, on its own screens. It lives in one model.Secret each
// and never in the status: close wipes it, whichever way the screen ends. A
// word on show is a Go string for as long as it is drawn, and the terminal
// holds it until it draws something else; the view shows one only when asked.

// english is the BIP-39 English word list, to complete the words of a
// restore. It is a copy of hdkey's: the CLI does not link hdkey, and the
// wallet gains no package (decision 142). A test checks its SHA-256.
//
//go:embed english.txt
var english string

var wordlist = sync.OnceValue(func() []string { return strings.Fields(english) })

const (
	// phraseIdle is how long the phrase stays with no key pressed.
	phraseIdle = 2 * time.Minute
	// maxWords is the longest phrase, and wordSize the longest word with the
	// space after it.
	maxWords = 24
	wordSize = 9
)

// phrase is a wallet's recovery phrase on its screen.
type phrase struct {
	label string
	words model.Secret
	shown bool
	until time.Time // when it hides itself
}

// askPhrase opens the authorization of the wallet's phrase.
func (m Model) askPhrase(ws ipc.WalletStatus) (Model, tea.Cmd) {
	w := ws.Wallet
	return m, m.begin(actions.ShowPhrase(w.ID), &authorization{title: "RECOVERY PHRASE OF " + label(w),
		finish: decoded(new(ipc.RecoveryPhrase), func(r *ipc.RecoveryPhrase) done {
			return done{phrase: &phrase{label: label(w), words: r.Phrase}}
		})})
}

func (m Model) showPhrase(p *phrase) (Model, tea.Cmd) {
	p.until = m.now().Add(phraseIdle)
	m.overlay, m.phrase = phraseOverlay, p
	return m, tea.Batch(m.fetch, phraseAfter())
}

func phraseAfter() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return phraseTick{} })
}

// phraseTimer hides the phrase once no key was pressed for phraseIdle.
func (m Model) phraseTimer() (Model, tea.Cmd) {
	if m.phrase == nil {
		return m, nil
	}
	if m.now().Before(m.phrase.until) {
		return m, phraseAfter()
	}
	m.close()
	m.note, m.failed = "The phrase hid itself after two minutes without a key.", false
	return m, nil
}

func (m Model) phraseKey(s string) (tea.Model, tea.Cmd) {
	switch s {
	case "space":
		m.phrase.shown = !m.phrase.shown
	case "esc":
		m.close()
	}
	return m, nil
}

func (m Model) phraseView(w int) []string {
	p := m.phrase
	left := max(p.until.Sub(m.now()), 0).Round(time.Second)
	inner := []string{paint(sPanel.Foreground(cRed).Bold(true), "Anyone who reads these words owns the funds of this wallet."),
		paint(sPanel, "Write them on paper. Do not take a photo or copy them."), paint(sPanel, "")}
	var words [][]byte
	if p.shown {
		words = bytes.Fields(p.words)
	}
	n := bytes.Count(p.words, []byte(" ")) + 1
	rows := (n + 3) / 4
	for r := range rows {
		row := ""
		for c := range 4 {
			i := r + c*rows
			if i >= n {
				break
			}
			word := "·······"
			if p.shown {
				word = string(words[i])
			}
			row += paint(sPanel.Foreground(cDim), fmt.Sprintf("%4d ", i+1)) + paint(sPanel.Foreground(cYellow), fmt.Sprintf("%-11s", word))
		}
		inner = append(inner, row)
	}
	inner = append(inner, paint(sPanel, ""), pressLine(sPanel, "space", "SHOW OR HIDE", "esc", "HIDE AND GO BACK"))
	timer := paint(sOrange, fmt.Sprintf(" hides in %d:%02d ", int(left.Minutes()), int(left.Seconds())%60))
	return m.panel(w, badge("RECOVERY PHRASE", cRed)+sp(1)+paint(sDim, p.label+" "), timer, inner)
}

// restore is a recovery phrase as it is typed: the words the view took,
// separated by spaces, and then the word being written. typed holds the
// longest phrase from the start, so it never moves and leaves no copy behind.
type restore struct {
	label string
	typed model.Secret
	shown bool
}

func (r *restore) words() int { return bytes.Count(r.typed, []byte(" ")) }

// word is the word being written.
func (r *restore) word() []byte { return r.typed[bytes.LastIndexByte(r.typed, ' ')+1:] }

// completions returns up to n words of the list that start with typed.
func completions(typed []byte, n int) []string {
	list := wordlist()
	i, _ := slices.BinarySearchFunc(list, typed, func(w string, t []byte) int { return bytes.Compare([]byte(w), t) })
	var out []string
	for ; i < len(list) && len(out) < n && bytes.HasPrefix([]byte(list[i]), typed); i++ {
		out = append(out, list[i])
	}
	return out
}

// complete returns the word typed names: itself, or the only one that starts
// so.
func complete(typed []byte) (string, bool) {
	found := completions(typed, 2)
	switch {
	case len(found) == 0:
		return "", false
	case found[0] == string(typed):
		return found[0], true
	}
	return found[0], len(found) == 1
}

// restoreForm asks for the label; the words come on their own screen.
func (m Model) restoreForm() (Model, tea.Cmd) {
	if !m.status.Unlocked { // before the person types the 24 words
		return m.refuse("The wallet is locked: unlock it in tab 6.")
	}
	m.overlay = formOverlay
	m.form = &form{title: "RESTORE A WALLET",
		fields: []field{{name: "LABEL", hint: "a name for it"}},
		submit: func(m Model, v []string) (Model, tea.Cmd) {
			if _, err := actions.RestoreWallet(v[0], nil); err != nil {
				return m.refuse(sentence(err))
			}
			m.close()
			m.overlay = restoreOverlay
			m.restore = &restore{label: v[0], typed: make(model.Secret, 0, maxWords*wordSize)}
			return m, nil
		}}
	return m, nil
}

func (m Model) restoreKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	m.note, m.failed = "", false
	r := m.restore
	switch k.String() {
	case "esc":
		m.close()
	case "ctrl+r":
		r.shown = !r.shown
	case "backspace":
		if len(r.typed) > 0 {
			r.typed[len(r.typed)-1] = 0
			r.typed = r.typed[:len(r.typed)-1]
		}
	case "enter", "tab", "space":
		return m.takeWord()
	default:
		for _, c := range []byte(strings.ToLower(k.Text)) {
			if c >= 'a' && c <= 'z' && len(r.word()) < wordSize-1 {
				r.typed = append(r.typed, c)
			}
		}
	}
	return m, nil
}

// takeWord takes the word being written and goes on to the next, or sends
// the phrase: at the last word, or at an empty one when the phrase can end
// there.
func (m Model) takeWord() (Model, tea.Cmd) {
	r := m.restore
	typed := r.word()
	if len(typed) == 0 {
		if n := r.words(); n < 12 || n%3 != 0 {
			return m.refuse("A recovery phrase has 12, 15, 18, 21 or 24 words.")
		}
		return m.sendPhrase()
	}
	word, ok := complete(typed)
	if !ok {
		return m.refuse("That is not the start of one word of the list.")
	}
	start := len(r.typed) - len(typed)
	r.typed = append(r.typed[:start], word...)
	if r.words() == maxWords-1 {
		return m.sendPhrase()
	}
	r.typed = append(r.typed, ' ')
	return m, nil
}

// sendPhrase sends a copy, which begin wipes: the words stay on the screen
// until the wallet takes them, for the person to mend them if it does not.
func (m Model) sendPhrase() (Model, tea.Cmd) {
	r := m.restore
	act, err := actions.RestoreWallet(r.label, slices.Clone(bytes.TrimRight(r.typed, " ")))
	if err != nil {
		return m.refuse(sentence(err))
	}
	return m, m.begin(act, &authorization{title: "RESTORE " + strings.ToUpper(r.label),
		finish: decoded(new(ipc.Wallet), func(w *ipc.Wallet) done {
			return done{note: "Wallet " + w.Label + " restored."}
		})})
}

func (m Model) restoreView(w int) []string {
	r := m.restore
	typed := r.word()
	inner := []string{paint(sPanel, "Type the words of the recovery phrase, in order, one at a time."),
		paint(sPanel, "A word is enough with the letters that make it the only one of the list."), paint(sPanel, ""),
		paint(sPanel.Foreground(cDim), "TAKEN  ") + paint(sPanel.Foreground(cYellow), fmt.Sprintf("%d", r.words())) +
			paint(sPanel.Foreground(cDim), fmt.Sprintf(" of 12 to %d words", maxWords))}
	text := strings.Repeat("•", len(typed))
	if r.shown {
		text = string(typed)
	}
	inner = append(inner, paint(sPanel.Foreground(cDim), fmt.Sprintf("WORD %-2d", r.words()+1))+
		paint(sPanel.Foreground(cYellow), text)+paint(sPanel.Foreground(cCyan), "▌"))
	if r.shown && len(typed) > 0 {
		inner = append(inner, paint(sPanel.Foreground(cDim), "       "+strings.Join(completions(typed, 6), "  ")))
	}
	inner = append(inner, paint(sPanel, ""), pressLine(sPanel, "enter", "TAKE THE WORD", "esc", "CANCEL"))
	return m.panel(w, badge("RESTORE", cRed)+sp(1)+paint(sDim, strings.ToUpper(r.label)+" "), "", inner)
}
