// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"fmt"

	tea "charm.land/bubbletea/v2"
)

// The view's widgets are its own, not bubbles' (decision 142): a cursor
// over a list is a few lines, and the fields for secrets are the view's
// since step 5.

// cursor is the chosen row of a list.
type cursor struct{ at int }

// move goes by delta rows, within a list of n rows.
func (c *cursor) move(delta, n int) {
	c.at = min(max(c.at+delta, 0), max(n-1, 0))
}

// clamp keeps the cursor inside a list that may have shrunk.
func (c *cursor) clamp(n int) { c.move(0, n) }

// window returns the rows to draw, from and to, when only height of the n
// rows fit: the cursor is always among them.
func (c cursor) window(n, height int) (from, to int) {
	height = max(height, 1)
	from = max(min(c.at-height+1, n-height), 0)
	return from, min(from+height, n)
}

// maxField is the longest text a field takes.
const maxField = 100

// field is one line of a form.
type field struct {
	name, hint string
	value      []rune
}

// form is a short form over the tab: what it is about, its fields and what
// comes of them. submit gets the values as written; what it refuses it says
// with refuse, and the form stays.
type form struct {
	title  string
	fields []field
	at     int
	submit func(m Model, values []string) (Model, tea.Cmd)
}

func (m Model) formKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	m.note, m.failed = "", false
	f := m.form
	n := len(f.fields)
	switch k.String() {
	case "esc":
		m.close()
	case "tab", "down":
		f.at = (f.at + 1) % n
	case "shift+tab", "up":
		f.at = (f.at + n - 1) % n
	case "enter":
		if f.at < n-1 {
			f.at++
			return m, nil
		}
		values := make([]string, n)
		for i, fl := range f.fields {
			values[i] = string(fl.value)
		}
		return f.submit(m, values)
	case "backspace":
		if v := f.fields[f.at].value; len(v) > 0 {
			f.fields[f.at].value = v[:len(v)-1]
		}
	default:
		if v := f.fields[f.at].value; len(v) < maxField {
			f.fields[f.at].value = append(v, []rune(k.Text)...)
		}
	}
	return m, nil
}

func (m Model) formView() []string {
	f := m.form
	out := []string{"", sp(2) + section(f.title), ""}
	for i, fl := range f.fields {
		mark, caret := sp(2), ""
		if i == f.at {
			mark, caret = paint(sYellow, "▸ "), paint(sCyan, "▌")
		}
		out = append(out, sp(2)+mark+paint(sDim, fmt.Sprintf("%-8s", fl.name))+paint(sHUD, "[ ")+
			paint(sBold, string(fl.value))+caret+paint(sHUD, " ]")+sp(2)+paint(sDim, fl.hint))
	}
	return out
}

// wrap splits text into lines of at most width runes, at the spaces if it
// can: a long address goes on the next line whole, or in pieces if it is
// longer than a line.
func wrap(text string, width int) []string {
	r := []rune(text)
	width = max(width, 1)
	var out []string
	for len(r) > width {
		cut := width
		for i := width; i > 0; i-- {
			if r[i] == ' ' {
				cut = i
				break
			}
		}
		out = append(out, string(r[:cut]))
		r = r[cut:]
		for len(r) > 0 && r[0] == ' ' {
			r = r[1:]
		}
	}
	return append(out, string(r))
}

// spinner is the only motion in the view: while it waits for a key.
var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
