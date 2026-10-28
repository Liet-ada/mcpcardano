// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

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

// spinner is the only motion in the view: while it waits for a key.
var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
