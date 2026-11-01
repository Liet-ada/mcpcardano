// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/tui"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

// TestViewNeedsATerminal: without one, view says so and exits 1.
func TestViewNeedsATerminal(t *testing.T) {
	w := walletkit.Start(t)
	p := person{t: t, w: w}
	if r := p.run("", "view"); r.code != ExitError || !strings.Contains(r.errOut, "needs a terminal") {
		t.Errorf("view without a terminal: %+v", r)
	}
}

// TestViewReachesEveryCommand: every command of the admin socket is in the
// view's palette, and a new one fails here until it is.
func TestViewReachesEveryCommand(t *testing.T) {
	inView := tui.CLICommands()
	for name := range commands {
		if name == "view" {
			continue
		}
		if !slices.ContainsFunc(inView, func(c string) bool { return strings.HasPrefix(c+" ", "mcpcardano "+name+" ") }) {
			t.Errorf("mcpcardano %s is not in the view", name)
		}
	}
}
