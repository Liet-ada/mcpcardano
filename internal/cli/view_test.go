// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"strings"
	"testing"

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
