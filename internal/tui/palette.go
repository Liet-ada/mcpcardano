// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
)

// command is one entry of the palette: what it does, the CLI command that
// does the same, and how it runs in the view.
type command struct {
	section string
	label   string
	cli     string
	style   lipgloss.Style
	run     func(Model) (Model, tea.Cmd)
}

func goTo(t tab) func(Model) (Model, tea.Cmd) {
	return func(m Model) (Model, tea.Cmd) { return m.show(t) }
}

// onKey presses a key of a tab.
func onKey(t tab, key string) func(Model) (Model, tea.Cmd) {
	return func(m Model) (Model, tea.Cmd) {
		m.tab = t
		next, cmd := m.tabKey(key)
		return next.(Model), cmd
	}
}

// onWallet runs a key of the wallets' tab on the chosen wallet.
func onWallet(key string) func(Model) (Model, tea.Cmd) {
	return func(m Model) (Model, tea.Cmd) {
		m.tab = tabWallets
		next, cmd := m.tabKey(key)
		return next.(Model), cmd
	}
}

// onChosen runs f on the chosen wallet.
func onChosen(f func(Model, ipc.WalletStatus) (Model, tea.Cmd)) func(Model) (Model, tea.Cmd) {
	return func(m Model) (Model, tea.Cmd) {
		m.tab = tabWallets
		if m.status == nil || len(m.status.Wallets) == 0 {
			return m, nil
		}
		return f(m, m.status.Wallets[m.wallets.at])
	}
}

// commands are grouped and coloured by purpose: cyan to look, pink for
// what reduces risk, orange for what raises it and takes an authorization,
// dim for the view itself.
var commands = []command{
	{"LOOK", "Overview", "mcpcardano status", sCyan, goTo(tabOverview)},
	{"LOOK", "Wallets, their limits and what they spent", "mcpcardano policy show -wallet <id>", sCyan, goTo(tabWallets)},
	{"LOOK", "Approvals waiting", "mcpcardano status", sCyan, goTo(tabApprovals)},
	{"LOOK", "Security keys", "mcpcardano key list", sCyan, goTo(tabKeys)},
	{"LOOK", "What the chosen wallet may release", "mcpcardano budget pending -wallet <id>", sCyan, onWallet("b")},
	{"LOOK", "Ask for the chosen wallet's balance", "", sCyan, onWallet("r")},
	{"LOOK", "Ask how the network is", "", sCyan, onKey(tabSystem, "n")},
	{"LOOK", "Audit log", "mcpcardano audit show", sCyan, goTo(tabAudit)},
	{"LOOK", "Verify the audit log's chains", "mcpcardano audit verify", sCyan, onKey(tabAudit, "v")},
	{"LOOK", "A recovery waiting", "mcpcardano recover status", sCyan, goTo(tabSystem)},
	{"LOOK", "Check the installation", "mcpcardano doctor", sCyan, Model.runDoctor},
	{"REDUCE RISK", "Freeze every wallet", "mcpcardano freeze", sRed, func(m Model) (Model, tea.Cmd) { return m, m.freeze("") }},
	{"REDUCE RISK", "Freeze the chosen wallet", "mcpcardano freeze -wallet <id>", sRed, onWallet("F")},
	{"REDUCE RISK", "Close the chosen wallet's session", "mcpcardano session close -wallet <id>", sRed, onChosen(Model.closeSession)},
	{"REDUCE RISK", "Reject the chosen approval", "mcpcardano reject <approval_id>", sRed, onKey(tabApprovals, "r")},
	{"AUTHORIZE", "Approve the chosen approval", "mcpcardano approve <approval_id>", sOrange, onKey(tabApprovals, "enter")},
	{"AUTHORIZE", "Unlock the wallet", "mcpcardano unlock", sOrange, onKey(tabSystem, "u")},
	{"AUTHORIZE", "Register a security key", "mcpcardano key add -name <name>", sOrange, onKey(tabKeys, "a")},
	{"AUTHORIZE", "Remove the chosen security key", "mcpcardano key remove -name <name>", sOrange, onKey(tabKeys, "d")},
	{"AUTHORIZE", "Start a recovery without keys", "mcpcardano recover start", sOrange, onKey(tabSystem, "r")},
	{"AUTHORIZE", "Cancel the recovery", "mcpcardano recover cancel", sOrange, onKey(tabSystem, "x")},
	{"AUTHORIZE", "Unfreeze the chosen wallet", "mcpcardano unfreeze -wallet <id>", sOrange, onChosen(Model.unfreeze)},
	{"AUTHORIZE", "Open a session on the chosen wallet", "mcpcardano session open -wallet <id> -for 1h -max <lovelace>", sOrange, onChosen(Model.sessionForm)},
	{"AUTHORIZE", "Edit the chosen wallet's policy", "mcpcardano policy set -wallet <id> <policy.json>", sOrange, onChosen(Model.editPolicy)},
	{"AUTHORIZE", "Edit the template of the agent's wallets", "mcpcardano policy set -template <policy.json>", sOrange, Model.editTemplate},
	{"AUTHORIZE", "Release the chosen wallet's budget", "mcpcardano budget release -wallet <id>", sOrange, onWallet("b")},
	{"AUTHORIZE", "See the chosen wallet's recovery phrase", "mcpcardano wallet backup -wallet <id>", sOrange, onChosen(Model.askPhrase)},
	{"AUTHORIZE", "Create a wallet", "mcpcardano wallet create -label <name>", sOrange, onWallet("c")},
	{"AUTHORIZE", "Restore a wallet", "mcpcardano wallet restore -label <name>", sOrange, onWallet("R")},
	{"VIEW", "Help", "", sDim, func(m Model) (Model, tea.Cmd) { m.overlay = helpOverlay; return m, nil }},
	{"VIEW", "Quit", "", sDim, func(m Model) (Model, tea.Cmd) { m.forget(); return m, tea.Quit }},
}

// CLICommands are the CLI's commands the palette names, for a test that none
// is left out.
func CLICommands() []string {
	var out []string
	for _, c := range commands {
		if c.cli != "" {
			out = append(out, c.cli)
		}
	}
	return out
}

// paletteState is what the person typed to filter the palette, and the
// chosen entry among those that match.
type paletteState struct {
	filter []rune
	cursor cursor
}

func (p paletteState) matches() []command {
	f := strings.ToLower(string(p.filter))
	var out []command
	for _, c := range commands {
		if strings.Contains(strings.ToLower(c.label+" "+c.cli+" "+c.section), f) {
			out = append(out, c)
		}
	}
	return out
}

func (m Model) paletteKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	found := m.palette.matches()
	switch k.String() {
	case "esc":
		m.overlay = noOverlay
	case "up":
		m.palette.cursor.move(-1, len(found))
	case "down":
		m.palette.cursor.move(1, len(found))
	case "backspace":
		if n := len(m.palette.filter); n > 0 {
			m.palette.filter = m.palette.filter[:n-1]
			m.palette.cursor = cursor{}
		}
	case "enter":
		if len(found) == 0 {
			return m, nil
		}
		m.overlay = noOverlay
		next, cmd := found[m.palette.cursor.at].run(m)
		return next, cmd
	default:
		if k.Text != "" {
			m.palette.filter = append(m.palette.filter, []rune(k.Text)...)
			m.palette.cursor = cursor{}
		}
	}
	return m, nil
}

func (m Model) paletteView(w, height int) []string {
	out := []string{"", sp(2) + section("COMMANDS") + sp(2) + paint(sHUD, "[") +
		paint(sCyan, " "+string(m.palette.filter)) + paint(sCyan, "▌ ") + paint(sHUD, "]"), ""}
	found := m.palette.matches()
	if len(found) == 0 {
		return append(out, sp(4)+paint(sDim, "Nothing matches."))
	}
	from, to := m.palette.cursor.window(len(found), height-4)
	last := ""
	for i := from; i < to; i++ {
		c := found[i]
		if c.section != last {
			out = append(out, sp(4)+paint(sDim, c.section))
			last = c.section
		}
		text := fmt.Sprintf("%-44s %s", c.label, c.cli)
		if i == m.palette.cursor.at {
			out = append(out, sp(4)+paint(sSelected, "▸ "+text+" "))
		} else {
			out = append(out, sp(4)+paint(c.style, "◆ ")+paint(sBase, fmt.Sprintf("%-44s ", c.label))+paint(sDim, c.cli))
		}
	}
	return out
}
