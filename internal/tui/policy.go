// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package tui

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/Liet-ada/mcpcardano/internal/actions"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The policy editor (decision 142). It edits the file policy show writes and
// policy set reads, and sends what actions.PolicyFile.Wire makes of it, so a
// policy changed here is the one policy set makes of the same JSON. It marks
// each change as looser or tighter, as a help: what counts is the summary of
// the wallet, which the dialog always shows below.

type part int

const (
	secLimits part = iota
	secDestinations
	secTokens
	secStructure
	secUTxO
	secMode
	parts
)

var partNames = [parts]string{"LIMITS", "DESTINATIONS", "TOKENS", "STRUCTURE", "UTXO", "MODE"}

// number is a field written as a number: an amount, in lovelace in the file
// and in ADA on screen, or a count.
type number struct {
	sec     part
	name    string
	amount  func(*actions.PolicyFile) *string
	count   func(*actions.PolicyFile) *uint32
	neutral bool // it steers the wallet: neither looser nor tighter
}

func (n number) value(f *actions.PolicyFile) uint64 {
	if n.count != nil {
		return uint64(*n.count(f))
	}
	v, _ := model.ParseAmount(*n.amount(f)) // empty is zero (decision 38)
	return v
}

func (n number) text(v uint64) string {
	if n.count != nil {
		return strconv.FormatUint(v, 10)
	}
	return strings.TrimSuffix(ada(v), " ADA")
}

// set writes what the person wrote into f.
func (n number) set(f *actions.PolicyFile, text string) error {
	if n.count != nil {
		v, err := strconv.ParseUint(text, 10, 32)
		if err == nil {
			*n.count(f) = uint32(v)
		}
		return err
	}
	v, err := actions.ParseADA(text)
	if err == nil {
		*n.amount(f) = model.FormatAmount(v)
	}
	return err
}

func limit(name string, at func(*actions.LimitsFile) *string) number {
	return number{sec: secLimits, name: name, amount: func(f *actions.PolicyFile) *string { return at(&f.Limits) }}
}

func limitCount(name string, at func(*actions.LimitsFile) *uint32) number {
	return number{sec: secLimits, name: name, count: func(f *actions.PolicyFile) *uint32 { return at(&f.Limits) }}
}

var numbers = []number{
	limit("PER TRANSACTION", func(l *actions.LimitsFile) *string { return &l.PerTx }),
	limit("PER HOUR", func(l *actions.LimitsFile) *string { return &l.PerHour }),
	limit("PER DAY", func(l *actions.LimitsFile) *string { return &l.PerDay }),
	limit("BUDGET", func(l *actions.LimitsFile) *string { return &l.Budget }),
	limit("APPROVE ABOVE", func(l *actions.LimitsFile) *string { return &l.ApprovalThreshold }),
	limit("MAXIMUM FEE", func(l *actions.LimitsFile) *string { return &l.MaxFee }),
	limitCount("TX PER HOUR", func(l *actions.LimitsFile) *uint32 { return &l.TxPerHour }),
	limitCount("NEW DEST PER HOUR", func(l *actions.LimitsFile) *uint32 { return &l.NewDestinationsPerHour }),
	limitCount("NEW DEST PER DAY", func(l *actions.LimitsFile) *uint32 { return &l.NewDestinationsPerDay }),
	limitCount("LIVE DRAFTS", func(l *actions.LimitsFile) *uint32 { return &l.MaxLiveDrafts }),
	limitCount("MAXIMUM TTL (S)", func(l *actions.LimitsFile) *uint32 { return &l.MaxTTLSeconds }),
	{sec: secUTxO, name: "ADA-ONLY TARGET", neutral: true, count: func(f *actions.PolicyFile) *uint32 { return &f.UTxO.TargetADAOnly }},
	{sec: secUTxO, name: "MINIMUM SPLIT", neutral: true, amount: func(f *actions.PolicyFile) *string { return &f.UTxO.MinSplit }},
	{sec: secUTxO, name: "DUST BELOW", neutral: true, amount: func(f *actions.PolicyFile) *string { return &f.UTxO.DustThreshold }},
	{sec: secUTxO, name: "DUST SWEPT", neutral: true, count: func(f *actions.PolicyFile) *uint32 { return &f.UTxO.MaxDustSweep }},
}

// toggle is a field that is on or off.
type toggle struct {
	sec    part
	name   string
	at     func(*actions.PolicyFile) *bool
	looser bool // whether on is the looser side
}

var toggles = []toggle{
	{secDestinations, "ANY ADDRESS", func(f *actions.PolicyFile) *bool { return &f.Destinations.Any }, true},
	{secStructure, "CERTIFICATES", func(f *actions.PolicyFile) *bool { return &f.Structure.Certificates }, true},
	{secStructure, "WITHDRAWALS", func(f *actions.PolicyFile) *bool { return &f.Structure.Withdrawals }, true},
	{secStructure, "MINT", func(f *actions.PolicyFile) *bool { return &f.Structure.Mint }, true},
	{secStructure, "INTERNAL TRANSFERS", func(f *actions.PolicyFile) *bool { return &f.Structure.InternalTransfers }, true},
	{secMode, "SESSION REQUIRED", func(f *actions.PolicyFile) *bool { return &f.SessionRequired }, false},
}

var networks = []string{string(model.Mainnet), string(model.Preprod), string(model.Preview)}

// direction is which way a change moves the policy.
type direction int

const (
	changed direction = iota
	looser
	tighter
)

// change is one difference from the policy as the wallet gave it.
type change struct {
	sec           part
	name          string
	before, after string
	way           direction
}

func yesNo(on bool) string {
	if on {
		return "yes"
	}
	return "no"
}

// editor is the policy of a wallet, or the template, as it is edited.
type editor struct {
	title    string // what it edits
	done     string // what to say once it changed
	walletID string // "" for the template
	base     actions.PolicyFile
	cur      actions.PolicyFile // with its switches and lists as they are now
	text     []string           // each number as written, which may not be one
	open     [parts]bool
	at       cursor
	address  []rune // a destination being written
	token    []rune // a token being written
}

func newEditor(title, finished, walletID, mode string, p ipc.Policy) *editor {
	e := &editor{title: title, done: finished, walletID: walletID, base: actions.PolicyFromWire(mode, p), cur: actions.PolicyFromWire(mode, p)}
	for _, n := range numbers {
		e.text = append(e.text, n.text(n.value(&e.base)))
	}
	e.open[secLimits] = true
	e.at.at = 1 // the first field, below the heading of the limits
	return e
}

// current asks the wallet for the policy of a wallet, or for the template.
func (m Model) current(walletID string) (string, ipc.Policy, error) {
	if walletID == "" {
		t, err := m.w.ShowTemplate(m.ctx)
		if err != nil {
			return "", ipc.Policy{}, err
		}
		return t.Mode, t.Policy, nil
	}
	w, err := m.w.ShowPolicy(m.ctx, walletID)
	if err != nil {
		return "", ipc.Policy{}, err
	}
	return w.Mode, w.Policy, nil
}

func (m Model) openEditor(title, finished, walletID string) tea.Cmd {
	return func() tea.Msg {
		mode, p, err := m.current(walletID)
		switch {
		case err != nil:
			return editorMsg{err: err}
		case mode == string(model.ModeA):
			return editorMsg{err: errors.New("Mode A wallets live in the server's config.json.")}
		}
		return editorMsg{editor: newEditor(title, finished, walletID, mode, p)}
	}
}

func (m Model) editPolicy(ws ipc.WalletStatus) (Model, tea.Cmd) {
	w := ws.Wallet
	return m, m.openEditor("POLICY OF "+label(w), "Policy of wallet "+w.Label+" changed", w.ID)
}

func (m Model) editTemplate() (Model, tea.Cmd) {
	return m, m.openEditor("TEMPLATE OF THE AGENT'S WALLETS", "Template changed", "")
}

// edited is the file with what the person wrote, and the name of the first
// number that is not one. Destinations open to any address take no list.
func (e *editor) edited() (actions.PolicyFile, string) {
	f, bad := e.cur, ""
	for i, n := range numbers {
		if n.set(&f, e.text[i]) != nil && bad == "" {
			bad = n.name
		}
	}
	if f.Destinations.Any {
		f.Destinations.Allowed = []string{}
	}
	return f, bad
}

// changes compares f with the policy as the wallet gave it.
func (e *editor) changes(f *actions.PolicyFile) []change {
	var out []change
	base := &e.base
	if f.Mode != base.Mode {
		out = append(out, change{secMode, "MODE", base.Mode, f.Mode, looser})
	}
	for _, n := range numbers {
		b, a := n.value(base), n.value(f)
		if a == b {
			continue
		}
		way := tighter
		if a > b {
			way = looser
		}
		if n.neutral {
			way = changed
		}
		out = append(out, change{n.sec, n.name, n.text(b), n.text(a), way})
	}
	for _, t := range toggles {
		b, a := *t.at(base), *t.at(f)
		if a == b {
			continue
		}
		way := tighter
		if a == t.looser {
			way = looser
		}
		out = append(out, change{t.sec, t.name, yesNo(b), yesNo(a), way})
	}
	for _, n := range networks {
		b, a := slices.Contains(base.Networks, n), slices.Contains(f.Networks, n)
		switch {
		case a && !b:
			out = append(out, change{secMode, strings.ToUpper(n), "no", "yes", looser})
		case b && !a:
			out = append(out, change{secMode, strings.ToUpper(n), "yes", "no", tighter})
		}
	}
	if !f.Destinations.Any { // an open wallet's list says nothing
		for _, a := range f.Destinations.Allowed {
			if !slices.Contains(base.Destinations.Allowed, a) {
				way := looser
				if base.Destinations.Any {
					way = changed // from any address, it narrows
				}
				out = append(out, change{secDestinations, a, "", "listed", way})
			}
		}
		for _, a := range base.Destinations.Allowed {
			if !slices.Contains(f.Destinations.Allowed, a) {
				out = append(out, change{secDestinations, a, "listed", "", tighter})
			}
		}
	}
	for _, id := range sortedKeys(f.Assets) {
		b, ok := base.Assets[id]
		bv, _ := model.ParseAmount(b)
		av, _ := model.ParseAmount(f.Assets[id])
		switch {
		case !ok:
			out = append(out, change{secTokens, id, "", "up to " + f.Assets[id], looser})
		case av > bv:
			out = append(out, change{secTokens, id, b, f.Assets[id], looser})
		case av < bv:
			out = append(out, change{secTokens, id, b, f.Assets[id], tighter})
		}
	}
	for _, id := range sortedKeys(base.Assets) {
		if _, ok := f.Assets[id]; !ok {
			out = append(out, change{secTokens, id, base.Assets[id], "", tighter})
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string { return slices.Sorted(maps.Keys(m)) }

type rowKind int

const (
	rowHead rowKind = iota
	rowNumber
	rowToggle
	rowMode
	rowNetwork
	rowAddress
	rowNewAddress
	rowToken
	rowNewToken
)

// row is one line of the editor; i is its place in its table, and key the
// address or the token it stands for.
type row struct {
	kind rowKind
	sec  part
	i    int
	key  string
}

// rows are the lines on show, with the sections that are open.
func (e *editor) rows() []row {
	var out []row
	for s := range parts {
		out = append(out, row{kind: rowHead, sec: s})
		if !e.open[s] {
			continue
		}
		if s == secMode {
			out = append(out, row{kind: rowMode, sec: s})
		}
		for i, n := range numbers {
			if n.sec == s {
				out = append(out, row{kind: rowNumber, sec: s, i: i})
			}
		}
		for i, t := range toggles {
			if t.sec == s {
				out = append(out, row{kind: rowToggle, sec: s, i: i})
			}
		}
		switch s {
		case secDestinations:
			if !e.cur.Destinations.Any {
				for _, a := range e.cur.Destinations.Allowed {
					out = append(out, row{kind: rowAddress, sec: s, key: a})
				}
				out = append(out, row{kind: rowNewAddress, sec: s})
			}
		case secTokens:
			for _, id := range sortedKeys(e.cur.Assets) {
				out = append(out, row{kind: rowToken, sec: s, key: id})
			}
			out = append(out, row{kind: rowNewToken, sec: s})
		case secMode:
			for i := range networks {
				out = append(out, row{kind: rowNetwork, sec: s, i: i})
			}
		}
	}
	return out
}

func (m Model) editorKey(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	m.note, m.failed = "", false
	e := m.editor
	rows := e.rows()
	r := rows[e.at.at]
	s := k.String()
	switch s {
	case "esc":
		m.close()
		return m, nil
	case "ctrl+r":
		return m.review()
	case "up", "shift+tab":
		e.at.move(-1, len(rows))
		return m, nil
	case "down", "tab":
		e.at.move(1, len(rows))
		return m, nil
	}
	press := s == "enter" || s == "space"
	switch r.kind {
	case rowHead:
		if press {
			e.open[r.sec] = !e.open[r.sec]
		}
	case rowToggle:
		if press {
			at := toggles[r.i].at(&e.cur)
			*at = !*at
		}
	case rowMode:
		if press {
			e.cur.Mode = map[string]string{string(model.ModeB): string(model.ModeC), string(model.ModeC): string(model.ModeB)}[e.cur.Mode]
		}
	case rowNetwork:
		if press {
			n := networks[r.i]
			if i := slices.Index(e.cur.Networks, n); i >= 0 {
				e.cur.Networks = slices.Delete(e.cur.Networks, i, i+1)
			} else {
				e.cur.Networks = append(e.cur.Networks, n)
			}
		}
	case rowNumber:
		switch {
		case s == "enter":
			e.at.move(1, len(rows))
		case s == "backspace":
			e.text[r.i] = e.text[r.i][:max(len(e.text[r.i])-1, 0)]
		case len(k.Text) == 1 && strings.Contains("0123456789.", k.Text) && len(e.text[r.i]) < maxField:
			e.text[r.i] += k.Text
		}
	case rowAddress:
		if s == "backspace" || s == "x" {
			i := slices.Index(e.cur.Destinations.Allowed, r.key)
			e.cur.Destinations.Allowed = slices.Delete(e.cur.Destinations.Allowed, i, i+1)
		}
	case rowToken:
		if s == "backspace" || s == "x" {
			delete(e.cur.Assets, r.key)
		}
	case rowNewAddress:
		if s == "enter" {
			return m.addAddress()
		}
		e.address = edit(e.address, k)
	case rowNewToken:
		if s == "enter" {
			return m.addToken()
		}
		e.token = edit(e.token, k)
	}
	e.at.clamp(len(e.rows()))
	return m, nil
}

// edit is what a key does to a line of text.
func edit(v []rune, k tea.KeyPressMsg) []rune {
	if k.String() == "backspace" {
		return v[:max(len(v)-1, 0)]
	}
	if len(v) >= 2*maxField {
		return v
	}
	return append(v, []rune(k.Text)...)
}

func (m Model) addAddress() (Model, tea.Cmd) {
	e := m.editor
	text := strings.TrimSpace(string(e.address))
	a, err := model.ParseAddress(model.Network(m.network), text)
	if err != nil {
		return m.refuse("That is not an address of " + m.network + ".")
	}
	text = a.Bech32()
	if slices.Contains(e.cur.Destinations.Allowed, text) {
		return m.refuse("That address is already listed.")
	}
	e.cur.Destinations.Allowed = append(e.cur.Destinations.Allowed, text)
	e.address = nil
	e.at.clamp(len(e.rows()))
	return m, nil
}

// addToken takes a token as policy.name and the cap per transaction, both as
// policy set reads them.
func (m Model) addToken() (Model, tea.Cmd) {
	e := m.editor
	parts := strings.Fields(string(e.token))
	if len(parts) != 2 {
		return m.refuse("Write the token as <policy>.<name> and then its cap per transaction.")
	}
	id, err := model.ParseAssetID(parts[0])
	if err != nil {
		return m.refuse("A token is written <policy hex>.<name hex>.")
	}
	most, err := model.ParseAmount(parts[1])
	if err != nil {
		return m.refuse("The cap is a whole number of units.")
	}
	e.cur.Assets[id.String()] = model.FormatAmount(most)
	e.token = nil
	e.at.clamp(len(e.rows()))
	return m, nil
}

// review asks the wallet for its summary of what changed. The policy is read
// again first: the wallet takes it whole, frozen or not, so one edited before
// a freeze would undo it, and one changed meanwhile would be overwritten.
func (m Model) review() (Model, tea.Cmd) {
	e := m.editor
	f, bad := e.edited()
	if bad != "" {
		return m.refuse(bad + " is not valid: mend it to review.")
	}
	ch := e.changes(&f)
	if len(ch) == 0 {
		return m.refuse("Nothing changed.")
	}
	n := model.Network(m.network)
	mode, p, err := f.Wire(n)
	if err != nil {
		return m.refuse(err.Error())
	}
	a := &authorization{title: e.title, changes: ch, warnings: actions.Warnings(n, mode, p),
		finish: decoded(new(ipc.PolicyHash), func(h *ipc.PolicyHash) done {
			return done{note: fmt.Sprintf("%s. The audit log records it as %x.", e.done, h.Hash[:8])}
		})}
	return m, func() tea.Msg {
		curMode, cur, err := m.current(e.walletID)
		if err != nil {
			return challenged{err: err}
		}
		if !reflect.DeepEqual(actions.PolicyFromWire(curMode, cur), e.base) {
			return challenged{err: errors.New("The policy changed while you edited it: esc, and open it again.")}
		}
		p.Frozen = cur.Frozen
		act := actions.ChangePolicy(e.walletID, mode, p)
		if e.walletID == "" {
			act = actions.SetTemplate(mode, p)
		}
		return m.begin(act, a)()
	}
}

// wayMark is the mark of a change, on the background of st.
func wayMark(way direction, st lipgloss.Style) string {
	switch way {
	case looser:
		return paint(st.Foreground(cOrange).Bold(true), "↑ looser")
	case tighter:
		return paint(st.Foreground(cGreen), "↓ tighter")
	}
	return paint(st.Foreground(cDim), "← changed")
}

// summary is a closed section in a line.
func (e *editor) summary(s part, f *actions.PolicyFile) string {
	amount := func(i int) string { return adaShort(numbers[i].value(f)) }
	switch s {
	case secLimits:
		return amount(0) + " per tx · " + amount(1) + " per hour · " + amount(2) + " per day · budget " + amount(3)
	case secDestinations:
		if f.Destinations.Any {
			return "any address"
		}
		return fmt.Sprintf("%d listed", len(f.Destinations.Allowed))
	case secTokens:
		if len(f.Assets) == 0 {
			return "none may leave"
		}
		return fmt.Sprintf("%d kinds may leave", len(f.Assets))
	case secStructure:
		st := f.Structure
		return "certificates " + yesNo(st.Certificates) + " · withdrawals " + yesNo(st.Withdrawals) +
			" · mint " + yesNo(st.Mint) + " · internal " + yesNo(st.InternalTransfers)
	case secUTxO:
		u := f.UTxO
		return fmt.Sprintf("target %d · min split %s · dust %s · sweep %d", u.TargetADAOnly, amount(12), amount(13), u.MaxDustSweep)
	}
	session := "session not required"
	if f.SessionRequired {
		session = "session required"
	}
	return f.Mode + " · " + session + " · networks " + strings.Join(f.Networks, ", ")
}

// wayCounts are how many changes of each way a closed section hides.
func wayCounts(s part, ch []change) string {
	var n [3]int
	for _, c := range ch {
		if c.sec == s {
			n[c.way]++
		}
	}
	out := ""
	for _, way := range []direction{looser, tighter, changed} {
		if n[way] > 0 {
			out += sp(2) + wayMark(way, sBase) + paint(sDim, fmt.Sprintf(" %d", n[way]))
		}
	}
	return out
}

func (e *editor) findChange(ch []change, s part, name string) *change {
	i := slices.IndexFunc(ch, func(c change) bool { return c.sec == s && c.name == name })
	if i < 0 {
		return nil
	}
	return &ch[i]
}

func (e *editor) line(r row, chosen bool, f *actions.PolicyFile, ch []change) string {
	name := func(text string) string {
		cell := fmt.Sprintf("%-20s", truncate(text, 20))
		if chosen {
			return sp(2) + paint(sSelected, "▸ "+cell)
		}
		return sp(4) + paint(sDim, cell)
	}
	caret := ""
	if chosen {
		caret = paint(sCyan, "▌")
	}
	field := func(text string) string {
		return sp(1) + paint(sHUD, "[ ") + paint(sBold, text) + caret + paint(sHUD, " ]")
	}
	was := func(c *change) string {
		if c == nil {
			return ""
		}
		return sp(2) + paint(sDim, "was "+c.before) + sp(2) + wayMark(c.way, sBase)
	}
	switch r.kind {
	case rowHead:
		mark, title, st, counts := "▸ ", fmt.Sprintf("%-20s", partNames[r.sec]), sYellow, wayCounts(r.sec, ch)
		if e.open[r.sec] {
			mark, counts = "▾ ", ""
		}
		if chosen {
			st = sSelected
		}
		return sp(2) + paint(st, mark+title) + sp(1) + paint(sDim, e.summary(r.sec, f)) + counts
	case rowNumber:
		n := numbers[r.i]
		unit := ""
		if n.amount != nil {
			unit = paint(sDim, " ADA")
		}
		probe := e.base
		if n.set(&probe, e.text[r.i]) != nil {
			return name(n.name) + field(e.text[r.i]) + unit + sp(2) + paint(sRed, "invalid")
		}
		return name(n.name) + field(e.text[r.i]) + unit + was(e.findChange(ch, r.sec, n.name))
	case rowToggle:
		t := toggles[r.i]
		return name(t.name) + sp(1) + paint(sBold, yesNo(*t.at(&e.cur))) + was(e.findChange(ch, r.sec, t.name))
	case rowMode:
		return name("MODE") + sp(1) + modeBadge(f.Mode) + was(e.findChange(ch, r.sec, "MODE"))
	case rowNetwork:
		n := networks[r.i]
		return name(strings.ToUpper(n)) + sp(1) + paint(sBold, yesNo(slices.Contains(f.Networks, n))) + was(e.findChange(ch, r.sec, strings.ToUpper(n)))
	case rowAddress:
		mark := ""
		if c := e.findChange(ch, r.sec, r.key); c != nil {
			mark = sp(2) + wayMark(c.way, sBase)
		}
		return name("LISTED") + sp(1) + paint(sCyan, r.key) + mark
	case rowToken:
		mark := ""
		if c := e.findChange(ch, r.sec, r.key); c != nil {
			mark = sp(2) + wayMark(c.way, sBase)
		}
		return name("UP TO "+f.Assets[r.key]) + sp(1) + paint(sCyan, r.key) + mark
	case rowNewAddress:
		return name("ADD AN ADDRESS") + field(string(e.address))
	}
	return name("ADD A TOKEN") + field(string(e.token)) + sp(2) + paint(sDim, "<policy>.<name> <cap>")
}

func (m Model) editorView(w, height int) []string {
	e := m.editor
	f, _ := e.edited()
	ch := e.changes(&f)
	legend := wayMark(changed, sBase) + sp(2) + wayMark(looser, sBase) + sp(2) + wayMark(tighter, sBase) + sp(2)
	out := []string{"", spread(sp(2)+section(e.title), legend, w), ""}
	rows := e.rows()
	from, to := e.at.window(len(rows), height-len(out))
	for i := from; i < to; i++ {
		out = append(out, e.line(rows[i], i == e.at.at, &f, ch))
	}
	return out
}

// changeLine is a change in the dialog of its authorization.
func changeLine(c change) string {
	text := paint(sPanel.Foreground(cYellow), c.name)
	switch {
	case c.before == "":
		text += paint(sPanel, "  "+c.after)
	case c.after == "":
		text += paint(sPanel, "  no longer "+c.before)
	default:
		text += paint(sPanel, "  "+c.before+" → "+c.after)
	}
	return text + paint(sPanel, "  ") + wayMark(c.way, sPanel)
}

// byWay puts first what loosens the policy, the first thing to read.
func byWay(ch []change) []change {
	out := slices.Clone(ch)
	order := map[direction]int{looser: 0, changed: 1, tighter: 2}
	slices.SortStableFunc(out, func(a, b change) int { return cmp.Compare(order[a.way], order[b.way]) })
	return out
}
