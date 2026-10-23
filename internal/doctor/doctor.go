// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package doctor checks an installation of mcpcardano without changing
// anything, as the person and not as root (section 10.5; decision 134). It
// reads the files of the installation, asks systemd about the units, the
// kernel about the clock and the wallet's network, and the wallet and the
// server through their sockets. Each check comes out ok, as a warning or as
// a failure.
package doctor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/Liet-ada/mcpcardano/deploy"
	"github.com/Liet-ada/mcpcardano/internal/fido"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
)

// Level is how a check came out.
type Level int

const (
	OK Level = iota
	Warn
	Fail
)

func (l Level) String() string { return [...]string{"ok  ", "warn", "FAIL"}[l] }

// Result is one check.
type Result struct {
	Level  Level
	Detail string
}

// Report is every check, in order.
type Report []Result

// Failed reports whether any check failed.
func (r Report) Failed() bool {
	return slices.ContainsFunc(r, func(x Result) bool { return x.Level == Fail })
}

// Write writes one line per check and a last one that counts them. A
// detail may carry what the server, which may be compromised, or the wallet
// said: only its visible characters reach the person's terminal, as in the
// rest of the CLI.
func (r Report) Write(w io.Writer) {
	var n [3]int
	for _, x := range r {
		fmt.Fprintf(w, "%s  %s\n", x.Level, visible(x.Detail))
		n[x.Level]++
	}
	switch {
	case n[Fail] > 0:
		fmt.Fprintf(w, "\n%d failed and %d warned.\n", n[Fail], n[Warn])
	case n[Warn] > 0:
		fmt.Fprintf(w, "\nNothing failed; %d warned.\n", n[Warn])
	default:
		fmt.Fprintln(w, "\nEverything is ok.")
	}
}

// visible turns into "?" every character that is not visible, as
// ipc.Detail does, so that no control sequence or change of direction
// reaches a terminal.
func visible(s string) string {
	return strings.Map(func(r rune) rune {
		if r != ' ' && (!unicode.IsGraphic(r) || unicode.IsSpace(r)) {
			return '?'
		}
		return r
	}, s)
}

// Wallet is what the wallet says on its admin socket.
type Wallet struct {
	Software string // from Hello: "mcpcardano-wallet <version>"
	Status   ipc.StatusReport
	Audit    ipc.AuditCheck
	AuditErr error // VerifyAudit's error, if the chains are broken
}

// Server is what the server says on its MCP socket.
type Server struct {
	Version string        // from initialize
	Status  networkStatus // get_network_status
}

// networkStatus is the part of get_network_status that doctor reads.
type networkStatus struct {
	ServerSlot string `json:"server_slot"`
	DataSource struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"datasource"`
	Tip *struct {
		Slot string `json:"slot"`
	} `json:"tip"`
}

// Env is what doctor reads: the machine, or fakes in the tests.
type Env struct {
	// Version is the CLI's.
	Version string
	// UID and Groups are the person's session.
	UID    uint32
	Groups []uint32
	// Lstat and ReadFile read the machine's files without following links.
	Lstat    func(path string) (fs.FileInfo, error)
	ReadFile func(path string) ([]byte, error)
	// Owner returns the user and the group of a file Lstat returned.
	Owner func(fs.FileInfo) (uid, gid uint32)
	// LookupUser and LookupGroup return the id of a user or a group, and
	// UserGroups the groups a user is in, as the system lists them for
	// the next session.
	LookupUser  func(name string) (uint32, error)
	LookupGroup func(name string) (uint32, error)
	UserGroups  func(uid uint32) ([]uint32, error)
	// UserName returns the name of a uid.
	UserName func(uid uint32) string
	// Show returns properties of a unit, as systemctl show does.
	Show func(unit string, props []string) (map[string]string, error)
	// Synced reports whether the kernel says the clock is synchronized.
	Synced func() (bool, error)
	// Wallet and Server ask them over their sockets.
	Wallet func(ctx context.Context, network string) (Wallet, error)
	Server func(ctx context.Context) (Server, error)
	// Keys lists the security keys attached.
	Keys func() ([]fido.Device, error)
}

// maxTipSkew is how far the server's clock may be from the tip of the chain,
// in slots of a second, before doctor warns: blocks come every 20 seconds
// on average, and some minutes apart now and then.
const maxTipSkew = 300

// doctor runs the checks against an env.
type doctor struct {
	ctx context.Context
	env Env
	r   Report
	ids struct{ wallet, server, group uint32 }
	// inGroup is whether the person's session is in the group, without
	// which it cannot read the configuration nor reach the sockets.
	inGroup bool
}

func (d *doctor) add(l Level, format string, args ...any) {
	d.r = append(d.r, Result{l, fmt.Sprintf(format, args...)})
}

// Run runs every check. A check that cannot run without an earlier one, as
// the sockets without the group, is left out and says why.
func Run(ctx context.Context, env Env) Report {
	d := &doctor{ctx: ctx, env: env}
	if !d.users() {
		return d.r
	}
	d.files()
	cfg := walletConf{Network: "preprod"}
	if d.inGroup {
		cfg = d.walletConfig()
	}
	d.isolation(d.units())
	d.clock()
	if !d.inGroup {
		return d.r
	}
	w, werr := env.Wallet(ctx, cfg.Network)
	s, serr := env.Server(ctx)
	d.versions(w, werr, s, serr)
	d.server(s, serr)
	if werr == nil {
		d.wallet(w)
	}
	return d.r
}

// users checks the users and the group install creates, and that the person
// is in the group. Without them nothing else is there to check.
func (d *doctor) users() bool {
	var err error
	if d.ids.group, err = d.env.LookupGroup(deploy.Group); err != nil {
		d.add(Fail, "there is no group %s: mcpcardano is not installed (sudo mcpcardano install)", deploy.Group)
		return false
	}
	for name, id := range map[string]*uint32{deploy.WalletUser: &d.ids.wallet, deploy.ServerUser: &d.ids.server} {
		if *id, err = d.env.LookupUser(name); err != nil {
			d.add(Fail, "there is no user %s: install again with sudo mcpcardano install", name)
			return false
		}
	}
	d.add(OK, "the users %s (%d) and %s (%d), and the group %s (%d)", deploy.WalletUser, d.ids.wallet, deploy.ServerUser, d.ids.server, deploy.Group, d.ids.group)
	d.inGroup = slices.Contains(d.env.Groups, d.ids.group)
	me := d.env.UserName(d.env.UID)
	groups, err := d.env.UserGroups(d.env.UID)
	switch {
	case err != nil:
		d.add(Fail, "cannot read your groups: %v", err)
	case !slices.Contains(groups, d.ids.group):
		d.add(Fail, "you (%s) are not in the group %s: install adds whoever runs it with sudo, or sudo usermod -aG %s %s", me, deploy.Group, deploy.Group, me)
	case !d.inGroup:
		d.add(Fail, "your session is not in the group %s yet, so doctor cannot read the configuration nor reach the sockets: log in again, or run newgrp %s, and run doctor again", deploy.Group, deploy.Group)
	}
	return true
}

// expect is what a path of the installation must be.
type expect struct {
	path string
	kind fs.FileMode // fs.ModeDir, fs.ModeSocket or 0 for a regular file
	uid  uint32
	gid  *uint32 // nil: any group
	mode fs.FileMode
	// atMost makes mode a ceiling: no bit outside it, as for the binaries,
	// which nobody but root may write.
	atMost bool
	// group says that only the group reaches the path.
	group bool
}

func (d *doctor) files() {
	root, group := uint32(0), d.ids.group
	var want []expect
	want = append(want, expect{path: deploy.BinDir, kind: fs.ModeDir, mode: 0o755, atMost: true})
	for _, b := range deploy.Binaries {
		want = append(want, expect{path: filepath.Join(deploy.BinDir, b), mode: 0o755, atMost: true})
	}
	for _, u := range deploy.Units {
		want = append(want, expect{path: filepath.Join(deploy.UnitDir, u), mode: 0o644, atMost: true})
	}
	want = append(want,
		expect{path: deploy.WalletConfigDir, kind: fs.ModeDir, uid: root, gid: &group, mode: 0o750},
		expect{path: deploy.WalletConfig, uid: root, gid: &group, mode: 0o640, group: true},
		expect{path: deploy.ServerConfigDir, kind: fs.ModeDir, uid: root, gid: &group, mode: 0o750},
		expect{path: deploy.ServerConfig, uid: root, gid: &group, mode: 0o640, group: true},
		expect{path: deploy.WalletData, kind: fs.ModeDir, uid: d.ids.wallet, mode: 0o700},
		expect{path: deploy.ServerData, kind: fs.ModeDir, uid: d.ids.server, mode: 0o700},
		expect{path: deploy.WalletRun, kind: fs.ModeDir, uid: d.ids.wallet, gid: &group, mode: 0o750},
		expect{path: deploy.ServiceSocket, kind: fs.ModeSocket, uid: d.ids.wallet, mode: 0o660, group: true},
		expect{path: deploy.AdminSocket, kind: fs.ModeSocket, uid: d.ids.wallet, mode: 0o660, group: true},
		expect{path: deploy.ServerRun, kind: fs.ModeDir, uid: d.ids.server, gid: &group, mode: 0o750},
		expect{path: deploy.MCPSocket, kind: fs.ModeSocket, uid: d.ids.server, mode: 0o660, group: true},
	)
	bad := 0
	for _, e := range want {
		if e.group && !d.inGroup {
			continue
		}
		if msg := d.check(e); msg != "" {
			d.add(Fail, "%s", msg)
			bad++
		}
	}
	if bad == 0 {
		d.add(OK, "the owners and modes of the binaries, the units, the configuration, the data and the sockets")
	}
	for _, u := range deploy.Units {
		p := filepath.Join(deploy.UnitDir, u)
		if b, err := d.env.ReadFile(p); err == nil && string(b) != deploy.Unit(u) {
			d.add(Warn, "%s is not the unit of this version of mcpcardano: sudo mcpcardano install puts it back", p)
		}
	}
}

func (d *doctor) check(e expect) string {
	fi, err := d.env.Lstat(e.path)
	if err != nil {
		return fmt.Sprintf("%s: %v", e.path, err)
	}
	kind := map[fs.FileMode]string{fs.ModeDir: "a directory", fs.ModeSocket: "a socket", 0: "a regular file"}
	if fi.Mode().Type() != e.kind {
		return fmt.Sprintf("%s is not %s", e.path, kind[e.kind])
	}
	uid, gid := d.env.Owner(fi)
	switch mode := fi.Mode().Perm(); {
	case uid != e.uid:
		return fmt.Sprintf("%s is %s's, and must be %s's", e.path, d.env.UserName(uid), d.env.UserName(e.uid))
	case e.gid != nil && gid != *e.gid:
		return fmt.Sprintf("%s has the group %d, and must have %s", e.path, gid, deploy.Group)
	case e.atMost && mode&^e.mode != 0:
		return fmt.Sprintf("%s has mode %04o: nobody but root may write it, or a program with your user could change what runs", e.path, mode)
	case !e.atMost && mode != e.mode:
		return fmt.Sprintf("%s has mode %04o, and must have %04o", e.path, mode, e.mode)
	}
	return ""
}

// walletConf is the part of the wallet's config.json that doctor reads; the
// group can read it.
type walletConf struct {
	Network     string  `json:"network"`
	AdminUID    *uint32 `json:"admin_uid"`
	Development bool    `json:"development"`
}

func (d *doctor) walletConfig() walletConf {
	c := walletConf{Network: "preprod"}
	b, err := d.env.ReadFile(deploy.WalletConfig)
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	switch {
	case err != nil:
		d.add(Fail, "cannot read %s: %v", deploy.WalletConfig, err)
	case c.Development:
		d.add(Fail, "%s has \"development\": true, so the wallet skips its isolation check and may reach the network (section 10.3)", deploy.WalletConfig)
	case c.AdminUID == nil || *c.AdminUID != d.env.UID:
		d.add(Fail, "%s does not admit you at the admin socket: its admin_uid is not %d", deploy.WalletConfig, d.env.UID)
	default:
		d.add(OK, "the wallet's configuration, on %s", c.Network)
	}
	return c
}

// units checks that the units run, are the ones install wrote, and have the
// hardening of section 10.3 as deploy/ has it, with what any drop-in
// changes. It returns the wallet's process, or 0.
func (d *doctor) units() int {
	pid := 0
	for _, u := range deploy.Units {
		want := hardening(deploy.Unit(u))
		keys := slices.Sorted(maps.Keys(want))
		props := append([]string{"ActiveState", "SubState", "Result", "MainPID", "FragmentPath", "DropInPaths", "SystemCallFilter"}, keys...)
		got, err := d.env.Show(u, props)
		if err != nil {
			d.add(Fail, "systemctl show %s: %v", u, err)
			continue
		}
		if got["ActiveState"] != "active" {
			d.add(Fail, "%s is %s (%s, %s): journalctl -u %s says why", u, got["ActiveState"], got["SubState"], got["Result"], u)
		} else {
			d.add(OK, "%s is running", u)
		}
		if f := got["FragmentPath"]; f != filepath.Join(deploy.UnitDir, u) {
			d.add(Fail, "%s comes from %q, not from the unit install wrote", u, f)
		}
		if p := got["DropInPaths"]; p != "" {
			d.add(Warn, "%s has drop-ins, which may change it: %s", u, p)
		}
		var weak []string
		for _, k := range keys {
			v, known := got[k]
			switch {
			case !known:
				d.add(Warn, "this systemd does not know %s, which %s sets", k, u)
			case !sameValue(k, v, want[k]):
				weak = append(weak, fmt.Sprintf("%s=%s, not %s", k, v, want[k]))
			}
		}
		if f := got["SystemCallFilter"]; f == "" || strings.HasPrefix(f, "~") {
			weak = append(weak, "SystemCallFilter is not a list of allowed calls")
		}
		if len(weak) > 0 {
			d.add(Fail, "%s does not have the hardening of section 10.3: %s", u, strings.Join(weak, "; "))
		} else {
			d.add(OK, "%s has the hardening of section 10.3", u)
		}
		if u == deploy.WalletService && got["ActiveState"] == "active" {
			pid, _ = strconv.Atoi(got["MainPID"])
		}
	}
	return pid
}

// hardening reads the settings of a unit's [Service] section that systemctl
// show prints as they are written: all but the command and the filter of
// system calls, which it prints expanded.
func hardening(unit string) map[string]string {
	out := map[string]string{}
	section := ""
	s := bufio.NewScanner(strings.NewReader(unit))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		switch {
		case line == "" || line[0] == '#':
		case line[0] == '[':
			section = line
		case section == "[Service]":
			k, v, _ := strings.Cut(line, "=")
			if k != "ExecStart" && k != "SystemCallFilter" {
				out[k] = v
			}
		}
	}
	return out
}

// sameValue compares a property as systemctl show prints it with the unit's
// setting; a list of address families may come in another order.
func sameValue(key, got, want string) bool {
	if key == "RestrictAddressFamilies" {
		g, w := strings.Fields(got), strings.Fields(want)
		slices.Sort(g)
		slices.Sort(w)
		return slices.Equal(g, w)
	}
	return got == want
}

// isolation reads the network interfaces of the wallet's process, which the
// person can read without root: with PrivateNetwork, only loopback.
func (d *doctor) isolation(pid int) {
	if pid == 0 {
		d.add(Fail, "the wallet is not running, so its isolation cannot be checked")
		return
	}
	b, err := d.env.ReadFile(fmt.Sprintf("/proc/%d/net/dev", pid))
	if err != nil {
		d.add(Fail, "cannot read the wallet's network interfaces: %v", err)
		return
	}
	var other []string
	for _, name := range interfaces(b) {
		if name != "lo" {
			other = append(other, name)
		}
	}
	if len(other) > 0 {
		d.add(Fail, "the wallet reaches the network: it has %s besides loopback", strings.Join(other, ", "))
		return
	}
	d.add(OK, "the wallet has no network, only loopback")
}

// interfaces lists the names in the text of /proc/net/dev, after its two
// lines of headers.
func interfaces(dev []byte) []string {
	var out []string
	for i, line := range strings.Split(string(dev), "\n") {
		if name, _, ok := strings.Cut(line, ":"); ok && i >= 2 {
			out = append(out, strings.TrimSpace(name))
		}
	}
	return out
}

func (d *doctor) clock() {
	ok, err := d.env.Synced()
	switch {
	case err != nil:
		d.add(Fail, "cannot ask the kernel whether the clock is synchronized: %v", err)
	case !ok:
		d.add(Fail, "the kernel says the clock is not synchronized, and the wallet takes the time from it (section 9.3): turn on its synchronization, as with timedatectl set-ntp true")
	default:
		d.add(OK, "the clock is synchronized")
	}
}

// versions checks that the CLI, the wallet and the server are the same
// version, as section 10.6 installs them.
func (d *doctor) versions(w Wallet, werr error, s Server, serr error) {
	if werr != nil {
		d.add(Fail, "the wallet does not answer on %s: %v", deploy.AdminSocket, werr)
	}
	if serr != nil {
		d.add(Fail, "the server does not answer on %s: %v", deploy.MCPSocket, serr)
	}
	if werr != nil || serr != nil {
		return
	}
	wallet := strings.TrimPrefix(w.Software, "mcpcardano-wallet ")
	if wallet != d.env.Version || s.Version != d.env.Version {
		d.add(Fail, "the versions differ: this CLI is %s, the wallet %s and the server %s; install the three together", d.env.Version, wallet, s.Version)
		return
	}
	d.add(OK, "the CLI, the wallet and the server are version %s", d.env.Version)
}

func (d *doctor) server(s Server, err error) {
	if err != nil {
		return
	}
	ds := s.Status.DataSource
	if ds.Status != "ok" || s.Status.Tip == nil {
		d.add(Fail, "the server cannot reach its data source, %s", ds.Name)
		return
	}
	d.add(OK, "the server reaches its data source, %s", ds.Name)
	now, err1 := strconv.ParseInt(s.Status.ServerSlot, 10, 64)
	tip, err2 := strconv.ParseInt(s.Status.Tip.Slot, 10, 64)
	if err1 != nil || err2 != nil {
		d.add(Warn, "cannot compare the clock with the tip of the chain")
		return
	}
	if skew := now - tip; skew > maxTipSkew || skew < -maxTipSkew {
		d.add(Warn, "the clock and the tip of the chain are %d seconds apart: check the clock, or the data source", skew)
		return
	}
	d.add(OK, "the clock and the tip of the chain agree, %d seconds apart", now-tip)
}

func (d *doctor) wallet(w Wallet) {
	if w.Status.Unlocked {
		d.add(OK, "the wallet is unlocked")
	} else {
		d.add(Warn, "the wallet is locked: mcpcardano unlock")
	}
	if w.AuditErr != nil {
		d.add(Fail, "the wallet's audit log or spending record is broken: %v", w.AuditErr)
	} else {
		d.add(OK, "the hash chains of the wallet's audit log (%d entries) and spending record (%d entries)", w.Audit.AuditEntries, w.Audit.LedgerEntries)
	}
	d.keys(len(w.Status.Keys))
}

// keys compares the keys registered with the ones the person reaches. Which
// attached key holds which credential only a touch would tell, so doctor
// does not ask.
func (d *doctor) keys(registered int) {
	attached, err := d.env.Keys()
	if err != nil {
		d.add(Warn, "cannot look for security keys: %v", err)
		return
	}
	var closed []string
	for _, k := range attached {
		if k.Err != nil {
			closed = append(closed, fmt.Sprintf("%s (%s): %v", k.Name, k.Path, k.Err))
		}
	}
	switch {
	case len(closed) > 0:
		d.add(Fail, "you cannot open a security key: %s. Over SSH, sudo mcpcardano install -fido-owner gives your keys to you", strings.Join(closed, "; "))
	case registered == 0:
		d.add(Warn, "no security key is registered: for relevant funds register one, so that a program that captures your password cannot use it (mcpcardano key add; decision 31)")
	case len(attached) == 0:
		d.add(OK, "%s registered; attach one to check that you reach it", count(registered, "security key"))
	default:
		reach := "the one attached"
		if len(attached) > 1 {
			reach = fmt.Sprintf("the %d attached", len(attached))
		}
		d.add(OK, "%s registered, and you reach %s", count(registered, "security key"), reach)
	}
}

// count writes n things, as "1 security key" or "2 security keys".
func count(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}
