// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package doctor

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/deploy"
)

// macHealthy is a healthy installation on macOS (decision 140).
func macHealthy() *machine {
	m := healthy()
	m.layout = deploy.MacOS
	l := deploy.MacOS
	for _, p := range []string{deploy.WalletData, deploy.ServerData, deploy.WalletRun, deploy.ServerRun,
		deploy.ServiceSocket, deploy.AdminSocket, deploy.MCPSocket} {
		delete(m.files, p)
	}
	for _, u := range deploy.Units {
		delete(m.files, filepath.Join(deploy.UnitDir, u))
	}
	put := func(p string, mode fs.FileMode, uid, gid uint32, data string) {
		m.files[p] = &file{mode, uid, gid, data}
	}
	m.daemons = map[string]Daemon{}
	for i, p := range l.Services {
		put(filepath.Join(l.ServiceDir, p), 0o644, 0, 0, l.Service(p))
		label := strings.TrimSuffix(p, ".plist")
		m.daemons[label] = Daemon{Path: filepath.Join(l.ServiceDir, p), State: "running", PID: 4343 + i,
			Username: []string{deploy.WalletUser, deploy.ServerUser}[i], Arguments: programArguments(l.Service(p))}
	}
	put(l.WalletData, fs.ModeDir|0o700, walletUID, groupID, "")
	put(l.ServerData, fs.ModeDir|0o700, serverUID, groupID, "")
	put(l.WalletRun, fs.ModeDir|0o750, walletUID, groupID, "")
	put(l.ServerRun, fs.ModeDir|0o750, serverUID, groupID, "")
	put(l.ServiceSocket, fs.ModeSocket|0o660, walletUID, groupID, "")
	put(l.AdminSocket, fs.ModeSocket|0o660, walletUID, groupID, "")
	put(l.MCPSocket, fs.ModeSocket|0o660, serverUID, groupID, "")
	put(deploy.ProfilePath, 0o644, 0, 0, deploy.WalletProfile)
	put(deploy.LogDir, fs.ModeDir|0o750, 0, groupID, "")
	put(deploy.LogDir+"/wallet.log", 0o640, walletUID, groupID, "")
	put(deploy.LogDir+"/server.log", 0o640, serverUID, groupID, "")
	m.wallet.Isolation = "isolation.ok"
	return m
}

func TestMacHealthy(t *testing.T) {
	r := macHealthy().run()
	for _, x := range r {
		if x.Level != OK {
			t.Errorf("a healthy installation gives %s %s", x.Level, x.Detail)
		}
	}
	out := text(r)
	for _, s := range []string{"mcpcardano-wallet is running as mcpcardano-wallet, inside its Seatbelt profile",
		"mcpcardano-server is running as mcpcardano-server", "the wallet has no network: it says so", "Everything is ok."} {
		if !strings.Contains(out, s) {
			t.Errorf("doctor does not say %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "systemd") || strings.Contains(out, ".service") {
		t.Errorf("doctor speaks of systemd on macOS:\n%s", out)
	}
}

func TestMacBroken(t *testing.T) {
	wallet := deploy.WalletLabel
	for _, c := range []struct {
		name   string
		break_ func(m *machine)
		level  Level
		want   string
	}{
		{"the wallet outside its profile", func(m *machine) {
			d := m.daemons[wallet]
			d.Arguments = d.Arguments[3:]
			m.daemons[wallet] = d
		}, Fail, "it runs \"/usr/local/bin/mcpcardano-wallet -config /etc/mcpcardano-wallet/config.json\""},
		{"the wallet as root", func(m *machine) { d := m.daemons[wallet]; d.Username = "root"; m.daemons[wallet] = d }, Fail, `it runs as "root"`},
		{"another plist loaded", func(m *machine) { d := m.daemons[wallet]; d.Path = "/tmp/x.plist"; m.daemons[wallet] = d }, Fail, `it comes from "/tmp/x.plist"`},
		{"the wallet not loaded", func(m *machine) { delete(m.daemons, wallet) }, Fail, "launchd does not run mcpcardano-wallet"},
		{"the wallet stopped", func(m *machine) { d := m.daemons[wallet]; d.State = "not running"; m.daemons[wallet] = d }, Fail, "/Library/Logs/mcpcardano/wallet.log says why"},
		{"the wallet's plist edited", func(m *machine) { m.files["/Library/LaunchDaemons/mcpcardano-wallet.plist"].data += " " }, Fail, "is not the plist of this version"},
		{"the server's plist edited", func(m *machine) { m.files["/Library/LaunchDaemons/mcpcardano-server.plist"].data += " " }, Warn, "is not the plist of this version"},
		{"the profile edited", func(m *machine) { m.files[deploy.ProfilePath].data = "(version 1)\n(allow default)\n" }, Fail, "is not the wallet's Seatbelt profile"},
		{"the profile the group writes", func(m *machine) { m.files[deploy.ProfilePath].mode = 0o664 }, Fail, "/etc/mcpcardano-wallet/wallet.sb has mode 0664"},
		{"a log anyone reads", func(m *machine) { m.files[deploy.LogDir+"/server.log"].mode = 0o644 }, Fail, "server.log has mode 0644, and must have 0640"},
		{"the sockets in /var/run", func(m *machine) { delete(m.files, deploy.MacOS.AdminSocket) }, Fail, "/usr/local/var/run/mcpcardano-wallet/admin.sock"},
		{"a start in development", func(m *machine) { m.wallet.Isolation = "isolation.skipped" }, Fail, "says isolation.skipped, not isolation.ok"},
		{"a start far back", func(m *machine) { m.wallet.Isolation = "" }, Warn, "too far back"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := macHealthy()
			c.break_(m)
			r := m.run()
			found := false
			for _, x := range r {
				if x.Level == c.level && strings.Contains(x.Detail, c.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("no %s with %q:\n%s", c.level, c.want, text(r))
			}
		})
	}
}

// Without root, doctor cannot ask macOS about the clock: it warns, and does
// not fail, since install asked as root.
func TestMacClockWithoutRoot(t *testing.T) {
	m := macHealthy()
	env := m.env()
	env.Synced = func() (bool, error) { return false, errors.New("systemsetup: You need administrator access") }
	r := Run(t.Context(), env)
	if r.Failed() || !strings.Contains(text(r), "cannot ask macOS whether it sets the clock") {
		t.Errorf("the clock without root:\n%s", text(r))
	}
}

func TestParsePrint(t *testing.T) {
	out := "system/mcpcardano-wallet = {\n\tactive count = 1\n\tpath = /Library/LaunchDaemons/mcpcardano-wallet.plist\n" +
		"\tstate = running\n\n\tprogram = /usr/bin/sandbox-exec\n\targuments = {\n\t\t/usr/bin/sandbox-exec\n\t\t-f\n\t\t/etc/mcpcardano-wallet/wallet.sb\n\t}\n\n" +
		"\tusername = mcpcardano-wallet\n\tgroup = mcpcardano\n\tpid = 812\n\tendpoints = {\n\t\tstate = active\n\t}\n}\n"
	d := parsePrint(out)
	want := Daemon{Path: "/Library/LaunchDaemons/mcpcardano-wallet.plist", State: "running", Username: "mcpcardano-wallet", PID: 812,
		Arguments: []string{"/usr/bin/sandbox-exec", "-f", "/etc/mcpcardano-wallet/wallet.sb"}}
	if d.Path != want.Path || d.State != want.State || d.Username != want.Username || d.PID != want.PID || strings.Join(d.Arguments, " ") != strings.Join(want.Arguments, " ") {
		t.Errorf("parsePrint: %+v", d)
	}
	if got := programArguments(deploy.WalletPlist); strings.Join(got, " ") != "/usr/bin/sandbox-exec -f /etc/mcpcardano-wallet/wallet.sb /usr/local/bin/mcpcardano-wallet -config /etc/mcpcardano-wallet/config.json" {
		t.Errorf("programArguments: %q", got)
	}
}

func TestScanIsolation(t *testing.T) {
	// log makes an audit log of n entries of "x", with the given types at
	// the given numbers, counted from 1.
	log := func(n int, at map[int]string) []string {
		l := make([]string, n)
		for i := range l {
			l[i] = "x"
		}
		for i, typ := range at {
			l[i-1] = typ
		}
		return l
	}
	for _, c := range []struct {
		name string
		log  []string
		want string
	}{
		{"a short log", []string{"log.header", "start", "isolation.ok", "peer.refused"}, "isolation.ok"},
		{"the start and its check on two pages", log(250, map[int]string{150: "start", 151: "isolation.ok"}), "isolation.ok"},
		{"the last start counts", log(400, map[int]string{20: "start", 21: "isolation.ok", 300: "start", 301: "isolation.skipped"}), "isolation.skipped"},
		{"a start too far back", log(1500, map[int]string{400: "start", 401: "isolation.ok"}), ""},
		{"no start", log(30, nil), ""},
	} {
		got, err := scanIsolation(uint64(len(c.log)), func(from, limit uint64) ([]string, error) {
			if from < 1 || limit < 1 || limit > 100 || from+limit-1 > uint64(len(c.log)) {
				t.Fatalf("%s: a page from %d of %d", c.name, from, limit)
			}
			return c.log[from-1 : from-1+limit], nil
		})
		if err != nil || got != c.want {
			t.Errorf("%s: %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}
