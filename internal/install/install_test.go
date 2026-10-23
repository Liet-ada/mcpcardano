// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/deploy"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// fake is a machine in a directory: the commands are recorded, and the ones
// that change users or files act on the fake's tables and directory.
type fake struct {
	t       *testing.T
	m       *Machine
	out     bytes.Buffer
	cmds    []string
	stdins  [][]byte // what each command got on its standard input
	owners  map[string]account
	users   map[string]account
	groups  map[string]uint32
	synced  bool
	systemd string            // what systemctl --version says
	fail    map[string]string // a command, as recorded, and what it writes when it fails
	// nextServer is the uid systemd-sysusers gives the server's user.
	nextServer uint32
	source     string
}

const person = "ana"

func newFake(t *testing.T) *fake {
	t.Helper()
	f := &fake{t: t, owners: map[string]account{}, users: map[string]account{person: {1000, 1000}, "bea": {1001, 1001}},
		groups: map[string]uint32{}, synced: true, systemd: "systemd 255 (255.4-1ubuntu8)\n+PAM +AUDIT\n", fail: map[string]string{},
		nextServer: 992, source: t.TempDir()}
	f.m = &Machine{root: t.TempDir(), run: f.run, chown: f.chown, lookupUser: f.lookupUser, lookupGroup: f.lookupGroup,
		synced: func() (bool, error) { return f.synced, nil }, out: &f.out}
	f.touch("/run/systemd/system/.keep")
	for _, b := range deploy.Binaries {
		if err := os.WriteFile(filepath.Join(f.source, b), []byte("binary "+b), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// rel turns a path under the fake's root into the machine's path.
func (f *fake) rel(path string) string {
	r, err := filepath.Rel(f.m.root, path)
	if err != nil || strings.HasPrefix(r, "..") {
		f.t.Fatalf("%s is outside the machine", path)
	}
	return "/" + r
}

func (f *fake) touch(p string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(f.m.path(p)), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(f.m.path(p), []byte("x"), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fake) run(c command) (string, error) {
	rec := c.String()
	if c.as != nil {
		rec = fmt.Sprintf("as %d:%d %s", c.as.uid, c.as.gid, rec)
	}
	f.cmds = append(f.cmds, rec)
	f.stdins = append(f.stdins, c.stdin)
	if out, ok := f.fail[rec]; ok {
		return out, errors.New("exit status 1")
	}
	switch {
	case rec == "systemctl --version":
		return f.systemd, nil
	case c.name == "systemd-sysusers":
		if _, ok := f.users[deploy.WalletUser]; !ok {
			f.users[deploy.WalletUser] = account{991, 991}
			f.users[deploy.ServerUser] = account{f.nextServer, f.nextServer}
			f.groups[deploy.Group] = 990
		}
	case c.name == "userdel":
		delete(f.users, c.args[0])
	case c.name == "groupdel":
		delete(f.groups, c.args[0])
	case slices.Contains(c.args, "init"):
		f.touch(deploy.MasterKey)
	case c.name == "systemd-creds":
		f.touch(deploy.Credential)
	}
	return "", nil
}

func (f *fake) chown(path string, uid, gid uint32) error {
	f.owners[f.rel(path)] = account{uid, gid}
	return nil
}

func (f *fake) lookupUser(name string) (account, error) {
	if a, ok := f.users[name]; ok {
		return a, nil
	}
	return account{}, errors.New("unknown user")
}

func (f *fake) lookupGroup(name string) (uint32, error) {
	if g, ok := f.groups[name]; ok {
		return g, nil
	}
	return 0, errors.New("unknown group")
}

func (f *fake) options() Options { return Options{Person: person, Source: f.source} }

// install runs Check and Install, as the CLI does.
func (f *fake) install(o Options, password string) error {
	f.t.Helper()
	f.cmds, f.stdins = nil, nil
	if err := f.m.Check(&o); err != nil {
		return err
	}
	var secret model.Secret
	if f.m.NeedsPassword() {
		secret = model.Secret(password)
	}
	return f.m.Install(o, secret)
}

func (f *fake) mustInstall(o Options, password string) {
	f.t.Helper()
	if err := f.install(o, password); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fake) read(p string) []byte {
	f.t.Helper()
	b, err := os.ReadFile(f.m.path(p))
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

// is checks the mode and the owner of p.
func (f *fake) is(p string, mode fs.FileMode, owner account) {
	f.t.Helper()
	fi, err := os.Lstat(f.m.path(p))
	if err != nil {
		f.t.Fatal(err)
	}
	if fi.Mode().Perm() != mode {
		f.t.Errorf("%s has mode %v, want %v", p, fi.Mode().Perm(), mode)
	}
	if got := f.owners[p]; got != owner {
		f.t.Errorf("%s is %v's, want %v's", p, got, owner)
	}
}

func (f *fake) walletConfig() map[string]any {
	f.t.Helper()
	var c map[string]any
	if err := json.Unmarshal(f.read(deploy.WalletConfig), &c); err != nil {
		f.t.Fatal(err)
	}
	return c
}

var (
	root    = account{0, 0}
	group   = uint32(990)
	walletA = account{991, 990}
)

func TestFirstInstall(t *testing.T) {
	f := newFake(t)
	o := f.options()
	o.DataSourceURL = "http://127.0.0.1:18080"
	f.mustInstall(o, "correct horse")

	want := []string{
		"systemd-sysusers " + deploy.SysUsersPath,
		"usermod -aG mcpcardano ana",
		"systemctl daemon-reload",
		"/usr/local/bin/mcpcardano-wallet -config /etc/mcpcardano-wallet/config.json -check",
		"/usr/local/bin/mcpcardano-server -config /etc/mcpcardano-server/config.json -check",
		"as 991:990 /usr/local/bin/mcpcardano-wallet -config /etc/mcpcardano-wallet/config.json init",
		"systemctl enable mcpcardano-wallet.service mcpcardano-server.service",
		"systemctl start mcpcardano-wallet.service",
		"systemctl start mcpcardano-server.service",
	}
	if !slices.Equal(f.cmds, want) {
		t.Errorf("commands:\n%s\nwant:\n%s", strings.Join(f.cmds, "\n"), strings.Join(want, "\n"))
	}
	for _, b := range deploy.Binaries {
		p := filepath.Join(deploy.BinDir, b)
		f.is(p, 0o755, root)
		if got := string(f.read(p)); got != "binary "+b {
			t.Errorf("%s holds %q", p, got)
		}
	}
	for _, u := range deploy.Units {
		p := filepath.Join(deploy.UnitDir, u)
		f.is(p, 0o644, root)
		if string(f.read(p)) != deploy.Unit(u) {
			t.Errorf("%s is not the unit of deploy/", p)
		}
	}
	f.is(deploy.SysUsersPath, 0o644, root)
	f.is(deploy.WalletConfigDir, 0o750, account{0, group})
	f.is(deploy.ServerConfigDir, 0o750, account{0, group})
	f.is(deploy.WalletConfig, 0o640, account{0, group})
	f.is(deploy.ServerConfig, 0o640, account{0, group})
	f.is(deploy.WalletData, 0o700, walletA)
	f.is(deploy.ServerData, 0o700, account{992, group})

	w := f.walletConfig()
	if w["network"] != "preprod" || w["service_uid"] != 992.0 || w["admin_uid"] != 1000.0 || w["admin_socket"] != deploy.AdminSocket ||
		w["service_socket"] != deploy.ServiceSocket || w["data_dir"] != deploy.WalletData {
		t.Errorf("the wallet's config.json: %v", w)
	}
	var s serverConfig
	if err := json.Unmarshal(f.read(deploy.ServerConfig), &s); err != nil {
		t.Fatal(err)
	}
	if s.Network != model.Preprod || s.Socket != deploy.MCPSocket || s.WalletSocket != deploy.ServiceSocket ||
		s.DataSource != (dataSourceConfig{"koios", "http://127.0.0.1:18080"}) || s.Wallets == nil {
		t.Errorf("the server's config.json: %+v", s)
	}
	if !bytes.Contains(f.read(deploy.ServerConfig), []byte(`"wallets": []`)) {
		t.Errorf("the server's config.json has no list of wallets:\n%s", f.read(deploy.ServerConfig))
	}

	// The password reached init, once, and is wiped.
	init := slices.IndexFunc(f.cmds, func(c string) bool { return strings.HasSuffix(c, " init") })
	if in := f.stdins[init]; len(in) != len("correct horse\n") || slices.ContainsFunc(in, func(b byte) bool { return b != 0 }) {
		t.Errorf("init's standard input is left as %q", in)
	}
	if f.m.exists(deploy.Credential) || f.m.exists(deploy.FIDORule) {
		t.Error("a first install without options sealed a key or wrote a rule of udev")
	}
	out := f.out.String()
	for _, s := range []string{"newgrp mcpcardano", "mcpcardano unlock", "mcpcardano doctor", "budget of 100 ADA", "20 ADA per transaction", "policy set -template"} {
		if !strings.Contains(out, s) {
			t.Errorf("the output does not say %q:\n%s", s, out)
		}
	}
}

func TestInstallAgainUpdates(t *testing.T) {
	f := newFake(t)
	f.mustInstall(f.options(), "correct horse")
	wallet, server := f.read(deploy.WalletConfig), f.read(deploy.ServerConfig)
	if err := os.WriteFile(filepath.Join(f.source, "mcpcardano-wallet"), []byte("binary v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.out.Reset()
	f.mustInstall(f.options(), "")

	// Section 10.6: the server stops first, and starts last.
	if len(f.cmds) < 2 || f.cmds[0] != "systemctl stop mcpcardano-server.service" || f.cmds[1] != "systemctl stop mcpcardano-wallet.service" {
		t.Errorf("an update starts with:\n%s", strings.Join(f.cmds, "\n"))
	}
	if f.cmds[len(f.cmds)-1] != "systemctl start mcpcardano-server.service" {
		t.Errorf("an update ends with %s", f.cmds[len(f.cmds)-1])
	}
	if slices.ContainsFunc(f.cmds, func(c string) bool { return strings.HasSuffix(c, " init") }) {
		t.Error("an update created the key store again")
	}
	if string(f.read("/usr/local/bin/mcpcardano-wallet")) != "binary v2" {
		t.Error("an update kept the old wallet")
	}
	if !bytes.Equal(f.read(deploy.WalletConfig), wallet) || !bytes.Equal(f.read(deploy.ServerConfig), server) {
		t.Error("an update rewrote a config.json")
	}
	if out := f.out.String(); !strings.Contains(out, "updated") || !strings.Contains(out, "locked") || strings.Contains(out, "template") {
		t.Errorf("an update says:\n%s", out)
	}

	// The installed CLI can update in place: its binaries stay.
	o := f.options()
	o.Source = f.m.path(deploy.BinDir)
	f.mustInstall(o, "")
	if string(f.read("/usr/local/bin/mcpcardano-wallet")) != "binary v2" {
		t.Error("an update from the installed binaries changed them")
	}

	for _, o := range []Options{{Network: model.Preview}, {DataSource: "koios"}, {DataSourceURL: "http://x"}} {
		o.Person, o.Source = person, f.source
		if err := f.install(o, ""); err == nil || !strings.Contains(err.Error(), "keeps its configuration") {
			t.Errorf("an update with %+v: %v", o, err)
		}
	}
	// Another person would take the admin socket.
	o = f.options()
	o.Person = "bea"
	if err := f.install(o, ""); err == nil || !strings.Contains(err.Error(), "admin_uid") {
		t.Errorf("an update by another person: %v", err)
	}
	if len(f.cmds) != 0 {
		t.Errorf("a refused update ran %v", f.cmds)
	}
}

func TestUninstallKeepsTheData(t *testing.T) {
	f := newFake(t)
	f.mustInstall(f.options(), "correct horse")
	f.cmds = nil
	if err := f.m.Uninstall(false); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl disable --now mcpcardano-server.service mcpcardano-wallet.service",
		"systemctl daemon-reload",
		"userdel mcpcardano-wallet",
		"userdel mcpcardano-server",
		"groupdel mcpcardano",
	}
	if !slices.Equal(f.cmds, want) {
		t.Errorf("commands:\n%s", strings.Join(f.cmds, "\n"))
	}
	for _, p := range []string{deploy.SysUsersPath, "/usr/local/bin/mcpcardano", "/usr/local/bin/mcpcardano-wallet", "/etc/systemd/system/mcpcardano-wallet.service"} {
		if f.m.exists(p) {
			t.Errorf("%s is still there", p)
		}
	}
	for _, p := range []string{deploy.WalletConfig, deploy.ServerConfig, deploy.MasterKey} {
		if !f.m.exists(p) {
			t.Errorf("%s is gone", p)
		}
	}
	f.is(deploy.WalletData, 0o700, root)
	f.is(deploy.ServerData, 0o700, root)
	f.is(deploy.MasterKey, 0o600, root)
	f.is(deploy.WalletConfig, 0o640, root)

	// Installed again, with the server's user under another uid: the key
	// store and the configuration come back to their users.
	f.nextServer = 993
	f.out.Reset()
	f.mustInstall(f.options(), "")
	if slices.ContainsFunc(f.cmds, func(c string) bool { return strings.HasSuffix(c, " init") }) {
		t.Error("installing over the kept data created another key store")
	}
	if w := f.walletConfig(); w["service_uid"] != 993.0 || w["admin_uid"] != 1000.0 || w["network"] != "preprod" {
		t.Errorf("the kept configuration became %v", w)
	}
	if !strings.Contains(f.out.String(), "correcting service_uid") {
		t.Errorf("install did not say it corrected service_uid:\n%s", f.out.String())
	}
	f.is(deploy.MasterKey, 0o600, walletA)
	f.is(deploy.WalletData, 0o700, walletA)
	f.is(deploy.ServerData, 0o700, account{993, group})
	f.is(deploy.WalletConfig, 0o640, account{0, group})
}

func TestUninstallDeletesTheData(t *testing.T) {
	f := newFake(t)
	o := f.options()
	o.Unlock = UnlockMachine
	f.touch(tpmDevice)
	f.mustInstall(o, "correct horse")
	if err := f.m.Uninstall(true); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{deploy.WalletConfigDir, deploy.ServerConfigDir, deploy.WalletData, deploy.ServerData, deploy.Credential} {
		if f.m.exists(p) {
			t.Errorf("%s is still there", p)
		}
	}
	// Nothing left to remove: uninstall again does nothing and says so.
	f.cmds = nil
	if err := f.m.Uninstall(false); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.cmds, []string{"systemctl daemon-reload"}) {
		t.Errorf("uninstalling twice ran %v", f.cmds)
	}
}

func TestUnlockByMachine(t *testing.T) {
	f := newFake(t)
	f.touch(tpmDevice)
	o := f.options()
	o.Unlock = UnlockMachine
	f.mustInstall(o, "correct horse")
	seal := slices.IndexFunc(f.cmds, func(c string) bool { return strings.HasPrefix(c, "systemd-creds ") })
	if seal < 0 || f.cmds[seal] != "systemd-creds encrypt --with-key=tpm2+host --name=mcpcardano-wallet.unlock - "+deploy.Credential {
		t.Fatalf("commands:\n%s", strings.Join(f.cmds, "\n"))
	}
	if key := f.stdins[seal]; len(key) != 32 || slices.ContainsFunc(key, func(b byte) bool { return b != 0 }) {
		t.Errorf("the key of the machine is left as %x", key)
	}
	if seal > slices.Index(f.cmds, "systemctl start mcpcardano-wallet.service") {
		t.Error("the key was sealed after the wallet started")
	}
	f.is(filepath.Dir(deploy.Credential), 0o700, root)
	if !strings.Contains(f.out.String(), "bind the key store to this machine") {
		t.Errorf("install does not say how to bind:\n%s", f.out.String())
	}

	// Updating without -unlock keeps it; -unlock password removes it.
	f.mustInstall(f.options(), "")
	if slices.ContainsFunc(f.cmds, func(c string) bool { return strings.HasPrefix(c, "systemd-creds ") }) || !f.m.exists(deploy.Credential) {
		t.Error("an update without -unlock changed the key of the machine")
	}
	o.Unlock = UnlockPassword
	f.mustInstall(o, "")
	if f.m.exists(deploy.Credential) {
		t.Error("-unlock password kept the key of the machine")
	}
}

func TestFIDOOwner(t *testing.T) {
	f := newFake(t)
	o := f.options()
	o.FIDOOwner = true
	if err := f.install(o, "correct horse"); err == nil || !strings.Contains(err.Error(), "60-fido-id.rules") {
		t.Errorf("-fido-owner without systemd's rule: %v", err)
	}
	f.touch("/usr/lib/udev/rules.d/60-fido-id.rules")
	f.mustInstall(o, "correct horse")
	rule := string(f.read(deploy.FIDORule))
	if !strings.Contains(rule, `SUBSYSTEM=="hidraw", ENV{ID_FIDO_TOKEN}=="1", OWNER="ana", MODE="0600"`) {
		t.Errorf("the rule of udev:\n%s", rule)
	}
	for _, c := range []string{"udevadm control --reload", "udevadm trigger --subsystem-match=hidraw --action=change"} {
		if !slices.Contains(f.cmds, c) {
			t.Errorf("install did not run %s", c)
		}
	}
	if strings.Contains(f.out.String(), "Warning") {
		t.Errorf("install warns with systemd's rule there:\n%s", f.out.String())
	}

	g := newFake(t)
	g.mustInstall(g.options(), "correct horse")
	if !strings.Contains(g.out.String(), "Warning: there is no rule 60-fido-id.rules") {
		t.Errorf("install does not warn without systemd's rule:\n%s", g.out.String())
	}
}

func TestCheck(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(*fake, *Options)
		want  string
	}{
		{"not root", func(f *fake, _ *Options) { f.m.euid = 1000 }, "sudo mcpcardano install"},
		{"no systemd", func(f *fake, _ *Options) { os.RemoveAll(f.m.path("/run/systemd")) }, "systemd"},
		{"clock", func(f *fake, _ *Options) { f.synced = false }, "timedatectl set-ntp true"},
		{"no person", func(_ *fake, o *Options) { o.Person = "" }, "-user"},
		{"root as the person", func(_ *fake, o *Options) { o.Person = "root" }, "-user"},
		{"a name udev cannot quote", func(_ *fake, o *Options) { o.Person = `ana"x` }, "user name"},
		{"unknown person", func(_ *fake, o *Options) { o.Person = "carla" }, "no user carla"},
		{"mainnet", func(_ *fake, o *Options) { o.Network = model.Mainnet }, "mainnet"},
		{"unknown network", func(_ *fake, o *Options) { o.Network = "testnet" }, "unknown network"},
		{"data source", func(_ *fake, o *Options) { o.DataSource = "blockfrost" }, "only koios"},
		{"unlock", func(_ *fake, o *Options) { o.Unlock = "tpm" }, "-unlock"},
		{"no TPM2", func(_ *fake, o *Options) { o.Unlock = UnlockMachine }, tpmDevice},
		{"old systemd", func(f *fake, o *Options) {
			o.Unlock = UnlockMachine
			f.touch(tpmDevice)
			f.systemd = "systemd 253 (253.5)\n"
		}, "systemd 254"},
		{"a binary missing", func(f *fake, o *Options) { os.Remove(filepath.Join(o.Source, "mcpcardano-server")) }, "mcpcardano-server must be next to"},
		{"unsupported", func(f *fake, _ *Options) { f.m.unsupported = "for now it runs on Linux only" }, "Linux only"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			o := f.options()
			c.setup(f, &o)
			err := f.install(o, "correct horse")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error with %q", err, c.want)
			}
			if len(f.cmds) > 1 || len(f.cmds) == 1 && f.cmds[0] != "systemctl --version" {
				t.Errorf("a refused install ran %v", f.cmds)
			}
		})
	}
}

func TestCommandFails(t *testing.T) {
	f := newFake(t)
	f.fail["systemd-sysusers "+deploy.SysUsersPath] = "Failed to parse line 7\n"
	err := f.install(f.options(), "correct horse")
	if err == nil || !strings.Contains(err.Error(), "Failed to parse line 7") {
		t.Fatalf("got %v", err)
	}
	if slices.ContainsFunc(f.cmds, func(c string) bool { return strings.HasPrefix(c, "systemctl start") }) {
		t.Error("install went on after a failure")
	}
}

func TestSystemdVersion(t *testing.T) {
	for in, want := range map[string]int{
		"systemd 255 (255.4-1ubuntu8)\n+PAM": 255,
		"systemd 259 (259.9-0ubuntu0.1)":     259,
		"":                                   0,
		"something else":                     0,
	} {
		if got := systemdVersion(in); got != want {
			t.Errorf("systemdVersion(%q) = %d, want %d", in, got, want)
		}
	}
}
