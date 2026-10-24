// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package doctor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/deploy"
	"github.com/Liet-ada/mcpcardano/internal/fido"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
)

// file is a file of the fake machine.
type file struct {
	mode     fs.FileMode
	uid, gid uint32
	data     string
}

type info struct {
	name string
	f    *file
}

func (i info) Name() string       { return filepath.Base(i.name) }
func (i info) Size() int64        { return int64(len(i.f.data)) }
func (i info) Mode() fs.FileMode  { return i.f.mode }
func (i info) ModTime() time.Time { return time.Time{} }
func (i info) IsDir() bool        { return i.f.mode.IsDir() }
func (i info) Sys() any           { return i.f }

// machine is a healthy installation, which each test breaks in one way.
type machine struct {
	files   map[string]*file
	show    map[string]map[string]string
	synced  bool
	wallet  Wallet
	walletE error
	server  Server
	keys    []fido.Device
	groups  []uint32 // the session's
	member  bool     // the person is in the group, for the next session
	noGroup bool
	asked   int // how many times a socket was asked
}

const (
	walletUID, serverUID, groupID, me = 991, 992, 990, 1000
	walletPID                         = 4242
)

func healthy() *machine {
	m := &machine{files: map[string]*file{}, show: map[string]map[string]string{}, synced: true,
		groups: []uint32{me, groupID}, member: true}
	put := func(p string, mode fs.FileMode, uid, gid uint32, data string) {
		m.files[p] = &file{mode, uid, gid, data}
	}
	put(deploy.BinDir, fs.ModeDir|0o755, 0, 0, "")
	for _, b := range deploy.Binaries {
		put(filepath.Join(deploy.BinDir, b), 0o755, 0, 0, "")
	}
	for _, u := range deploy.Units {
		put(filepath.Join(deploy.UnitDir, u), 0o644, 0, 0, deploy.Unit(u))
		props := hardening(deploy.Unit(u))
		props["ActiveState"], props["SubState"], props["Result"] = "active", "running", "success"
		props["MainPID"] = "4343"
		props["FragmentPath"] = filepath.Join(deploy.UnitDir, u)
		props["DropInPaths"] = ""
		props["SystemCallFilter"] = "_llseek accept accept4 access"
		props["ExecStart"] = shown(settings(deploy.Unit(u))["ExecStart"])
		m.show[u] = props
	}
	m.show[deploy.WalletService]["MainPID"] = fmt.Sprint(walletPID)
	put(deploy.WalletConfigDir, fs.ModeDir|0o750, 0, groupID, "")
	put(deploy.ServerConfigDir, fs.ModeDir|0o750, 0, groupID, "")
	put(deploy.WalletConfig, 0o640, 0, groupID, `{"network": "preprod", "admin_uid": 1000, "service_uid": 992}`)
	put(deploy.ServerConfig, 0o640, 0, groupID, `{}`)
	put(deploy.WalletData, fs.ModeDir|0o700, walletUID, groupID, "")
	put(deploy.ServerData, fs.ModeDir|0o700, serverUID, groupID, "")
	put(deploy.WalletRun, fs.ModeDir|0o750, walletUID, groupID, "")
	put(deploy.ServerRun, fs.ModeDir|0o750, serverUID, groupID, "")
	put(deploy.ServiceSocket, fs.ModeSocket|0o660, walletUID, groupID, "")
	put(deploy.AdminSocket, fs.ModeSocket|0o660, walletUID, groupID, "")
	put(deploy.MCPSocket, fs.ModeSocket|0o660, serverUID, groupID, "")
	put(fmt.Sprintf("/proc/%d/net/dev", walletPID), 0o444, walletUID, walletUID,
		"Inter-|   Receive\n face |bytes    packets\n    lo:       0       0    0    0\n")
	m.wallet = Wallet{Software: "mcpcardano-wallet v1", Status: ipc.StatusReport{Unlocked: true, Keys: []ipc.KeyInfo{{Name: "yubikey"}}},
		Audit: ipc.AuditCheck{AuditEntries: 12, LedgerEntries: 3}}
	m.server = Server{Version: "v1"}
	m.server.Status.ServerSlot, m.server.Status.Tip = "100000", &struct {
		Slot string `json:"slot"`
	}{"99980"}
	m.server.Status.DataSource.Name, m.server.Status.DataSource.Status = "koios", "ok"
	m.keys = []fido.Device{{Name: "Yubico YubiKey", Path: "/dev/hidraw1"}}
	return m
}

func (m *machine) env() Env {
	users := map[string]uint32{deploy.WalletUser: walletUID, deploy.ServerUser: serverUID}
	names := map[uint32]string{0: "root", walletUID: deploy.WalletUser, serverUID: deploy.ServerUser, me: "ana"}
	return Env{
		Version: "v1",
		UID:     me,
		Groups:  m.groups,
		Lstat: func(p string) (fs.FileInfo, error) {
			if f, ok := m.files[p]; ok {
				return info{p, f}, nil
			}
			return nil, fs.ErrNotExist
		},
		ReadFile: func(p string) ([]byte, error) {
			if f, ok := m.files[p]; ok {
				return []byte(f.data), nil
			}
			return nil, fs.ErrNotExist
		},
		Owner: func(fi fs.FileInfo) (uint32, uint32) { f := fi.Sys().(*file); return f.uid, f.gid },
		LookupUser: func(name string) (uint32, error) {
			if id, ok := users[name]; ok {
				return id, nil
			}
			return 0, errors.New("unknown user")
		},
		LookupGroup: func(name string) (uint32, error) {
			if name != deploy.Group || m.noGroup {
				return 0, errors.New("unknown group")
			}
			return groupID, nil
		},
		UserGroups: func(uint32) ([]uint32, error) {
			if m.member {
				return []uint32{me, groupID}, nil
			}
			return []uint32{me}, nil
		},
		UserName: func(uid uint32) string { return names[uid] },
		Show: func(unit string, props []string) (map[string]string, error) {
			out := map[string]string{}
			for _, p := range props {
				if v, ok := m.show[unit][p]; ok {
					out[p] = v
				}
			}
			return out, nil
		},
		Synced: func() (bool, error) { return m.synced, nil },
		Wallet: func(context.Context, string) (Wallet, error) { m.asked++; return m.wallet, m.walletE },
		Server: func(context.Context) (Server, error) { m.asked++; return m.server, nil },
		Keys:   func() ([]fido.Device, error) { return m.keys, nil },
	}
}

func (m *machine) run() Report { return Run(context.Background(), m.env()) }

func text(r Report) string {
	var b bytes.Buffer
	r.Write(&b)
	return b.String()
}

func TestHealthy(t *testing.T) {
	r := healthy().run()
	for _, x := range r {
		if x.Level != OK {
			t.Errorf("a healthy installation gives %s %s", x.Level, x.Detail)
		}
	}
	out := text(r)
	for _, s := range []string{"has the hardening of section 10.3", "the wallet has no network", "version v1", "koios", "20 seconds apart", "(12 entries)", "Everything is ok."} {
		if !strings.Contains(out, s) {
			t.Errorf("doctor does not say %q:\n%s", s, out)
		}
	}
}

func TestBroken(t *testing.T) {
	for _, c := range []struct {
		name   string
		break_ func(m *machine)
		level  Level
		want   string
	}{
		{"a binary the group writes", func(m *machine) { m.files["/usr/local/bin/mcpcardano-wallet"].mode = 0o775 }, Fail, "nobody but root may write it"},
		{"a binary of the person's", func(m *machine) { m.files["/usr/local/bin/mcpcardano"].uid = me }, Fail, "/usr/local/bin/mcpcardano is ana's, and must be root's"},
		{"the directory of the binaries", func(m *machine) { m.files[deploy.BinDir].mode = fs.ModeDir | 0o777 }, Fail, "/usr/local/bin has mode 0777"},
		{"the wallet's data open", func(m *machine) { m.files[deploy.WalletData].mode = fs.ModeDir | 0o755 }, Fail, "/var/lib/mcpcardano-wallet has mode 0755, and must have 0700"},
		{"the data of another user", func(m *machine) { m.files[deploy.WalletData].uid = 0 }, Fail, "/var/lib/mcpcardano-wallet is root's, and must be mcpcardano-wallet's"},
		{"the configuration's group", func(m *machine) { m.files[deploy.WalletConfig].gid = 0 }, Fail, "has the group 0, and must have mcpcardano"},
		{"a socket missing", func(m *machine) { delete(m.files, deploy.AdminSocket) }, Fail, deploy.AdminSocket},
		{"a socket as a file", func(m *machine) { m.files[deploy.MCPSocket].mode = 0o660 }, Fail, "is not a socket"},
		{"the server's unit edited", func(m *machine) { m.files["/etc/systemd/system/mcpcardano-server.service"].data += "# edited\n" }, Warn, "is not the unit of this version"},
		{"the wallet's unit edited", func(m *machine) { m.files["/etc/systemd/system/mcpcardano-wallet.service"].data += "# edited\n" }, Fail, "is not the unit of this version"},
		{"a drop-in on the wallet", func(m *machine) {
			m.show[deploy.WalletService]["DropInPaths"] = "/etc/systemd/system/mcpcardano-wallet.service.d/x.conf"
		}, Fail, "has drop-ins"},
		{"another binary", func(m *machine) {
			m.show[deploy.WalletService]["ExecStart"] = shown("/tmp/evil -config /etc/mcpcardano-wallet/config.json")
		}, Fail, `it runs "/tmp/evil -config`},
		{"a setuid binary", func(m *machine) { m.files["/usr/local/bin/mcpcardano"].mode = 0o755 | fs.ModeSetuid }, Fail, "setuid"},
		{"development", func(m *machine) {
			m.files[deploy.WalletConfig].data = `{"network": "preprod", "admin_uid": 1000, "development": true}`
		}, Fail, `"development": true`},
		{"another admin", func(m *machine) { m.files[deploy.WalletConfig].data = `{"network": "preprod", "admin_uid": 1001}` }, Fail, "does not admit you"},
		{"the wallet stopped", func(m *machine) {
			m.show[deploy.WalletService]["ActiveState"], m.show[deploy.WalletService]["SubState"] = "failed", "failed"
		}, Fail, "the wallet is not running"},
		{"a drop-in", func(m *machine) {
			m.show[deploy.ServerService]["DropInPaths"] = "/etc/systemd/system/mcpcardano-server.service.d/x.conf"
		}, Warn, "has drop-ins"},
		{"network for the wallet", func(m *machine) { m.show[deploy.WalletService]["PrivateNetwork"] = "no" }, Fail, "PrivateNetwork=no, not yes"},
		{"the home for the server", func(m *machine) { m.show[deploy.ServerService]["ProtectHome"] = "no" }, Fail, "mcpcardano-server.service does not have the hardening"},
		{"a filter that denies", func(m *machine) { m.show[deploy.WalletService]["SystemCallFilter"] = "~@mount" }, Fail, "SystemCallFilter is not a list of allowed calls"},
		{"an old systemd", func(m *machine) { delete(m.show[deploy.WalletService], "ImportCredential") }, Warn, "does not know ImportCredential"},
		{"another unit file", func(m *machine) {
			m.show[deploy.WalletService]["FragmentPath"] = "/lib/systemd/system/mcpcardano-wallet.service"
		}, Fail, "not from the unit install wrote"},
		{"the wallet on the network", func(m *machine) {
			m.files[fmt.Sprintf("/proc/%d/net/dev", walletPID)].data += "  eth0:  10 1 0 0\n"
		}, Fail, "the wallet reaches the network: it has eth0"},
		{"the clock", func(m *machine) { m.synced = false }, Fail, "not synchronized"},
		{"versions", func(m *machine) { m.server.Version = "v2" }, Fail, "this CLI is v1, the wallet v1 and the server v2"},
		{"the wallet does not answer", func(m *machine) { m.walletE = errors.New("connection refused") }, Fail, "the wallet does not answer"},
		{"no data source", func(m *machine) { m.server.Status.DataSource.Status, m.server.Status.Tip = "unavailable", nil }, Fail, "cannot reach its data source, koios"},
		{"the second source down", func(m *machine) {
			m.server.Status.DataSources = []sourceStatus{{"koios", "ok"}, {"blockfrost", "unavailable"}}
		}, Warn, "the data source blockfrost does not answer: the server uses koios"},
		{"the tip far", func(m *machine) { m.server.Status.Tip.Slot = "90000" }, Warn, "10000 seconds apart"},
		{"locked", func(m *machine) { m.wallet.Status.Unlocked = false }, Warn, "mcpcardano unlock"},
		{"a broken chain", func(m *machine) { m.wallet.AuditErr = errors.New("entry 7: hash") }, Fail, "broken: entry 7"},
		{"no key", func(m *machine) { m.wallet.Status.Keys = nil }, Warn, "decision 31"},
		{"a key out of reach", func(m *machine) { m.keys[0].Err = fs.ErrPermission }, Fail, "-fido-owner"},
		{"not a member", func(m *machine) { m.member = false }, Fail, "you (ana) are not in the group mcpcardano"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := healthy()
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
			if r.Failed() != (c.level == Fail) {
				t.Errorf("Failed() = %v:\n%s", r.Failed(), text(r))
			}
		})
	}
}

func TestNotInstalled(t *testing.T) {
	m := healthy()
	m.noGroup = true
	r := m.run()
	if len(r) != 1 || r[0].Level != Fail || !strings.Contains(r[0].Detail, "sudo mcpcardano install") {
		t.Errorf("without the group:\n%s", text(r))
	}
}

func TestSessionWithoutTheGroup(t *testing.T) {
	m := healthy()
	m.groups = []uint32{me}
	r := m.run()
	out := text(r)
	if !strings.Contains(out, "newgrp mcpcardano") || !r.Failed() {
		t.Errorf("a session without the group:\n%s", out)
	}
	// What needs the group is left out, not failed one by one.
	if m.asked != 0 || strings.Contains(out, deploy.AdminSocket) || strings.Contains(out, deploy.WalletConfig) {
		t.Errorf("doctor tried what needs the group:\n%s", out)
	}
	if !strings.Contains(out, "the wallet has no network") || !strings.Contains(out, "the clock is synchronized") {
		t.Errorf("doctor left out what it can check without the group:\n%s", out)
	}
}

func TestReorderedFamilies(t *testing.T) {
	m := healthy()
	m.show[deploy.ServerService]["RestrictAddressFamilies"] = "AF_INET6 AF_UNIX AF_INET"
	if r := m.run(); r.Failed() {
		t.Errorf("the same families in another order:\n%s", text(r))
	}
}

func TestHardening(t *testing.T) {
	h := hardening(deploy.WalletUnit)
	for k, v := range map[string]string{"PrivateNetwork": "yes", "RestrictAddressFamilies": "AF_UNIX", "CapabilityBoundingSet": "",
		"LimitMEMLOCK": "infinity", "User": deploy.WalletUser, "ProtectSystem": "strict"} {
		if got, ok := h[k]; !ok || got != v {
			t.Errorf("%s = %q, %v; want %q", k, got, ok, v)
		}
	}
	for _, k := range []string{"ExecStart", "SystemCallFilter", "Description", "WantedBy", "Before"} {
		if _, ok := h[k]; ok {
			t.Errorf("hardening has %s", k)
		}
	}
	if _, ok := hardening(deploy.ServerUnit)["PrivateNetwork"]; ok {
		t.Error("the server's unit has no PrivateNetwork, and hardening gives it one")
	}
}

func TestReport(t *testing.T) {
	r := Report{{OK, "a"}, {Warn, "b"}, {Fail, "c"}, {Fail, "d"}}
	if out := text(r); !strings.Contains(out, "FAIL  c\n") || !strings.Contains(out, "warn  b\n") || !strings.Contains(out, "2 failed and 1 warned.") {
		t.Errorf("report:\n%s", out)
	}
	if out := text(Report{{Warn, "b"}}); !strings.Contains(out, "Nothing failed; 1 warned.") {
		t.Errorf("report:\n%s", out)
	}
}

func TestNoControlReachesTheTerminal(t *testing.T) {
	m := healthy()
	m.server.Version = "v1\x1b]0;owned\x07\x1b[2J\u202eevil\nok    all is fine"
	out := text(m.run())
	if strings.ContainsAny(out, "\x1b\x07\u202e") || strings.Contains(out, "\nok    all is fine") {
		t.Errorf("doctor wrote what the server said as it came:\n%q", out)
	}
	if !strings.Contains(out, "the server v1?]0;owned??[2J?evil?ok    all is fine") {
		t.Errorf("doctor does not show the version, made visible:\n%s", out)
	}
}

// shown writes a command as systemctl show prints an ExecStart.
func shown(cmd string) string {
	path, _, _ := strings.Cut(cmd, " ")
	return "{ path=" + path + " ; argv[]=" + cmd + " ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
}

func TestArgv(t *testing.T) {
	// As systemd 259 printed it.
	got := argv("{ path=/bin/echo ; argv[]=/bin/echo otro -x ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }")
	if got != "/bin/echo otro -x" {
		t.Errorf("argv = %q", got)
	}
	if argv("") != "" {
		t.Error("argv of nothing")
	}
}
