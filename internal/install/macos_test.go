// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/deploy"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// newMacFake is a fake macOS: launchd and dscl instead of systemd, and the
// layout of decision 140. A user and a group already take the id 400.
func newMacFake(t *testing.T) *fake {
	f := newFake(t)
	f.m.l = deploy.MacOS
	os.RemoveAll(f.m.path("/run"))
	f.users["_taken"] = account{400, 400}
	f.groups["_taken"] = 400
	return f
}

// macOS plays dscl and launchctl. launchd leaves a daemon's sockets when it
// stops it, as macOS does.
func (f *fake) macOS(c command) (string, error) {
	a := c.args
	switch {
	case c.name == "dscl" && a[1] == "-list":
		var b strings.Builder
		if a[2] == "/Users" {
			for n, u := range f.users {
				fmt.Fprintf(&b, "%-20s %d\n", n, u.uid)
			}
		} else {
			for n, g := range f.groups {
				fmt.Fprintf(&b, "%-20s %d\n", n, g)
			}
		}
		return b.String(), nil
	case c.name == "dscl" && a[1] == "-create" && len(a) == 5:
		kind, name := path.Split(a[2])
		v, _ := strconv.ParseUint(a[4], 10, 32)
		u := f.users[name]
		switch {
		case a[3] == "UniqueID":
			u.uid = uint32(v)
			f.users[name] = u
		case a[3] == "PrimaryGroupID" && kind == "/Groups/":
			f.groups[name] = uint32(v)
		case a[3] == "PrimaryGroupID":
			u.gid = uint32(v)
			f.users[name] = u
		}
	case c.name == "dscl" && a[1] == "-delete":
		if kind, name := path.Split(a[2]); kind == "/Users/" {
			delete(f.users, name)
		} else {
			delete(f.groups, name)
		}
	case a[0] == "print":
		if !f.loaded[strings.TrimPrefix(a[1], "system/")] {
			return "Could not find service", errors.New("exit status 113")
		}
	case a[0] == "bootstrap":
		l := strings.TrimSuffix(filepath.Base(a[2]), ".plist")
		f.loaded[l] = true
		switch {
		case f.silent == l:
		case l == deploy.WalletLabel:
			f.touch(f.m.l.ServiceSocket)
			f.touch(f.m.l.AdminSocket)
		case l == deploy.ServerLabel:
			f.touch(f.m.l.MCPSocket)
		}
	case a[0] == "bootout":
		delete(f.loaded, strings.TrimPrefix(a[1], "system/"))
	}
	return "", nil
}

// The ids dscl gives: the first free from 400, which _taken holds.
var (
	macGroup  = uint32(401)
	macWallet = account{401, 401}
	macServer = account{402, 401}
)

func (f *fake) ran(cmd string) bool { return slices.Contains(f.cmds, cmd) }

func TestMacFirstInstall(t *testing.T) {
	f := newMacFake(t)
	f.mustInstall(f.options(), "correct horse")
	for _, c := range f.cmds {
		if strings.HasPrefix(c, "systemctl") || strings.HasPrefix(c, "systemd") || strings.HasPrefix(c, "usermod") {
			t.Errorf("ran %q on macOS", c)
		}
	}
	if f.groups[deploy.Group] != macGroup || f.users[deploy.WalletUser] != macWallet || f.users[deploy.ServerUser] != macServer {
		t.Errorf("ids: group %d, wallet %v, server %v", f.groups[deploy.Group], f.users[deploy.WalletUser], f.users[deploy.ServerUser])
	}
	for _, c := range []string{
		"dscl . -create /Users/mcpcardano-wallet UserShell /usr/bin/false",
		"dscl . -create /Users/mcpcardano-wallet NFSHomeDirectory /var/empty",
		"dscl . -create /Users/mcpcardano-server IsHidden 1",
		"dseditgroup -o edit -a ana -t user mcpcardano",
		"as 401:401 /usr/local/bin/mcpcardano-wallet -config /etc/mcpcardano-wallet/config.json init",
	} {
		if !f.ran(c) {
			t.Errorf("did not run %q", c)
		}
	}
	wallet := slices.Index(f.cmds, "launchctl bootstrap system /Library/LaunchDaemons/mcpcardano-wallet.plist")
	server := slices.Index(f.cmds, "launchctl bootstrap system /Library/LaunchDaemons/mcpcardano-server.plist")
	if wallet < 0 || server < wallet {
		t.Errorf("the wallet starts at %d and the server at %d:\n%s", wallet, server, strings.Join(f.cmds, "\n"))
	}

	for p, want := range map[string]string{
		"/Library/LaunchDaemons/mcpcardano-wallet.plist": deploy.WalletPlist,
		"/Library/LaunchDaemons/mcpcardano-server.plist": deploy.ServerPlist,
		deploy.ProfilePath: deploy.WalletProfile,
	} {
		if string(f.read(p)) != want {
			t.Errorf("%s is not the one in deploy/", p)
		}
		f.is(p, 0o644, root)
	}
	f.is(deploy.MacWalletRun, 0o750, macWallet)
	f.is(deploy.MacServerRun, 0o750, macServer)
	f.is(deploy.LogDir, 0o750, account{0, macGroup})
	f.is(deploy.LogDir+"/wallet.log", 0o640, macWallet)
	f.is(deploy.LogDir+"/server.log", 0o640, macServer)
	f.is(deploy.MacWalletData, 0o700, macWallet)
	f.is(deploy.MacServerData, 0o700, macServer)
	f.is(deploy.WalletConfig, 0o640, account{0, macGroup})

	w := f.walletConfig()
	if w["data_dir"] != deploy.MacWalletData || w["admin_socket"] != deploy.MacOS.AdminSocket || w["service_socket"] != deploy.MacOS.ServiceSocket {
		t.Errorf("the wallet's config.json: %v", w)
	}
	var s map[string]any
	if err := json.Unmarshal(f.read(deploy.ServerConfig), &s); err != nil {
		t.Fatal(err)
	}
	if s["data_dir"] != deploy.MacServerData || s["socket"] != deploy.MacOS.MCPSocket || s["wallet_socket"] != deploy.MacOS.ServiceSocket {
		t.Errorf("the server's config.json: %v", s)
	}
}

func TestMacInstallAgain(t *testing.T) {
	f := newMacFake(t)
	f.mustInstall(f.options(), "correct horse")
	f.mustInstall(f.options(), "")
	server := slices.Index(f.cmds, "launchctl bootout system/mcpcardano-server")
	wallet := slices.Index(f.cmds, "launchctl bootout system/mcpcardano-wallet")
	if server < 0 || wallet < server {
		t.Errorf("the server stops at %d and the wallet at %d", server, wallet)
	}
	if f.users[deploy.WalletUser] != macWallet || slices.ContainsFunc(f.cmds, func(c string) bool { return strings.HasPrefix(c, "dscl . -create") }) {
		t.Error("install made the users again")
	}

	// The socket the wallet left stays in its directory: install waits for
	// a new one, not for that.
	f.silent = deploy.WalletLabel
	err := f.install(f.options(), "")
	if err == nil || !strings.Contains(err.Error(), "/Library/Logs/mcpcardano/wallet.log") {
		t.Errorf("a wallet that does not answer: %v", err)
	}
}

func TestMacRefuses(t *testing.T) {
	f := newMacFake(t)
	for _, o := range []Options{
		{Person: person, Source: f.source, Unlock: UnlockMachine},
		{Person: person, Source: f.source, FIDOOwner: true},
	} {
		if err := f.m.Check(&o); err == nil {
			t.Errorf("Check(%+v) passed", o)
		}
	}
	f.synced = false
	o := f.options()
	if err := f.m.Check(&o); err == nil || !strings.Contains(err.Error(), "systemsetup -setusingnetworktime on") {
		t.Errorf("a clock that does not sync: %v", err)
	}
}

func TestMacBlockfrost(t *testing.T) {
	f := newMacFake(t)
	o := f.options()
	o.DataSource = "blockfrost,koios"
	o.BlockfrostKey = model.Secret("preprodAbc123")
	f.mustInstall(o, "correct horse")
	for _, c := range f.cmds {
		if strings.Contains(c, "systemd") || strings.Contains(c, "systemctl") {
			t.Errorf("ran %q on macOS", c)
		}
	}
	key := deploy.MacServerData + "/secrets/blockfrost"
	if string(f.read(key)) != "preprodAbc123" {
		t.Errorf("%s holds %q", key, f.read(key))
	}
	f.is(key, 0o600, macServer)
	f.is(deploy.MacServerData+"/secrets", 0o700, macServer)

	f.cmds = nil
	if err := f.m.CheckAPIKey("blockfrost"); err != nil {
		t.Fatal(err)
	}
	if err := f.m.SetAPIKey("blockfrost", model.Secret("preprodDef456")); err != nil {
		t.Fatal(err)
	}
	if string(f.read(key)) != "preprodDef456" || !f.ran("launchctl kickstart -k system/mcpcardano-server") {
		t.Errorf("set: %q, ran %v", f.read(key), f.cmds)
	}
	if err := f.m.RemoveAPIKey("blockfrost"); err != nil {
		t.Fatal(err)
	}
	if f.m.exists(key) {
		t.Error("the key is still there")
	}
}

func TestMacUninstall(t *testing.T) {
	for _, deleteData := range []bool{false, true} {
		f := newMacFake(t)
		f.mustInstall(f.options(), "correct horse")
		f.cmds = nil
		if err := f.m.CheckUninstall(); err != nil {
			t.Fatal(err)
		}
		if err := f.m.Uninstall(deleteData); err != nil {
			t.Fatal(err)
		}
		server := slices.Index(f.cmds, "launchctl bootout system/mcpcardano-server")
		wallet := slices.Index(f.cmds, "launchctl bootout system/mcpcardano-wallet")
		if server < 0 || wallet < server {
			t.Errorf("the server stops at %d and the wallet at %d", server, wallet)
		}
		for _, c := range []string{"dscl . -delete /Users/mcpcardano-wallet", "dscl . -delete /Users/mcpcardano-server", "dscl . -delete /Groups/mcpcardano"} {
			if !f.ran(c) {
				t.Errorf("did not run %q", c)
			}
		}
		for _, p := range []string{"/Library/LaunchDaemons/mcpcardano-wallet.plist", "/Library/LaunchDaemons/mcpcardano-server.plist",
			deploy.ProfilePath, deploy.MacWalletRun, deploy.MacServerRun, "/usr/local/bin/mcpcardano-wallet"} {
			if f.m.exists(p) {
				t.Errorf("%s is still there", p)
			}
		}
		for _, p := range []string{deploy.MacWalletData, deploy.MacServerData, deploy.LogDir, deploy.WalletConfig} {
			if f.m.exists(p) == deleteData {
				t.Errorf("deleteData %v: %s there: %v", deleteData, p, f.m.exists(p))
			}
		}
		if !deleteData {
			f.is(deploy.MacWalletData, 0o700, root)
			f.is(deploy.LogDir+"/wallet.log", 0o640, root)
		}
	}
}

func TestFreeID(t *testing.T) {
	f := newMacFake(t)
	for i := firstID; i <= lastID; i++ {
		f.users[fmt.Sprint("u", i)] = account{uint32(i), 0}
	}
	if _, err := f.m.freeID("/Users", "UniqueID"); err == nil {
		t.Error("found a free id in a full range")
	}
	delete(f.users, "u450")
	if id, err := f.m.freeID("/Users", "UniqueID"); err != nil || id != 450 {
		t.Errorf("freeID: %d, %v", id, err)
	}
}

func TestNetworkTime(t *testing.T) {
	for out, want := range map[string]bool{"Network Time: On\n": true, "Network Time: Off\n": false} {
		if got, err := networkTime(out); err != nil || got != want {
			t.Errorf("%q: %v, %v", out, got, err)
		}
	}
	// Without root, systemsetup says so and exits with 0.
	if _, err := networkTime("You need administrator access to run this tool... exiting!\n"); err == nil {
		t.Error("an answer without root counts as one")
	}
}
