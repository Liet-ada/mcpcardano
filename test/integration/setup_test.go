// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build integration

package integration

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The tests of mcpcardano install, uninstall and doctor (decision 134).

const (
	walletConfig = "/etc/mcpcardano-wallet/config.json"
	serverConfig = "/etc/mcpcardano-server/config.json"
	walletData   = "/var/lib/mcpcardano-wallet"
	serverData   = "/var/lib/mcpcardano-server"
)

// asRoot writes a file as root, keeping the owner and the mode of one that
// is there.
func asRoot(t *testing.T, path, content string) {
	t.Helper()
	sudo(t, "mkdir", "-p", filepath.Dir(path))
	if code, out := run(t, content, "sudo", "-n", "tee", path); code != 0 {
		t.Fatalf("writing %s: %s", path, out)
	}
}

// restartUnit restarts a service and waits for its socket, past systemd's
// limit of 5 starts in 10 seconds.
func restartUnit(t *testing.T, unit, socket string) {
	t.Helper()
	sudo(t, "systemctl", "reset-failed", unit)
	run(t, "", "sudo", "-n", "systemctl", "restart", unit)
	for range 50 {
		if fi, err := os.Stat(socket); err == nil && fi.Mode().Type() == os.ModeSocket {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// dropIn adds a drop-in to a unit, or removes it with an empty text.
func dropIn(t *testing.T, unit, text string) {
	t.Helper()
	path := "/etc/systemd/system/" + unit + ".service.d/doctor-test.conf"
	if text == "" {
		sudo(t, "rm", "-f", path)
	} else {
		asRoot(t, path, "[Service]\n"+text+"\n")
	}
	sudo(t, "systemctl", "daemon-reload")
}

// flip flips a bit of a byte in the middle of a file and, called again,
// flips it back, whatever the wallet appended in between.
func flip(t *testing.T, path string) {
	t.Helper()
	sudo(t, "python3", "-c", "import sys\nf = open(sys.argv[1], 'r+b')\nf.seek(40)\nb = f.read(1)\nf.seek(40)\nf.write(bytes([b[0] ^ 1]))", path)
}

func doctor(t *testing.T) (int, string) {
	t.Helper()
	return run(t, "", cli, "doctor")
}

func mustDoctor(t *testing.T) {
	t.Helper()
	if code, out := doctor(t); code != 0 {
		t.Fatalf("doctor: exit %d\n%s", code, out)
	}
}

// TestDoctor provokes, one by one, the failures of the machine that doctor
// must find, and puts each back. The clock and the security keys are
// tested in internal/doctor, with fakes.
func TestDoctor(t *testing.T) {
	phase(t, "doctor")
	mustDoctor(t)

	// A session that is not in the group yet, as right after install.
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	code, out := run(t, "", "sudo", "-n", "setpriv", "--reuid="+me.Uid, "--regid="+me.Gid, "--clear-groups", cli, "doctor")
	if code != 1 || !strings.Contains(out, "newgrp mcpcardano") || !strings.Contains(out, "the wallet has no network") {
		t.Errorf("doctor without the group: exit %d\n%s", code, out)
	}

	wallet, err := os.ReadFile(walletConfig)
	if err != nil {
		t.Fatal(err)
	}
	server, err := os.ReadFile(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name           string
		break_, repair func()
		want           []string
	}{
		{"the wallet's data open",
			func() { sudo(t, "chmod", "0755", walletData) },
			func() { sudo(t, "chmod", "0700", walletData) },
			[]string{walletData + " has mode 0755, and must have 0700"}},
		{"a binary the group writes",
			func() { sudo(t, "chmod", "0775", "/usr/local/bin/mcpcardano-server") },
			func() { sudo(t, "chmod", "0755", "/usr/local/bin/mcpcardano-server") },
			[]string{"/usr/local/bin/mcpcardano-server has mode 0775: nobody but root may write it"}},
		{"the server's hardening",
			func() {
				dropIn(t, "mcpcardano-server", "ProtectHome=no")
				restartUnit(t, "mcpcardano-server", mcpSocket)
			},
			func() {
				dropIn(t, "mcpcardano-server", "")
				restartUnit(t, "mcpcardano-server", mcpSocket)
			},
			[]string{"mcpcardano-server.service does not have the hardening of section 10.3: ProtectHome=no, not yes", "has drop-ins"}},
		{"the wallet on the network",
			func() {
				dropIn(t, "mcpcardano-wallet", "PrivateNetwork=no")
				asRoot(t, walletConfig, strings.Replace(string(wallet), "{", `{"development": true,`, 1))
				restartUnit(t, "mcpcardano-wallet", admin)
			},
			func() {
				dropIn(t, "mcpcardano-wallet", "")
				asRoot(t, walletConfig, string(wallet))
				restartUnit(t, "mcpcardano-wallet", admin)
			},
			[]string{"PrivateNetwork=no, not yes", `"development": true`, "the wallet reaches the network: it has"}},
		{"another version",
			func() {
				sudo(t, "install", "-m", "0755", filepath.Join(work(t), "other", "mcpcardano-server"), "/usr/local/bin/")
				restartUnit(t, "mcpcardano-server", mcpSocket)
			},
			func() {
				sudo(t, "install", "-m", "0755", filepath.Join(work(t), "bin", "mcpcardano-server"), "/usr/local/bin/")
				restartUnit(t, "mcpcardano-server", mcpSocket)
			},
			[]string{"the versions differ", "the server other"}},
		{"no data source",
			func() {
				asRoot(t, serverConfig, strings.Replace(string(server), "127.0.0.1:18080", "127.0.0.1:9", 1))
				restartUnit(t, "mcpcardano-server", mcpSocket)
			},
			func() {
				asRoot(t, serverConfig, string(server))
				restartUnit(t, "mcpcardano-server", mcpSocket)
			},
			[]string{"the server cannot reach its data source"}},
		{"a broken chain",
			func() { flip(t, walletData+"/audit.log") },
			func() { flip(t, walletData+"/audit.log") },
			[]string{"the wallet's audit log or spending record is broken"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.break_()
			code, out := doctor(t)
			c.repair()
			if code != 1 {
				t.Errorf("doctor: exit %d\n%s", code, out)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("doctor does not say %q:\n%s", w, out)
				}
			}
		})
	}
	mustDoctor(t)
}

// asPerson runs the CLI as the person in a new session of the group, which
// uninstall and install may have made again with another id.
func asPerson(t *testing.T, input, command string) (int, string) {
	t.Helper()
	return run(t, input, "sg", "mcpcardano", "-c", cli+" "+command)
}

// TestUninstall removes mcpcardano and checks what is kept, installs it again
// over what was kept, and removes it with its data.
func TestUninstall(t *testing.T) {
	phase(t, "uninstall")
	credential := "/etc/credstore.encrypted/mcpcardano-wallet.unlock"
	sudo(t, cli, "uninstall")
	for _, name := range []string{"mcpcardano-wallet", "mcpcardano-server"} {
		if _, err := user.Lookup(name); err == nil {
			t.Errorf("the user %s is still there", name)
		}
	}
	if _, err := user.LookupGroup("mcpcardano"); err == nil {
		t.Error("the group mcpcardano is still there")
	}
	for _, p := range []string{cli, "/usr/local/bin/mcpcardano-wallet", "/etc/systemd/system/mcpcardano-wallet.service", credential} {
		if code, _ := run(t, "", "sudo", "-n", "test", "-e", p); code == 0 {
			t.Errorf("%s is still there", p)
		}
	}
	// The data stays, root's alone, and the key store in it.
	for _, p := range []string{walletData, serverData} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st := fi.Sys().(*syscall.Stat_t); st.Uid != 0 || st.Gid != 0 || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s is kept as %v, %d:%d", p, fi.Mode(), st.Uid, st.Gid)
		}
	}
	sudo(t, "test", "-f", walletData+"/keystore/master.key")

	// Installed again, it keeps the key store: no password is asked, and
	// the old one opens it.
	if code, out := run(t, "", "sudo", "-n", filepath.Join(work(t), "bin", "mcpcardano"), "install"); code != 0 {
		t.Fatalf("install again: exit %d\n%s", code, out)
	}
	for range 50 {
		if _, err := os.Stat(mcpSocket); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if code, out := asPerson(t, password(t), "unlock"); code != 0 {
		t.Fatalf("unlock after installing again: exit %d\n%s", code, out)
	}
	if code, out := asPerson(t, "", "doctor"); code != 0 {
		t.Fatalf("doctor after installing again: exit %d\n%s", code, out)
	}

	// -delete-data deletes nothing without the phrase, and everything with
	// it.
	if code, out := run(t, "no\n", "sudo", "-n", cli, "uninstall", "-delete-data"); code != 3 {
		t.Errorf("uninstall -delete-data without the phrase: exit %d\n%s", code, out)
	}
	sudo(t, "systemctl", "is-active", "mcpcardano-wallet")
	if code, out := run(t, "delete the wallets\n", "sudo", "-n", cli, "uninstall", "-delete-data"); code != 0 {
		t.Fatalf("uninstall -delete-data: exit %d\n%s", code, out)
	}
	for _, p := range []string{walletData, serverData, "/etc/mcpcardano-wallet", "/etc/mcpcardano-server"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s is still there: %v", p, err)
		}
	}
}
