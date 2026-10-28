// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/Liet-ada/mcpcardano/deploy"
)

// The services: units of systemd on Linux, daemons of launchd on macOS
// (decision 140). The rest of install is the same on both.

// installed reports whether the definitions of the services are there, from
// an earlier install.
func (m *Machine) installed() bool {
	return slices.ContainsFunc(m.l.Services, func(s string) bool { return m.exists(filepath.Join(m.l.ServiceDir, s)) })
}

// label is the name launchd knows a daemon by: its plist without .plist.
func label(plist string) string { return strings.TrimSuffix(plist, ".plist") }

// logs are the files where the two daemons of launchd write, the wallet's
// first.
var logs = []string{deploy.LogDir + "/wallet.log", deploy.LogDir + "/server.log"}

// stopServices stops the server and then the wallet.
func (m *Machine) stopServices() error {
	for _, s := range []string{m.l.Services[1], m.l.Services[0]} {
		var err error
		if m.l.MacOS {
			err = m.bootout(label(s))
		} else {
			err = m.cmd(nil, "systemctl", "stop", s)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// bootout stops a daemon of launchd and unloads it, if it is loaded.
func (m *Machine) bootout(label string) error {
	if _, err := m.run(command{name: "launchctl", args: []string{"print", "system/" + label}}); err != nil {
		return nil // not loaded
	}
	return m.cmd(nil, "launchctl", "bootout", "system/"+label)
}

// installServices writes the definitions of the services. On macOS it also
// writes the wallet's Seatbelt profile and makes what systemd would make:
// the directories of the sockets, which stay since macOS does not empty
// them, and the logs (decision 140).
func (m *Machine) installServices(r ids) error {
	if !m.l.MacOS {
		m.say("Installing the units.")
		for _, u := range m.l.Services {
			if err := m.writeFile(filepath.Join(m.l.ServiceDir, u), []byte(m.l.Service(u)), 0o644, 0, 0); err != nil {
				return err
			}
		}
		return m.cmd(nil, "systemctl", "daemon-reload")
	}
	m.say("Installing the daemons, the wallet's Seatbelt profile and the logs.")
	for _, p := range m.l.Services {
		if err := m.writeFile(filepath.Join(m.l.ServiceDir, p), []byte(m.l.Service(p)), 0o644, 0, 0); err != nil {
			return err
		}
	}
	if err := m.writeFile(deploy.ProfilePath, []byte(deploy.WalletProfile), 0o644, 0, 0); err != nil {
		return err
	}
	for _, d := range []struct {
		dir string
		uid uint32
	}{{m.l.WalletRun, r.wallet.uid}, {m.l.ServerRun, r.server.uid}} {
		if err := m.mkdir(d.dir, 0o750, d.uid, r.group); err != nil {
			return err
		}
	}
	if err := m.mkdir(deploy.LogDir, 0o750, 0, r.group); err != nil {
		return err
	}
	for i, uid := range []uint32{r.wallet.uid, r.server.uid} {
		if err := m.logFile(logs[i], uid, r.group); err != nil {
			return err
		}
	}
	return nil
}

// logFile makes a log if there is none, and gives it to its daemon's user
// and the group, with 0640: the person and doctor read it.
func (m *Machine) logFile(p string, uid, gid uint32) error {
	f, err := os.OpenFile(m.path(p), os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	f.Close()
	if err := m.chown(m.path(p), uid, gid); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if err := os.Chmod(m.path(p), 0o640); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// startServices starts the wallet and then the server, and waits for each
// to open its socket: the service manager says a service started when it
// runs, not when it answers, and the server needs the wallet's sockets.
func (m *Machine) startServices() error {
	sockets := []string{m.l.AdminSocket, m.l.MCPSocket}
	if !m.l.MacOS {
		if err := m.cmd(nil, "systemctl", append([]string{"enable"}, m.l.Services...)...); err != nil {
			return err
		}
		for i, u := range m.l.Services {
			if err := m.cmd(nil, "systemctl", "start", u); err != nil {
				return err
			}
			if err := m.waitFor(sockets[i]); err != nil {
				return fmt.Errorf("install: %s did not open %s in %v: journalctl -u %s says why", u, sockets[i], m.startWait, u)
			}
		}
		return nil
	}
	for i, p := range m.l.Services {
		// launchd never empties the directory of the sockets: one left
		// from before goes, so that waiting for it waits for the daemon.
		if err := os.Remove(m.path(sockets[i])); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("install: %w", err)
		}
		if err := m.cmd(nil, "launchctl", "bootstrap", "system", filepath.Join(m.l.ServiceDir, p)); err != nil {
			return err
		}
		if err := m.waitFor(sockets[i]); err != nil {
			return fmt.Errorf("install: %s did not open %s in %v: %s says why", label(p), sockets[i], m.startWait, logs[i])
		}
	}
	return nil
}
