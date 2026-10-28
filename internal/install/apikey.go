// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Liet-ada/mcpcardano/deploy"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The API keys of the server's data sources, as Blockfrost's project id
// (decision 138): encrypted with systemd-creds in the credential store, with
// the TPM2 and the host's key if there is a TPM2 and the host's key alone if
// not. The server's unit imports them; systemd decrypts them for the server
// alone, in memory. macOS has no systemd-creds: there a key is a file of the
// server's user with mode 0600 in its secrets/, which the separate user keeps
// from the agent (decision 139). mcpcardano apikey sets and removes them.

// keyName is the name of an API key, as the server's config.json names it
// in a source's secret.
var keyName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// projectID checks the shape of a Blockfrost key as its client does, so
// that a mistyped one is caught before the server starts.
func projectID(key []byte) bool {
	if len(key) == 0 || len(key) > 128 {
		return false
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// errProjectID reports a key that is not a Blockfrost project id.
var errProjectID = errors.New("the project id of Blockfrost has 1 to 128 letters and digits")

// writeAPIKey encrypts an API key for the server. The key reaches
// systemd-creds on its standard input. A copy in clear in the server's
// secrets/, from development or an earlier version, is removed.
func (m *Machine) writeAPIKey(name string, key model.Secret) error {
	if !projectID(key) {
		return fmt.Errorf("install: %w", errProjectID)
	}
	if m.l.MacOS {
		return m.writePlainKey(name, key)
	}
	cred := deploy.ServerCredential + name
	m.say("Encrypting the API key %s for the server, in %s.", name, deploy.CredStore)
	if err := m.mkdir(deploy.CredStore, 0o700, 0, 0); err != nil {
		return err
	}
	if err := m.cmd(key, "systemd-creds", "encrypt", "--with-key=auto", "--name="+cred, "-", filepath.Join(deploy.CredStore, cred)); err != nil {
		return err
	}
	return m.removePlainKey(name)
}

// plainKey is where the server reads a key in clear.
func (m *Machine) plainKey(name string) string { return filepath.Join(m.l.ServerData, "secrets", name) }

// writePlainKey writes a key where the server reads it on macOS, for its
// user alone.
func (m *Machine) writePlainKey(name string, key model.Secret) error {
	server, err := m.lookupUser(deploy.ServerUser)
	if err != nil {
		return fmt.Errorf("install: no user %s: %v", deploy.ServerUser, err)
	}
	group, err := m.lookupGroup(deploy.Group)
	if err != nil {
		return fmt.Errorf("install: no group %s: %v", deploy.Group, err)
	}
	dir := filepath.Dir(m.plainKey(name))
	m.say("Writing the API key %s for the server, in %s, which its user alone reads.", name, dir)
	if err := m.mkdir(dir, 0o700, server.uid, group); err != nil {
		return err
	}
	return m.writeFile(m.plainKey(name), key, 0o600, server.uid, group)
}

func (m *Machine) removePlainKey(name string) error {
	p := m.plainKey(name)
	err := os.Remove(m.path(p))
	switch {
	case err == nil:
		m.say("Removed the copy in clear, %s.", p)
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// CheckAPIKey checks, before a key is asked, that mcpcardano apikey can
// run: as root, with systemd 254 or later on Linux, for a name a
// configuration can give.
func (m *Machine) CheckAPIKey(name string) error {
	if err := m.checkSystem("apikey"); err != nil {
		return err
	}
	if !keyName.MatchString(name) {
		return fmt.Errorf("apikey: %q is not a name of a key: 1 to 64 letters, digits, - and _", name)
	}
	if m.l.MacOS {
		return nil
	}
	return m.checkCredentials("apikey", "keeping an API key encrypted")
}

// SetAPIKey encrypts the key for the server, in place of one it had, and
// restarts the server if it runs. CheckAPIKey must have passed.
func (m *Machine) SetAPIKey(name string, key model.Secret) error {
	if !projectID(key) {
		return fmt.Errorf("apikey: %w", errProjectID)
	}
	if err := m.writeAPIKey(name, key); err != nil {
		return err
	}
	return m.restartServer()
}

// RemoveAPIKey removes the key and restarts the server if it runs: a source
// that needed it no longer answers, and the server goes on with the others.
func (m *Machine) RemoveAPIKey(name string) error {
	p := filepath.Join(deploy.CredStore, deploy.ServerCredential+name)
	if m.l.MacOS {
		p = m.plainKey(name)
	}
	err := os.Remove(m.path(p))
	switch {
	case err == nil:
		m.say("Removed the API key %s.", name)
	case errors.Is(err, fs.ErrNotExist):
		m.say("There is no API key %s.", name)
	default:
		return fmt.Errorf("apikey: %w", err)
	}
	if err := m.removePlainKey(name); err != nil {
		return err
	}
	return m.restartServer()
}

func (m *Machine) restartServer() error {
	m.say("Restarting the server, if it runs.")
	if m.l.MacOS {
		if _, err := m.run(command{name: "launchctl", args: []string{"print", "system/" + deploy.ServerLabel}}); err != nil {
			return nil // not loaded
		}
		return m.cmd(nil, "launchctl", "kickstart", "-k", "system/"+deploy.ServerLabel)
	}
	return m.cmd(nil, "systemctl", "try-restart", deploy.ServerService)
}
