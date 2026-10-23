// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package install installs, updates and removes mcpcardano as root, as
// sections 10.1 and 10.6 say and decision 134 fixes for Linux: the three
// binaries, the users and the group, the units of systemd, the two
// config.json, the key store and, if the person asks for it, the unlock bound
// to the machine. It never unlocks the wallet, and never rewrites a
// master.key. macOS arrives with step 7 of H-3.
package install

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/deploy"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/policy"
)

// The ways the wallet unlocks at its start (section 10.1, point 5).
const (
	UnlockPassword = "password"
	UnlockMachine  = "machine"
)

// Options are what the person chose. The network and the data source only
// apply to a first install: a later one keeps the config.json as they are.
type Options struct {
	// Person is the user who joins the group and whom the wallet's admin
	// socket admits: whoever ran sudo.
	Person string
	// Network and DataSource are empty when not given: preprod and Koios.
	Network       model.Network
	DataSource    string
	DataSourceURL string
	// Unlock is UnlockPassword, UnlockMachine, or empty to keep what there
	// is (the password, on a first install).
	Unlock string
	// FIDOOwner installs a rule of udev that gives the person's security
	// keys to the person alone, for a session over SSH.
	FIDOOwner bool
	// Source is the directory that holds the three binaries.
	Source string
}

// minSystemdForCredentials is the first systemd with ImportCredential=, which
// the wallet's unit uses for the key of the machine (decision 132).
const minSystemdForCredentials = 254

// tpmDevice is the kernel's resource manager of the TPM2, which systemd-creds
// uses.
const tpmDevice = "/dev/tpmrm0"

// fidoRules are where systemd's rule that marks security keys may live; it
// sets ID_FIDO_TOKEN, and the rule of uaccess gives them to the person at
// the machine.
var fidoRules = []string{
	"/etc/udev/rules.d/60-fido-id.rules",
	"/usr/lib/udev/rules.d/60-fido-id.rules",
	"/lib/udev/rules.d/60-fido-id.rules",
}

// userName is a portable user name (POSIX 3.437), which a rule of udev can
// quote as it is.
var userName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// safePath is where the system's commands are taken from, whatever PATH
// sudo passed on: a directory the person can write must never lend root a
// systemctl, nor a systemd-creds that gets the key of the machine.
var safePath = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// SystemCommand returns the path of one of the system's commands, found in
// safePath alone. A path is returned as it is.
func SystemCommand(name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}
	for _, d := range safePath {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("install: there is no %s in %s", name, strings.Join(safePath, ":"))
}

// SafeEnv is the whole environment of the commands install runs.
func SafeEnv() []string { return []string{"PATH=" + strings.Join(safePath, ":")} }

// command is a command install runs: as root, or as a user of a service.
type command struct {
	name  string
	args  []string
	stdin []byte
	as    *account
}

func (c command) String() string { return strings.Join(append([]string{c.name}, c.args...), " ") }

// account is a user and the group a command runs with.
type account struct{ uid, gid uint32 }

// Machine is what install touches: the real one, or a directory and a
// recorder of commands in the tests.
type Machine struct {
	// root prefixes every path: "/" on the machine.
	root string
	// run runs a command and returns what it wrote.
	run func(command) (string, error)
	// chown gives a file, which it does not follow if it is a link, to a
	// user and a group.
	chown func(path string, uid, gid uint32) error
	// lookupUser and lookupGroup read the users and groups of the machine.
	lookupUser  func(name string) (account, error)
	lookupGroup func(name string) (uint32, error)
	// synced reports whether the kernel says the clock is synchronized.
	synced func() (bool, error)
	// euid is the effective user of the process.
	euid int
	// startWait is how long a service may take to open its socket.
	startWait time.Duration
	// unsupported says why install cannot run on this system, if it cannot.
	unsupported string
	out         io.Writer
}

func (m *Machine) path(p string) string { return filepath.Join(m.root, p) }

func (m *Machine) exists(p string) bool {
	_, err := os.Lstat(m.path(p))
	return err == nil
}

func (m *Machine) say(format string, args ...any) { fmt.Fprintf(m.out, format+"\n", args...) }

// cmd runs a command as root; its output goes into the error if it fails.
func (m *Machine) cmd(stdin []byte, name string, args ...string) error {
	c := command{name: name, args: args, stdin: stdin}
	if out, err := m.run(c); err != nil {
		return fmt.Errorf("install: %s: %v%s", c, err, indent(out))
	}
	return nil
}

func indent(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return ""
	}
	return "\n  " + strings.ReplaceAll(out, "\n", "\n  ")
}

// writeFile puts data at p with its mode and owner, through a temporary file
// in the same directory and a rename, so that nothing ever sees half of it.
func (m *Machine) writeFile(p string, data []byte, mode fs.FileMode, uid, gid uint32) error {
	dst := m.path(p)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".*")
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp) // after the rename there is nothing to remove
	_, err = f.Write(data)
	for _, step := range []func() error{func() error { return f.Chmod(mode) }, f.Sync} {
		if err == nil {
			err = step()
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	// The owner comes after the rename: until then the file is root's,
	// which only narrows who can read it.
	if err == nil {
		err = m.chown(dst, uid, gid)
	}
	if err != nil {
		return fmt.Errorf("install: writing %s: %w", p, err)
	}
	return nil
}

// copyFile copies the file src, outside root, to p. src must be the file
// itself: it is opened without following a link, so that what Check saw is
// what is copied.
func (m *Machine) copyFile(src, p string, mode fs.FileMode) error {
	f, err := openNoFollow(src)
	if err != nil {
		return fmt.Errorf("install: %s must be the binary itself, not a link: %w", src, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("install: %s is not a regular file", src)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return m.writeFile(p, data, mode, 0, 0)
}

// mkdir makes the directory p, its parents as root with 0755, and gives p
// its mode and owner, also if it was there.
func (m *Machine) mkdir(p string, mode fs.FileMode, uid, gid uint32) error {
	dir := m.path(p)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if err := os.Mkdir(dir, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("install: %w", err)
	}
	if err := m.isDir(p); err != nil {
		return err
	}
	if err := m.chown(dir, uid, gid); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return m.chmodDir(p, mode)
}

// isDir checks that p is a directory, and not a link to one.
func (m *Machine) isDir(p string) error {
	if fi, err := os.Lstat(m.path(p)); err != nil || !fi.IsDir() {
		return fmt.Errorf("install: %s is not a directory", p)
	}
	return nil
}

// chmodDir gives the directory p its mode. chmod follows a link, so p must
// be the directory itself.
func (m *Machine) chmodDir(p string, mode fs.FileMode) error {
	if err := m.isDir(p); err != nil {
		return err
	}
	if err := os.Chmod(m.path(p), mode); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// chownTree gives p and everything under it to uid and gid, without
// following links.
func (m *Machine) chownTree(p string, uid, gid uint32) error {
	err := filepath.WalkDir(m.path(p), func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return m.chown(path, uid, gid)
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// owner returns the owner of p.
func (m *Machine) owner(p string) (account, error) {
	fi, err := os.Lstat(m.path(p))
	if err != nil {
		return account{}, err
	}
	return ownerOf(fi), nil
}

// NeedsPassword reports whether there is no key store yet, so that install
// creates one and needs its password.
func (m *Machine) NeedsPassword() bool { return !m.exists(deploy.MasterKey) }

// configured reports whether the wallet's configuration is there, from an
// earlier install.
func (m *Machine) configured() bool { return m.exists(deploy.WalletConfig) }

// Check checks, before anything is changed or a password asked, that install
// can run with these options.
func (m *Machine) Check(o *Options) error {
	if err := m.checkSystem("install"); err != nil {
		return err
	}
	if ok, err := m.synced(); err != nil || !ok {
		why := "the kernel says the clock is not synchronized"
		if err != nil {
			why = fmt.Sprintf("cannot ask the kernel whether the clock is synchronized: %v", err)
		}
		return fmt.Errorf("install: %s. The wallet takes the time from it (section 9.3): turn on its synchronization, as with timedatectl set-ntp true, and run install again", why)
	}
	if err := m.checkHardlinks(); err != nil {
		return err
	}
	if o.Person == "" || o.Person == "root" {
		return errors.New("install: run it with sudo from the person's account, or name the person with -user")
	}
	if !userName.MatchString(o.Person) {
		return fmt.Errorf("install: %q is not a user name install can use", o.Person)
	}
	person, err := m.lookupUser(o.Person)
	if err != nil {
		return fmt.Errorf("install: no user %s: %v", o.Person, err)
	}
	if m.configured() {
		if o.Network != "" || o.DataSource != "" || o.DataSourceURL != "" {
			return fmt.Errorf("install: mcpcardano is installed and keeps its configuration: to change the network or the data source, edit %s and %s", deploy.WalletConfig, deploy.ServerConfig)
		}
		// admin_uid is the person's: if it names someone else, install
		// stops, because changing it would hand the admin socket to another
		// user.
		c, err := m.readWalletConfig()
		if err != nil {
			return err
		}
		admin, err := c.uid("admin_uid")
		if err != nil {
			return err
		}
		if admin != person.uid {
			return fmt.Errorf("install: %s admits the user %d at the admin socket, not %s (%d): run install as that user, or change admin_uid by hand", deploy.WalletConfig, admin, o.Person, person.uid)
		}
	} else {
		if o.Network == "" {
			o.Network = model.Preprod
		}
		if o.DataSource == "" {
			o.DataSource = "koios"
		}
		switch {
		case o.Network == model.Mainnet:
			return errors.New("install: mainnet stays disabled (paper, section 7.4)")
		case !o.Network.Valid():
			return fmt.Errorf("install: unknown network %q", o.Network)
		case o.DataSource != "koios":
			return fmt.Errorf("install: unknown data source %q: there is only koios", o.DataSource)
		}
		// The server's configuration may be left from an install that
		// stopped half way; install keeps it, but not for another network.
		if data, err := os.ReadFile(m.path(deploy.ServerConfig)); err == nil {
			var c struct {
				Network model.Network `json:"network"`
			}
			if err := json.Unmarshal(data, &c); err != nil || c.Network != o.Network {
				return fmt.Errorf("install: %s is left from an earlier install, and is not for %s: remove it, or install with its network", deploy.ServerConfig, o.Network)
			}
		}
	}
	switch o.Unlock {
	case "", UnlockPassword:
	case UnlockMachine:
		if err := m.checkMachineUnlock(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("install: -unlock is %s or %s", UnlockPassword, UnlockMachine)
	}
	if o.FIDOOwner && !m.fidoRule() {
		return errors.New("install: -fido-owner needs systemd's rule 60-fido-id.rules, which marks the security keys")
	}
	// Whoever can write the directory of the binaries can replace them, the
	// wallet's among them, as doctor says too.
	if fi, err := os.Lstat(m.path(deploy.BinDir)); err == nil && fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("install: %s has mode %04o, so others than root could replace the binaries, the wallet's among them: make it root's alone, as with chmod 755 %s, and run install again", deploy.BinDir, fi.Mode().Perm(), deploy.BinDir)
	}
	for _, b := range deploy.Binaries {
		fi, err := os.Lstat(filepath.Join(o.Source, b))
		if err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("install: %s must be next to mcpcardano, in %s, as a file and not a link", b, o.Source)
		}
	}
	return nil
}

// hardlinks is where Linux says whether a user may make a hard link to a file
// of someone else's.
const hardlinks = "/proc/sys/fs/protected_hardlinks"

// checkHardlinks refuses a kernel that lets anyone link anyone's files. A
// service could then put, in its data directory, a link to a file of root's,
// which install would give to the service's user when it gives the data
// back, as after uninstall.
func (m *Machine) checkHardlinks() error {
	b, err := os.ReadFile(m.path(hardlinks))
	if err != nil || strings.TrimSpace(string(b)) == "1" {
		return nil
	}
	return errors.New("install: fs.protected_hardlinks is off, so a service could link a file of root's into its data directory for install to give it away: turn it on, as with sysctl fs.protected_hardlinks=1, and run it again")
}

func (m *Machine) checkSystem(what string) error {
	switch {
	case m.unsupported != "":
		return fmt.Errorf("%s: %s", what, m.unsupported)
	case m.euid != 0:
		return fmt.Errorf("%s: run it as root: sudo mcpcardano %s", what, what)
	case !m.exists("/run/systemd/system"):
		return fmt.Errorf("%s: the services need systemd, which is not running", what)
	}
	return nil
}

// checkMachineUnlock checks what the unlock bound to the machine needs: a
// TPM2 and a systemd with ImportCredential= (decision 132). Whether the
// TPM2 seals is known when it seals.
func (m *Machine) checkMachineUnlock() error {
	out, err := m.run(command{name: "systemctl", args: []string{"--version"}})
	if err != nil {
		return fmt.Errorf("install: systemctl --version: %v", err)
	}
	if v := systemdVersion(out); v < minSystemdForCredentials {
		return fmt.Errorf("install: the unlock bound to the machine needs systemd %d or later, and this is %d", minSystemdForCredentials, v)
	}
	if !m.exists(tpmDevice) {
		return fmt.Errorf("install: the unlock bound to the machine needs a TPM2, and there is no %s", tpmDevice)
	}
	return nil
}

// systemdVersion reads the version in the first line of systemctl --version,
// as "systemd 255 (255.4-1ubuntu8)", or 0.
func systemdVersion(out string) int {
	f := strings.Fields(out)
	if len(f) < 2 || f[0] != "systemd" {
		return 0
	}
	v, _ := strconv.Atoi(f[1])
	return v
}

func (m *Machine) fidoRule() bool { return slices.ContainsFunc(fidoRules, m.exists) }

// Install installs mcpcardano, or updates it if it is there. password
// creates the key store, if NeedsPassword; Check must have passed.
func (m *Machine) Install(o Options, password model.Secret) error {
	upgrade := slices.ContainsFunc(deploy.Units, func(u string) bool { return m.exists(filepath.Join(deploy.UnitDir, u)) })
	if upgrade {
		// Section 10.6: the server stops first, and the wallet after it.
		m.say("Stopping the services.")
		for _, u := range []string{deploy.ServerService, deploy.WalletService} {
			if err := m.cmd(nil, "systemctl", "stop", u); err != nil {
				return err
			}
		}
	}
	if err := m.installBinaries(o.Source); err != nil {
		return err
	}
	ids, err := m.installUsers(o.Person)
	if err != nil {
		return err
	}
	m.say("Installing the units.")
	for _, u := range deploy.Units {
		if err := m.writeFile(filepath.Join(deploy.UnitDir, u), []byte(deploy.Unit(u)), 0o644, 0, 0); err != nil {
			return err
		}
	}
	if err := m.cmd(nil, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := m.installConfig(o, ids); err != nil {
		return err
	}
	if err := m.installData(ids, password); err != nil {
		return err
	}
	if err := m.installUnlock(o.Unlock); err != nil {
		return err
	}
	if err := m.installFIDO(o); err != nil {
		return err
	}
	m.say("Starting the wallet and then the server.")
	if err := m.cmd(nil, "systemctl", "enable", deploy.WalletService, deploy.ServerService); err != nil {
		return err
	}
	// systemd says a service started when it runs, not when it answers:
	// the server starts once the wallet has its sockets, and install ends
	// once the server has its own.
	for _, s := range []struct{ unit, socket string }{
		{deploy.WalletService, deploy.AdminSocket},
		{deploy.ServerService, deploy.MCPSocket},
	} {
		if err := m.cmd(nil, "systemctl", "start", s.unit); err != nil {
			return err
		}
		if err := m.waitFor(s.socket); err != nil {
			return fmt.Errorf("install: %s did not open %s in %v: journalctl -u %s says why", s.unit, s.socket, m.startWait, s.unit)
		}
	}
	m.next(upgrade, o.Network)
	return nil
}

// waitFor waits until p exists, for startWait at most.
func (m *Machine) waitFor(p string) error {
	deadline := time.Now().Add(m.startWait)
	for !m.exists(p) {
		if time.Now().After(deadline) {
			return fs.ErrNotExist
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func (m *Machine) installBinaries(source string) error {
	m.say("Installing the binaries in %s.", deploy.BinDir)
	same := filepath.Clean(source) == filepath.Clean(m.path(deploy.BinDir))
	for _, b := range deploy.Binaries {
		dst := filepath.Join(deploy.BinDir, b)
		if same {
			// The installed CLI runs install again: the binaries are there,
			// but their owner and mode are checked all the same.
			if err := m.chown(m.path(dst), 0, 0); err != nil {
				return fmt.Errorf("install: %w", err)
			}
			if err := os.Chmod(m.path(dst), 0o755); err != nil {
				return fmt.Errorf("install: %w", err)
			}
			continue
		}
		if err := m.copyFile(filepath.Join(source, b), dst, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// ids are the users and the group install made, and the person.
type ids struct {
	wallet, server, person account
	group                  uint32
}

func (m *Machine) installUsers(person string) (ids, error) {
	m.say("Creating the users %s and %s and the group %s, and adding %s to it.", deploy.WalletUser, deploy.ServerUser, deploy.Group, person)
	var r ids
	if err := m.writeFile(deploy.SysUsersPath, []byte(deploy.SysUsers), 0o644, 0, 0); err != nil {
		return r, err
	}
	if err := m.cmd(nil, "systemd-sysusers", deploy.SysUsersPath); err != nil {
		return r, err
	}
	if err := m.cmd(nil, "usermod", "-aG", deploy.Group, person); err != nil {
		return r, err
	}
	var err error
	if r.group, err = m.lookupGroup(deploy.Group); err != nil {
		return r, fmt.Errorf("install: %w", err)
	}
	for name, a := range map[string]*account{deploy.WalletUser: &r.wallet, deploy.ServerUser: &r.server, person: &r.person} {
		if *a, err = m.lookupUser(name); err != nil {
			return r, fmt.Errorf("install: %w", err)
		}
	}
	return r, nil
}

// walletConfig and serverConfig are the config.json install writes (section
// 7.5), in the order of deploy/README.md.
type walletConfig struct {
	Network       model.Network `json:"network"`
	DataDir       string        `json:"data_dir"`
	ServiceSocket string        `json:"service_socket"`
	AdminSocket   string        `json:"admin_socket"`
	ServiceUID    uint32        `json:"service_uid"`
	AdminUID      uint32        `json:"admin_uid"`
}

type serverConfig struct {
	Network      model.Network    `json:"network"`
	DataDir      string           `json:"data_dir"`
	Socket       string           `json:"socket"`
	WalletSocket string           `json:"wallet_socket"`
	DataSource   dataSourceConfig `json:"datasource"`
	Wallets      []struct{}       `json:"wallets"`
}

type dataSourceConfig struct {
	Kind string `json:"kind"`
	URL  string `json:"url,omitempty"`
}

func marshal(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err) // the types above always marshal
	}
	return append(b, '\n')
}

func (m *Machine) installConfig(o Options, r ids) error {
	for _, d := range []string{deploy.WalletConfigDir, deploy.ServerConfigDir} {
		if err := m.mkdir(d, 0o750, 0, r.group); err != nil {
			return err
		}
	}
	if !m.configured() {
		m.say("Writing %s and %s, on %s.", deploy.WalletConfig, deploy.ServerConfig, o.Network)
		w := walletConfig{Network: o.Network, DataDir: deploy.WalletData, ServiceSocket: deploy.ServiceSocket,
			AdminSocket: deploy.AdminSocket, ServiceUID: r.server.uid, AdminUID: r.person.uid}
		s := serverConfig{Network: o.Network, DataDir: deploy.ServerData, Socket: deploy.MCPSocket,
			WalletSocket: deploy.ServiceSocket, DataSource: dataSourceConfig{Kind: o.DataSource, URL: o.DataSourceURL}, Wallets: []struct{}{}}
		if err := m.writeFile(deploy.WalletConfig, marshal(w), 0o640, 0, r.group); err != nil {
			return err
		}
		if !m.exists(deploy.ServerConfig) {
			if err := m.writeFile(deploy.ServerConfig, marshal(s), 0o640, 0, r.group); err != nil {
				return err
			}
		}
	} else if err := m.keepConfig(r); err != nil {
		return err
	}
	for _, f := range []string{deploy.WalletConfig, deploy.ServerConfig} {
		if err := m.chown(m.path(f), 0, r.group); err != nil {
			return fmt.Errorf("install: %w", err)
		}
		if err := os.Chmod(m.path(f), 0o640); err != nil {
			return fmt.Errorf("install: %w", err)
		}
	}
	// The binaries check what they will run with, as the users they will
	// run as, and not as root.
	for _, c := range []command{
		{name: filepath.Join(deploy.BinDir, "mcpcardano-wallet"), args: []string{"-config", deploy.WalletConfig, "-check"}, as: &account{r.wallet.uid, r.group}},
		{name: filepath.Join(deploy.BinDir, "mcpcardano-server"), args: []string{"-config", deploy.ServerConfig, "-check"}, as: &account{r.server.uid, r.group}},
	} {
		if out, err := m.run(c); err != nil {
			return fmt.Errorf("install: %s: %v%s", c, err, indent(out))
		}
	}
	return nil
}

// keptConfig is the wallet's config.json of an earlier install, field by
// field, so that install can correct one and keep the rest as it is.
type keptConfig map[string]json.RawMessage

func (m *Machine) readWalletConfig() (keptConfig, error) {
	data, err := os.ReadFile(m.path(deploy.WalletConfig))
	if err != nil {
		return nil, fmt.Errorf("install: %w", err)
	}
	var c keptConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("install: %s: %v", deploy.WalletConfig, err)
	}
	return c, nil
}

func (c keptConfig) uid(field string) (uint32, error) {
	var v uint32
	if err := json.Unmarshal(c[field], &v); err != nil {
		return 0, fmt.Errorf("install: %s: %s: %v", deploy.WalletConfig, field, err)
	}
	return v, nil
}

// keepConfig keeps the wallet's config.json of an earlier install. If the
// server's user has another uid, as after uninstall and install, it
// corrects service_uid, which install owns; Check made sure that admin_uid
// is the person's.
func (m *Machine) keepConfig(r ids) error {
	c, err := m.readWalletConfig()
	if err != nil {
		return err
	}
	service, err := c.uid("service_uid")
	if err != nil {
		return err
	}
	m.say("Keeping %s and %s.", deploy.WalletConfig, deploy.ServerConfig)
	if service == r.server.uid {
		return nil
	}
	m.say("The user %s is now %d, not %d: correcting service_uid.", deploy.ServerUser, r.server.uid, service)
	c["service_uid"] = json.RawMessage(strconv.FormatUint(uint64(r.server.uid), 10))
	return m.writeFile(deploy.WalletConfig, marshal(c), 0o640, 0, r.group)
}

// installData makes the two data directories, gives them back to their
// users if they are someone else's, as after uninstall, and creates the key
// store if there is none.
func (m *Machine) installData(r ids, password model.Secret) error {
	for _, d := range []struct {
		dir  string
		user account
	}{{deploy.WalletData, r.wallet}, {deploy.ServerData, r.server}} {
		if o, err := m.owner(d.dir); err == nil && o != (account{d.user.uid, r.group}) {
			if err := m.chownTree(d.dir, d.user.uid, r.group); err != nil {
				return err
			}
		}
		if err := m.mkdir(d.dir, 0o700, d.user.uid, r.group); err != nil {
			return err
		}
	}
	if !m.NeedsPassword() {
		m.say("Keeping the key store in %s.", deploy.WalletData)
		return nil
	}
	if len(password) == 0 {
		return errors.New("install: the key store needs a password")
	}
	m.say("Creating the key store in %s.", deploy.WalletData)
	stdin := append(append(make([]byte, 0, len(password)+1), password...), '\n')
	defer clear(stdin)
	c := command{name: filepath.Join(deploy.BinDir, "mcpcardano-wallet"), args: []string{"-config", deploy.WalletConfig, "init"},
		stdin: stdin, as: &account{r.wallet.uid, r.group}}
	if out, err := m.run(c); err != nil {
		return fmt.Errorf("install: %s: %v%s", c, err, indent(out))
	}
	return nil
}

// installUnlock seals the key of the machine with the TPM2 (decision 132),
// or removes it. The key goes to systemd-creds on its standard input and is
// wiped.
func (m *Machine) installUnlock(unlock string) error {
	switch {
	case unlock == UnlockMachine && !m.exists(deploy.Credential):
		m.say("Sealing the key of the machine with the TPM2.")
		if err := m.mkdir(filepath.Dir(deploy.Credential), 0o700, 0, 0); err != nil {
			return err
		}
		key := make([]byte, 32)
		defer clear(key)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("install: %w", err)
		}
		return m.cmd(key, "systemd-creds", "encrypt", "--with-key=tpm2+host", "--name="+filepath.Base(deploy.Credential), "-", deploy.Credential)
	case unlock == UnlockMachine:
		m.say("Keeping the key of the machine sealed earlier. If the TPM2 was cleared since, it no longer opens: install -unlock password, and then -unlock machine, seals a new one.")
	case unlock == UnlockPassword && m.exists(deploy.Credential):
		m.say("Removing the key of the machine: the next unlock with the password removes its wrapping.")
		if err := os.Remove(m.path(deploy.Credential)); err != nil {
			return fmt.Errorf("install: %w", err)
		}
	}
	return nil
}

func (m *Machine) installFIDO(o Options) error {
	if !m.fidoRule() {
		m.say("Warning: there is no rule 60-fido-id.rules of systemd, so your user may not reach a security key. mcpcardano doctor checks it.")
	}
	if !o.FIDOOwner {
		return nil
	}
	m.say("Giving the security keys to %s, also over SSH.", o.Person)
	rule := fmt.Sprintf("# mcpcardano install -fido-owner: the security keys are %s's alone.\nSUBSYSTEM==\"hidraw\", ENV{ID_FIDO_TOKEN}==\"1\", OWNER=\"%s\", MODE=\"0600\"\n", o.Person, o.Person)
	if err := m.writeFile(deploy.FIDORule, []byte(rule), 0o644, 0, 0); err != nil {
		return err
	}
	if err := m.cmd(nil, "udevadm", "control", "--reload"); err != nil {
		return err
	}
	return m.cmd(nil, "udevadm", "trigger", "--subsystem-match=hidraw", "--action=change")
}

// next says what the person does now and, after a first install on network
// n, what the wallets of the agent start with.
func (m *Machine) next(upgrade bool, n model.Network) {
	bound := m.exists(deploy.Credential)
	m.say("")
	if upgrade {
		m.say("mcpcardano is updated.")
	} else {
		m.say("mcpcardano is installed.")
	}
	switch {
	case bound && !upgrade:
		m.say("Next: log in again, or run newgrp %s, so that your session is in the group; then mcpcardano unlock, once, to bind the key store to this machine; and mcpcardano doctor. From the next start on, the wallet starts unlocked.", deploy.Group)
	case bound:
		m.say("Next: mcpcardano doctor. If the wallet is locked, mcpcardano unlock.")
	case upgrade:
		m.say("The wallet started again, locked. Next: mcpcardano unlock, and mcpcardano doctor.")
	default:
		m.say("Next: log in again, or run newgrp %s, so that your session is in the group; then mcpcardano unlock, and mcpcardano doctor.", deploy.Group)
	}
	if upgrade {
		return
	}
	l := policy.DefaultTemplate(n).Policy.Limits
	m.say("")
	m.say("The wallets the agent creates start in mode C with a budget of %s, at most %s per transaction, %s per hour and %s per day, fees up to %s, %d transactions per hour, and any destination with at most %d new per hour and %d per day. To change that:",
		ada(l.Budget), ada(l.PerTx), ada(l.PerHour), ada(l.PerDay), ada(l.MaxFee), l.TxPerHour, l.NewDestinationsPerHour, l.NewDestinationsPerDay)
	m.say("  mcpcardano policy show -template > template.json")
	m.say("  mcpcardano policy set -template template.json   # after editing it")
}

func ada(lovelace uint64) string {
	if lovelace%1_000_000 == 0 {
		return fmt.Sprintf("%d ADA", lovelace/1_000_000)
	}
	return fmt.Sprintf("%d.%06d ADA", lovelace/1_000_000, lovelace%1_000_000)
}

// CheckUninstall checks that uninstall can run, before the person is asked
// to confirm anything.
func (m *Machine) CheckUninstall() error {
	if err := m.checkSystem("uninstall"); err != nil {
		return err
	}
	return m.checkHardlinks()
}

// Uninstall removes the services, the binaries, the users, the group and
// the key of the machine (section 10.1). The configuration and the data
// stay, given to root so that no new user with the same uid inherits them,
// unless deleteData, which the person confirmed apart.
func (m *Machine) Uninstall(deleteData bool) error {
	if err := m.checkSystem("uninstall"); err != nil {
		return err
	}
	var units []string
	for _, u := range []string{deploy.ServerService, deploy.WalletService} {
		if m.exists(filepath.Join(deploy.UnitDir, u)) {
			units = append(units, u)
		}
	}
	if len(units) > 0 {
		m.say("Stopping the services.")
		if err := m.cmd(nil, "systemctl", append([]string{"disable", "--now"}, units...)...); err != nil {
			return err
		}
	}
	rule := m.exists(deploy.FIDORule)
	var gone []string
	for _, b := range deploy.Binaries {
		gone = append(gone, filepath.Join(deploy.BinDir, b))
	}
	for _, u := range deploy.Units {
		gone = append(gone, filepath.Join(deploy.UnitDir, u))
	}
	gone = append(gone, deploy.SysUsersPath, deploy.Credential, deploy.FIDORule)
	m.say("Removing the binaries, the units and the key of the machine.")
	for _, p := range gone {
		if err := os.Remove(m.path(p)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("install: %w", err)
		}
	}
	if err := m.cmd(nil, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if rule {
		if err := m.cmd(nil, "udevadm", "control", "--reload"); err != nil {
			return err
		}
	}
	kept := []string{deploy.WalletConfigDir, deploy.ServerConfigDir, deploy.WalletData, deploy.ServerData}
	if deleteData {
		m.say("Deleting the configuration, the key store and the records.")
		for _, p := range kept {
			if err := os.RemoveAll(m.path(p)); err != nil {
				return fmt.Errorf("install: %w", err)
			}
		}
	} else {
		for _, p := range kept {
			if err := m.chownTree(p, 0, 0); err != nil {
				return err
			}
		}
		for _, p := range []string{deploy.WalletData, deploy.ServerData} {
			if !m.exists(p) {
				continue
			}
			if err := m.chmodDir(p, 0o700); err != nil {
				return err
			}
		}
	}
	m.say("Removing the users and the group.")
	for _, u := range []string{deploy.WalletUser, deploy.ServerUser} {
		if _, err := m.lookupUser(u); err == nil {
			if err := m.cmd(nil, "userdel", u); err != nil {
				return err
			}
		}
	}
	if _, err := m.lookupGroup(deploy.Group); err == nil {
		if err := m.cmd(nil, "groupdel", deploy.Group); err != nil {
			return err
		}
	}
	m.say("")
	if deleteData {
		m.say("mcpcardano is uninstalled, with its data.")
		return nil
	}
	m.say("mcpcardano is uninstalled. Kept, as root's: %s. The key store opens only with its password; install keeps using them.", strings.Join(kept, ", "))
	return nil
}
