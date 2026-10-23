// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build linux

package install

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// NewMachine returns this machine, on which install writes as root.
func NewMachine(out io.Writer) *Machine {
	return &Machine{root: "/", run: run, chown: lchown, lookupUser: lookupUser, lookupGroup: lookupGroup,
		synced: ClockSynced, euid: os.Geteuid(), startWait: 30 * time.Second, out: out}
}

func lchown(path string, uid, gid uint32) error { return os.Lchown(path, int(uid), int(gid)) }

// run runs a command from safePath, with a bare environment, in /. One that
// runs as a user of a service has no supplementary groups.
func run(c command) (string, error) {
	path, err := SystemCommand(c.name)
	if err != nil {
		return "", err
	}
	cmd := exec.Command(path, c.args...)
	cmd.Env = SafeEnv()
	cmd.Dir = "/"
	if c.stdin != nil {
		cmd.Stdin = bytes.NewReader(c.stdin)
	}
	if c.as != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.as.uid, Gid: c.as.gid}}
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func lookupUser(name string) (account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return account{}, err
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil {
		return account{}, fmt.Errorf("user %s has uid %s and gid %s", name, u.Uid, u.Gid)
	}
	return account{uint32(uid), uint32(gid)}, nil
}

func lookupGroup(name string) (uint32, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("group %s has gid %s", name, g.Gid)
	}
	return uint32(gid), nil
}

// timeError is what adjtimex returns while the clock is not synchronized
// (TIME_ERROR in adjtimex(2)).
const timeError = 5

// ClockSynced asks the kernel whether the clock is synchronized, whichever
// client of NTP keeps it so, as timedatectl does. Reading needs no
// privilege.
func ClockSynced() (bool, error) {
	var t unix.Timex
	state, err := unix.Adjtimex(&t)
	if err != nil {
		return false, err
	}
	return state != timeError, nil
}
