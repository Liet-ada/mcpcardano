// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package install

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Liet-ada/mcpcardano/deploy"
)

// The users and the group on macOS, made with dscl (decision 140): the names
// of Linux, hidden, with the first free ids from 400 to 499, no shell and no
// home. The group is the primary one of both users.

const firstID, lastID = 400, 499

// macUsers makes the group and the two users if they are not there, and adds
// the person to the group.
func (m *Machine) macUsers(person string) error {
	gid, err := m.lookupGroup(deploy.Group)
	if err != nil {
		if gid, err = m.freeID("/Groups", "PrimaryGroupID"); err != nil {
			return err
		}
		g := "/Groups/" + deploy.Group
		if err := m.dscl([][]string{{g}, {g, "PrimaryGroupID", itoa(gid)}, {g, "RealName", deploy.Group}, {g, "Password", "*"}}); err != nil {
			return err
		}
	}
	for _, u := range []struct{ name, real string }{
		{deploy.WalletUser, "mcpcardano wallet"},
		{deploy.ServerUser, "mcpcardano server"},
	} {
		if _, err := m.lookupUser(u.name); err == nil {
			continue
		}
		uid, err := m.freeID("/Users", "UniqueID")
		if err != nil {
			return err
		}
		p := "/Users/" + u.name
		if err := m.dscl([][]string{{p}, {p, "UniqueID", itoa(uid)}, {p, "PrimaryGroupID", itoa(gid)}, {p, "RealName", u.real},
			{p, "UserShell", "/usr/bin/false"}, {p, "NFSHomeDirectory", "/var/empty"}, {p, "Password", "*"}, {p, "IsHidden", "1"}}); err != nil {
			return err
		}
	}
	if err := m.cmd(nil, "dseditgroup", "-o", "edit", "-a", person, "-t", "user", deploy.Group); err != nil {
		return err
	}
	// The lookups that follow must see what dscl made.
	return m.cmd(nil, "dscacheutil", "-flushcache")
}

// dscl runs dscl . -create with each list of arguments.
func (m *Machine) dscl(creates [][]string) error {
	for _, args := range creates {
		if err := m.cmd(nil, "dscl", append([]string{".", "-create"}, args...)...); err != nil {
			return err
		}
	}
	return nil
}

// freeID returns the first id from firstID to lastID that no record in dir
// has as attr, as dscl . -list dir attr prints them: a name and an id per
// line.
func (m *Machine) freeID(dir, attr string) (uint32, error) {
	out, err := m.run(command{name: "dscl", args: []string{".", "-list", dir, attr}})
	if err != nil {
		return 0, fmt.Errorf("install: dscl . -list %s %s: %v%s", dir, attr, err, indent(out))
	}
	used := map[uint64]bool{}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			if id, err := strconv.ParseUint(f[1], 10, 32); err == nil {
				used[id] = true
			}
		}
	}
	for id := uint64(firstID); id <= lastID; id++ {
		if !used[id] {
			return uint32(id), nil
		}
	}
	return 0, fmt.Errorf("install: no free id from %d to %d in %s", firstID, lastID, dir)
}

// removeMacUsers removes the two users and the group, if they are there.
func (m *Machine) removeMacUsers() error {
	for _, u := range []string{deploy.WalletUser, deploy.ServerUser} {
		if _, err := m.lookupUser(u); err == nil {
			if err := m.cmd(nil, "dscl", ".", "-delete", "/Users/"+u); err != nil {
				return err
			}
		}
	}
	if _, err := m.lookupGroup(deploy.Group); err == nil {
		if err := m.cmd(nil, "dscl", ".", "-delete", "/Groups/"+deploy.Group); err != nil {
			return err
		}
	}
	return m.cmd(nil, "dscacheutil", "-flushcache")
}

func itoa(id uint32) string { return strconv.FormatUint(uint64(id), 10) }

// networkTime reads what systemsetup -getusingnetworktime prints: "Network
// Time: On" or "Off". Without root it prints that it needs administrator
// access and exits with 0, which is neither.
func networkTime(out string) (bool, error) {
	switch strings.TrimSpace(out) {
	case "Network Time: On":
		return true, nil
	case "Network Time: Off":
		return false, nil
	}
	return false, fmt.Errorf("systemsetup -getusingnetworktime:%s", indent(out))
}
