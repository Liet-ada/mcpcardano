// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build linux || darwin

package doctor

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/Liet-ada/mcpcardano/deploy"
	"github.com/Liet-ada/mcpcardano/internal/fido"
	"github.com/Liet-ada/mcpcardano/internal/install"
)

// NewEnv returns this machine as the person who runs doctor sees it.
func NewEnv(version string) (Env, error) {
	gs, err := os.Getgroups()
	if err != nil {
		return Env{}, fmt.Errorf("doctor: %w", err)
	}
	groups := []uint32{uint32(os.Getegid())}
	for _, g := range gs {
		groups = append(groups, uint32(g))
	}
	return Env{
		L:           deploy.Current(),
		Version:     version,
		UID:         uint32(os.Getuid()),
		Groups:      groups,
		Lstat:       os.Lstat,
		ReadFile:    os.ReadFile,
		Owner:       owner,
		LookupUser:  lookupUser,
		LookupGroup: lookupGroup,
		UserGroups:  userGroups,
		UserName:    userName,
		Show:        show,
		Print:       printDaemon,
		Synced:      install.ClockSynced,
		Wallet: func(ctx context.Context, network string) (Wallet, error) {
			return AskWallet(ctx, deploy.Current().AdminSocket, version, network)
		},
		Server: func(ctx context.Context) (Server, error) { return AskServer(ctx, deploy.Current().MCPSocket, version) },
		Keys:   fido.Attached,
	}, nil
}

func owner(fi fs.FileInfo) (uint32, uint32) {
	st := fi.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid
}

func id(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	return uint32(v), err
}

func lookupUser(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	return id(u.Uid)
}

func lookupGroup(name string) (uint32, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return id(g.Gid)
}

func userGroups(uid uint32) ([]uint32, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	var out []uint32
	for _, s := range ids {
		if g, err := id(s); err == nil {
			out = append(out, g)
		}
	}
	return out, nil
}

func userName(uid uint32) string {
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		return u.Username
	}
	return strconv.FormatUint(uint64(uid), 10)
}

// show runs systemctl show, which needs no privilege, and reads its lines
// of property=value. A property this systemd does not know is left out.
// systemctl comes from the system's directories, not from the person's
// PATH.
func show(unit string, props []string) (map[string]string, error) {
	systemctl, err := install.SystemCommand("systemctl")
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(systemctl, "show", unit, "-p", strings.Join(props, ","))
	cmd.Env = install.SafeEnv()
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for line := range strings.Lines(string(out)) {
		if k, v, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "="); ok && slices.Contains(props, k) {
			m[k] = v
		}
	}
	return m, nil
}

// printDaemon runs launchctl print, which needs no privilege for a daemon of the
// system, and reads the lines of its first level and its arguments.
// launchctl comes from the system's directories, not from the person's
// PATH.
func printDaemon(label string) (Daemon, error) {
	launchctl, err := install.SystemCommand("launchctl")
	if err != nil {
		return Daemon{}, err
	}
	cmd := exec.Command(launchctl, "print", "system/"+label)
	cmd.Env = install.SafeEnv()
	out, err := cmd.Output()
	if err != nil {
		return Daemon{}, fmt.Errorf("launchctl print system/%s: %w", label, err)
	}
	return parsePrint(string(out)), nil
}

// parsePrint reads what launchctl print says: "\tkey = value" at the first
// level, and the arguments one per line between "\targuments = {" and "\t}".
func parsePrint(out string) Daemon {
	var d Daemon
	inArgs := false
	for line := range strings.Lines(out) {
		line = strings.TrimSuffix(line, "\n")
		switch {
		case inArgs && line == "\t}":
			inArgs = false
		case inArgs:
			d.Arguments = append(d.Arguments, strings.TrimSpace(line))
		case line == "\targuments = {":
			inArgs = true
		case strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "\t\t"):
			k, v, ok := strings.Cut(strings.TrimPrefix(line, "\t"), " = ")
			if !ok {
				continue
			}
			switch k {
			case "path":
				d.Path = v
			case "state":
				d.State = v
			case "username":
				d.Username = v
			case "pid":
				d.PID, _ = strconv.Atoi(v)
			}
		}
	}
	return d
}
