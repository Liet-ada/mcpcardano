// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build darwin

package install

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Liet-ada/mcpcardano/deploy"
)

// NewMachine returns this machine, on which install writes as root.
func NewMachine(out io.Writer) *Machine {
	return &Machine{root: "/", l: deploy.MacOS, run: run, chown: lchown, lookupUser: lookupUser, lookupGroup: lookupGroup,
		synced: ClockSynced, euid: os.Geteuid(), startWait: 30 * time.Second, out: out}
}

// ClockSynced asks macOS whether it sets the clock from the network, as
// systemsetup -getusingnetworktime says; it needs root.
func ClockSynced() (bool, error) {
	out, err := run(command{name: "systemsetup", args: []string{"-getusingnetworktime"}})
	if err != nil {
		return false, fmt.Errorf("systemsetup -getusingnetworktime: %v%s", err, indent(out))
	}
	return networkTime(out)
}
