// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build linux

package install

import (
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Liet-ada/mcpcardano/deploy"
)

// NewMachine returns this machine, on which install writes as root.
func NewMachine(out io.Writer) *Machine {
	return &Machine{root: "/", l: deploy.Linux, run: run, chown: lchown, lookupUser: lookupUser, lookupGroup: lookupGroup,
		synced: ClockSynced, euid: os.Geteuid(), startWait: 30 * time.Second, out: out}
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
