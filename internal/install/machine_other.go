// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !linux

package install

import (
	"errors"
	"io"
)

// NewMachine returns a machine on which install refuses to run: for now it
// runs on Linux only.
func NewMachine(out io.Writer) *Machine {
	return &Machine{unsupported: "for now it runs on Linux only", out: out}
}

// ClockSynced is known on Linux only, for now.
func ClockSynced() (bool, error) { return false, errors.New("install: unknown on this system") }
