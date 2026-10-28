// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !linux && !darwin

package install

import (
	"errors"
	"io"
)

// NewMachine returns a machine on which install refuses to run: it runs on
// Linux and macOS only.
func NewMachine(out io.Writer) *Machine {
	return &Machine{unsupported: "it runs on Linux and macOS only", out: out}
}

// ClockSynced is known on Linux and macOS only.
func ClockSynced() (bool, error) { return false, errors.New("install: unknown on this system") }
