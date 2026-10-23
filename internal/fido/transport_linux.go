// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build linux

package fido

import (
	"fmt"
	"os"

	authn "github.com/go-authn/fido"
)

// transport opens the first security key among the hidraw devices. The
// person's user needs access to it, which the udev rules of most
// distributions give to whoever has a session at the machine.
func transport() (authn.Transport, error) {
	keys, err := hidrawKeys("/sys/class/hidraw", "/dev")
	if err != nil {
		return nil, fmt.Errorf("fido: cannot look for a security key: %w", err)
	}
	if len(keys) == 0 {
		return nil, ErrNoKey
	}
	f, err := os.OpenFile(keys[0].path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("fido: cannot open %s (%s): %w", keys[0].name, keys[0].path, err)
	}
	return newHidraw(f, keys[0].name), nil
}
