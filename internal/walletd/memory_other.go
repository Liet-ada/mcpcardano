// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !linux && !darwin

package walletd

import "errors"

// LockMemory cannot keep the memory out of swap on other systems: the wallet
// runs on Linux and macOS.
func LockMemory() error {
	return errors.New("walletd: no memory lock on this system")
}
