// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !linux && !darwin

package walletd

import "fmt"

// checkIsolation has no check on other systems: the wallet runs on Linux and
// macOS only.
func checkIsolation() error {
	return fmt.Errorf("%w: no isolation check on this system", ErrNotIsolated)
}
