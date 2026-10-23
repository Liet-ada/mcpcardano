// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

// LockMemory does nothing on macOS, which always encrypts its swap.
func LockMemory() error { return nil }
