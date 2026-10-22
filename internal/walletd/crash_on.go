// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build crashtest

package walletd

import (
	"os"
	"syscall"
)

// crashHook kills the process at the point that MCPCARDANO_WALLET_CRASH
// names, as if it had been killed there: the crash tests of section 9.1 build
// the wallet with the crashtest tag.
func crashHook() func(point string) {
	at := os.Getenv("MCPCARDANO_WALLET_CRASH")
	return func(point string) {
		if point == at {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
	}
}
