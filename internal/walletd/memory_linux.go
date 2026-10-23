// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"fmt"
	"syscall"
)

// LockMemory keeps the wallet's memory out of swap, where a seed or a key
// would outlive the wipe. MCL_FUTURE locks what the process maps later too,
// its growing heap included. The unit lifts the limit with LimitMEMLOCK.
func LockMemory() error {
	if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
		return fmt.Errorf("walletd: locking the memory out of swap (the unit sets LimitMEMLOCK=infinity): %w", err)
	}
	return nil
}
