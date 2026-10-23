// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"fmt"
	"syscall"
)

// mclOnFault is MCL_ONFAULT (Linux 4.4), which syscall lacks. On every
// architecture of Linux it is the bit after MCL_FUTURE.
const mclOnFault = syscall.MCL_FUTURE << 1

// LockMemory keeps the wallet's memory out of swap, where a seed or a key
// would outlive the wipe. MCL_FUTURE locks what the process maps later too,
// its growing heap included. MCL_ONFAULT locks each page when it is first
// used, not before: what Go reserves and never touches, such as the index of
// its heap or the 32 MiB that crypto/internal/fips140 keeps for FIPS mode,
// takes no RAM. The unit lifts the limit with LimitMEMLOCK.
func LockMemory() error {
	if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE | mclOnFault); err != nil {
		return fmt.Errorf("walletd: locking the memory out of swap (the unit sets LimitMEMLOCK=infinity): %w", err)
	}
	return nil
}
