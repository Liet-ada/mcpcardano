// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"fmt"
	"net"
)

// checkIsolation reports whether the wallet runs without network (section
// 10.3): with PrivateNetwork, only the loopback interface exists.
func checkIsolation() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("walletd: listing the network interfaces: %w", err)
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback == 0 {
			return fmt.Errorf("%w: interface %s is not loopback", ErrNotIsolated, i.Name)
		}
	}
	return nil
}
