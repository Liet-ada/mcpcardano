// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// checkIsolation reports whether the wallet runs without network (section
// 10.3): inside its Seatbelt profile, a TCP connection to 127.0.0.1 fails
// with "operation not permitted", not with "connection refused".
func checkIsolation() error {
	c, err := net.DialTimeout("tcp", "127.0.0.1:9", time.Second)
	if err == nil {
		c.Close()
		return fmt.Errorf("%w: a TCP connection to 127.0.0.1 succeeded", ErrNotIsolated)
	}
	if !errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("%w: a TCP connection to 127.0.0.1 failed with %v, not with EPERM", ErrNotIsolated, err)
	}
	return nil
}
