// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"errors"
	"slices"
	"testing"
)

// TestIsolationLinux reads the interfaces as /proc/net/dev lists them, and
// finds the machine that runs the tests, which has network, not isolated.
func TestIsolationLinux(t *testing.T) {
	dev := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    1460      20    0    0    0     0          0         0     1460      20    0    0    0     0       0          0
  eth0: 9876543   12345    0    0    0     0          0         0   123456     789    0    0    0     0       0          0
`
	if got := interfaces(dev); !slices.Equal(got, []string{"lo", "eth0"}) {
		t.Errorf("interfaces %q", got)
	}
	if got := interfaces(""); len(got) != 0 {
		t.Errorf("no text: %q", got)
	}
	if err := checkIsolation(); !errors.Is(err, ErrNotIsolated) {
		t.Errorf("a machine with network: %v", err)
	}
}
