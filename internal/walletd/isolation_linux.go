// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"fmt"
	"os"
	"strings"
)

// checkIsolation reports whether the wallet runs without network (section
// 10.3): with PrivateNetwork, only the loopback interface exists. It reads
// the interfaces of its own network namespace from /proc, without opening a
// socket: the unit allows only AF_UNIX, and net.Interfaces needs netlink.
func checkIsolation() error {
	b, err := os.ReadFile("/proc/self/net/dev")
	if err != nil {
		return fmt.Errorf("walletd: listing the network interfaces: %w", err)
	}
	names := interfaces(string(b))
	if len(names) == 0 {
		return fmt.Errorf("%w: no network interface listed, not even loopback", ErrNotIsolated)
	}
	for _, name := range names {
		if name != "lo" {
			return fmt.Errorf("%w: interface %s is not loopback", ErrNotIsolated, name)
		}
	}
	return nil
}

// interfaces lists the names in the text of /proc/net/dev, after its two
// lines of headers.
func interfaces(dev string) []string {
	lines := strings.Split(dev, "\n")
	var out []string
	for _, l := range lines[min(2, len(lines)):] {
		if name, _, ok := strings.Cut(l, ":"); ok {
			out = append(out, strings.TrimSpace(name))
		}
	}
	return out
}
