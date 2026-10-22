// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ipc

import (
	"net"
	"syscall"
)

// PeerUID returns the user the kernel certifies at the other end of a Unix
// socket connection, with SO_PEERCRED (section 5.1). It uses the standard
// library, not golang.org/x/sys/unix, which imports unsafe and so cannot be
// in the wallet (section 2.4).
func PeerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	return cred.Uid, nil
}
