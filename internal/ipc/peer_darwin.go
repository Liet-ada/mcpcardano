// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ipc

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
)

// From <sys/un.h> and <sys/ucred.h>.
const (
	solLocal       = 0 // SOL_LOCAL
	localPeerCred  = 1 // LOCAL_PEERCRED
	xucredVersion0 = 0 // XUCRED_VERSION
)

// PeerUID returns the user the kernel certifies at the other end of a Unix
// socket connection, with LOCAL_PEERCRED (section 5.1).
//
// The standard library has no call for it, and golang.org/x/sys/unix, which
// has one, imports unsafe and so cannot be in the wallet (section 2.4).
// LOCAL_PEERCRED fills a struct xucred, whose first fields are
// u_int cr_version and uid_t cr_uid, and the kernel copies only as many bytes
// as the caller asks for (sooptcopyout). So it is read with the standard
// getsockopt for a 20-byte struct, IPv6Mreq, whose first 8 bytes are then the
// version and the user id.
func PeerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var m *syscall.IPv6Mreq
	var serr error
	if err := raw.Control(func(fd uintptr) {
		m, serr = syscall.GetsockoptIPv6Mreq(int(fd), solLocal, localPeerCred)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, serr
	}
	if binary.NativeEndian.Uint32(m.Multiaddr[0:4]) != xucredVersion0 {
		return 0, errors.New("ipc: unexpected xucred version")
	}
	return binary.NativeEndian.Uint32(m.Multiaddr[4:8]), nil
}
