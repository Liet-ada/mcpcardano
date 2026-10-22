// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !linux && !darwin

package ipc

import (
	"errors"
	"net"
)

// PeerUID is only available on Linux and macOS, the platforms of the MVP
// (section 11.4).
func PeerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("ipc: peer credentials are not supported on this system")
}
