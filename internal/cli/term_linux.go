// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import "golang.org/x/sys/unix"

const (
	ioctlGetTermios = unix.TCGETS
	ioctlSetTermios = unix.TCSETS
)
