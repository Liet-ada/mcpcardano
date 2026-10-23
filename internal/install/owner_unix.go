// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build unix

package install

import (
	"io/fs"
	"syscall"
)

func ownerOf(fi fs.FileInfo) account {
	st := fi.Sys().(*syscall.Stat_t)
	return account{st.Uid, st.Gid}
}
