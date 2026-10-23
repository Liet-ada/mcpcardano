// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build unix

package install

import (
	"io/fs"
	"os"
	"syscall"
)

func ownerOf(fi fs.FileInfo) account {
	st := fi.Sys().(*syscall.Stat_t)
	return account{st.Uid, st.Gid}
}

// openNoFollow opens a file to read it, and fails if it is a link.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
