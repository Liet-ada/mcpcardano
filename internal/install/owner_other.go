// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !unix

package install

import (
	"io/fs"
	"os"
)

func ownerOf(fs.FileInfo) account { return account{} }

// openNoFollow opens a file to read it.
func openNoFollow(path string) (*os.File, error) { return os.Open(path) }
