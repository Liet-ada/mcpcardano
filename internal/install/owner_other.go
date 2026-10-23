// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !unix

package install

import "io/fs"

func ownerOf(fs.FileInfo) account { return account{} }
