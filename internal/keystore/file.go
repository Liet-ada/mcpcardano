// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package keystore

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// maxFile bounds what readFile reads: a master.key or a seed takes under 200
// bytes, so a bigger file is damaged and is refused before it is decoded.
const maxFile = 4 << 10

// readFile reads a file of the key store, which must have mode 0600 or less.
func readFile(path string) ([]byte, error) {
	if err := checkMode(path, 0o600); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}
	if len(b) > maxFile {
		return nil, ErrFormat
	}
	return b, nil
}

// writeFile writes dir/name atomically (section 7.4): it writes a temporary
// file in the same directory with mode 0600, syncs it, puts it in place and
// syncs the directory, so the file is either the old one or the new one,
// never half written. With replace, it renames the temporary file over the
// old one. Without, it links it, which fails with ErrExists if there is a
// file already: the file system keeps it, not a check before writing that
// another process could race.
func writeFile(dir, name string, data []byte, replace bool) (err error) {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	path := filepath.Join(dir, name)
	if replace {
		err = os.Rename(tmp.Name(), path)
	} else if err = os.Link(tmp.Name(), path); err == nil {
		os.Remove(tmp.Name()) // the file is in place; a leftover would only be litter
	}
	if errors.Is(err, fs.ErrExist) {
		return ErrExists
	}
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	return nil
}
