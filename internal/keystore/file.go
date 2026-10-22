// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package keystore

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFile replaces dir/name atomically (section 7.4): it writes a
// temporary file in the same directory with mode 0600, syncs it, renames it
// over the original and syncs the directory, so the file is either the old
// one or the new one, never half written.
func writeFile(dir, name string, data []byte) (err error) {
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
	if err = os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
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
