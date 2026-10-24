// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package server

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxSecretBytes bounds a secret file: a provider's key is short.
const maxSecretBytes = 1 << 10

// plainName checks the name of a source or of a secret, which becomes a
// file name.
func plainName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// readSecret reads a provider's key (section 7.1): from the credentials
// systemd hands the unit, if it has one with that name, or else from
// secrets/ in the data directory, where the file must be the server's and
// readable by nobody else. Errors never quote the file.
func readSecret(dataDir, name string) (string, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		b, err := readBounded(filepath.Join(dir, name))
		if err == nil {
			return strings.TrimSpace(string(b)), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("server: credential %s: %w", name, err)
		}
	}
	path := filepath.Join(dataDir, "secrets", name)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("server: secret %s: %w", name, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("server: secret %s: %w", name, err)
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 || st == nil || int(st.Uid) != os.Getuid() {
		return "", fmt.Errorf("server: %s must be a file of the server's user with mode 0600, not %v", path, fi.Mode())
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("server: secret %s: %w", name, err)
	}
	if len(b) > maxSecretBytes {
		return "", fmt.Errorf("server: %s is larger than %d bytes", path, maxSecretBytes)
	}
	return strings.TrimSpace(string(b)), nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err == nil && len(b) > maxSecretBytes {
		err = fmt.Errorf("larger than %d bytes", maxSecretBytes)
	}
	return b, err
}
