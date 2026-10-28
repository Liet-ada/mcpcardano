// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build darwin

package fido

import (
	"errors"

	authn "github.com/go-authn/fido"
	macfido "github.com/go-macos/fido"
)

// transport opens the first security key through IOKit, with go-macos/fido,
// which needs no cgo.
func transport() (authn.Transport, error) {
	t, err := macfido.Transport()
	if errors.Is(err, macfido.ErrNoKey) {
		return nil, ErrNoKey
	}
	return t, err
}

// Attached lists the security key attached: go-macos/fido opens the first
// one, which is the one the CLI uses, and the key does not notice.
func Attached() ([]Device, error) {
	t, err := macfido.Transport()
	switch {
	case errors.Is(err, macfido.ErrNoKey):
		return nil, nil
	case err != nil:
		return []Device{{Name: "a security key", Path: "IOKit", Err: err}}, nil
	}
	defer t.Close()
	return []Device{{Name: t.Name(), Path: "IOKit"}}, nil
}
