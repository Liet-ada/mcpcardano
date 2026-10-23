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

// Attached lists the security keys attached, which only Linux can do for
// now.
func Attached() ([]Device, error) {
	return nil, errors.New("fido: listing the security keys is supported on Linux only")
}
