// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !linux && !darwin

package fido

import (
	"errors"

	authn "github.com/go-authn/fido"
)

func transport() (authn.Transport, error) {
	return nil, errors.New("fido: security keys are supported on Linux and macOS only")
}

// Attached lists the security keys attached, which only Linux can do for
// now.
func Attached() ([]Device, error) {
	return nil, errors.New("fido: listing the security keys is supported on Linux only")
}
