// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !linux

package doctor

import "errors"

// NewEnv is for Linux only, for now: macOS arrives with step 7 of H-3.
func NewEnv(string) (Env, error) {
	return Env{}, errors.New("doctor: for now it runs on Linux only")
}
