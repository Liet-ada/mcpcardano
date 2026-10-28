// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !linux && !darwin

package doctor

import "errors"

// NewEnv is for Linux and macOS only.
func NewEnv(string) (Env, error) {
	return Env{}, errors.New("doctor: it runs on Linux and macOS only")
}
