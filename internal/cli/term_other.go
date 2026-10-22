// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !darwin && !linux

package cli

import (
	"context"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The CLI runs on Linux and macOS (section 1.1); elsewhere it reads secrets
// as from a script.
func isTerminal(int) bool { return false }

func withoutEcho(_ context.Context, _ int, read func() (model.Secret, error)) (model.Secret, error) {
	return read()
}
