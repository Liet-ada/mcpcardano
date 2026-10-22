// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build !crashtest

package walletd

// crashHook does nothing outside the crash tests.
func crashHook() func(point string) { return func(string) {} }
