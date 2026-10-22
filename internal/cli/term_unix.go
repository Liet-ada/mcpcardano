// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build darwin || linux

package cli

import (
	"context"

	"golang.org/x/sys/unix"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	return err == nil
}

// withoutEcho runs read with the terminal's echo off, and puts the terminal
// back as it was, also when the person interrupts.
func withoutEcho(ctx context.Context, fd int, read func() (model.Secret, error)) (model.Secret, error) {
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, err
	}
	t := *old
	t.Lflag &^= unix.ECHO
	t.Lflag |= unix.ICANON | unix.ISIG
	t.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &t); err != nil {
		return nil, err
	}
	defer unix.IoctlSetTermios(fd, ioctlSetTermios, old)
	type result struct {
		s   model.Secret
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, err := read()
		done <- result{s, err}
	}()
	select {
	case r := <-done:
		return r.s, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
