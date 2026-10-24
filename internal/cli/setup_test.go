// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestNewPassword(t *testing.T) {
	ctx := context.Background()
	// From a script, the password comes once.
	p, err := newPassword(ctx, strings.NewReader("correct horse\nnext line\n"), io.Discard)
	if err != nil || string(p) != "correct horse" {
		t.Errorf("got %q, %v", p, err)
	}
	if _, err := newPassword(ctx, strings.NewReader("short\n"), io.Discard); err == nil || !strings.Contains(err.Error(), "at least 8 bytes") {
		t.Errorf("a short password: %v", err)
	}
	if _, err := newPassword(ctx, strings.NewReader("\n"), io.Discard); !errors.Is(err, errCancelled) {
		t.Errorf("an empty password: %v", err)
	}
}

func TestSetupUsage(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		run  func() int
	}{
		{"install", func() int { return Install(ctx, []string{"extra"}, strings.NewReader(""), io.Discard, io.Discard) }},
		{"install flag", func() int { return Install(ctx, []string{"-unknown"}, strings.NewReader(""), io.Discard, io.Discard) }},
		{"uninstall", func() int { return Uninstall(ctx, []string{"extra"}, strings.NewReader(""), io.Discard, io.Discard) }},
		{"doctor", func() int { return Doctor(ctx, []string{"extra"}, "test", io.Discard, io.Discard) }},
		{"apikey", func() int { return APIKey(ctx, []string{"set"}, strings.NewReader(""), io.Discard, io.Discard) }},
		{"apikey verb", func() int {
			return APIKey(ctx, []string{"show", "blockfrost"}, strings.NewReader(""), io.Discard, io.Discard)
		}},
	} {
		if code := c.run(); code != ExitUsage {
			t.Errorf("%s with a wrong argument: exit %d", c.name, code)
		}
	}
	// Not as root, install changes nothing and says how to run it.
	var errOut strings.Builder
	if code := Install(ctx, nil, strings.NewReader(""), io.Discard, &errOut); code != ExitError || !strings.Contains(errOut.String(), "install") {
		t.Errorf("install not as root: exit %d, %s", code, errOut.String())
	}
	// Nor apikey, which asks for no key.
	errOut.Reset()
	if code := APIKey(ctx, []string{"set", "blockfrost"}, strings.NewReader("preprodKey\n"), io.Discard, &errOut); code != ExitError ||
		!strings.Contains(errOut.String(), "apikey") || strings.Contains(errOut.String(), "Key:") {
		t.Errorf("apikey not as root: exit %d, %s", code, errOut.String())
	}
}
