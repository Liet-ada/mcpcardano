// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build linux

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A command named in a directory of PATH that the person can write is not
// the one install runs, and what install runs gets a bare environment.
func TestCommandsComeFromTheSystem(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sh"), []byte("#!/bin/false\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("MCPCARDANO_SECRET", "x")
	path, err := SystemCommand("sh")
	if err != nil || strings.HasPrefix(path, dir) {
		t.Fatalf("SystemCommand(sh) = %s, %v", path, err)
	}
	out, err := run(command{name: "sh", args: []string{"-c", "echo $PATH; pwd; env | grep -c MCPCARDANO || true"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(safePath, ":") + "\n/\n0\n"; out != want {
		t.Errorf("the command saw %q, want %q", out, want)
	}
	if _, err := SystemCommand("no-such-command-of-mcpcardano"); err == nil {
		t.Error("a command that is not there was found")
	}
}
