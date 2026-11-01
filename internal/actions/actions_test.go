// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package actions

import (
	"strings"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
)

const wallet = "w_aaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestParseADA(t *testing.T) {
	for s, want := range map[string]uint64{
		"40":                    40_000_000,
		"12.5":                  12_500_000,
		"0.000001":              1,
		"007":                   7_000_000,
		"4.":                    4_000_000,
		"0":                     0,
		"18446744073709.551615": 18446744073709551615,
	} {
		if got, err := ParseADA(s); err != nil || got != want {
			t.Errorf("%q: %d, %v", s, got, err)
		}
	}
	for _, s := range []string{"", ".5", "1.2.3", "1.0000001", "-1", "1,5", "1e6", " 1", "18446744073709.551616"} {
		if got, err := ParseADA(s); err == nil {
			t.Errorf("%q: %d", s, got)
		}
	}
}

func TestOpenSession(t *testing.T) {
	a, err := OpenSession(wallet, 90*time.Second, 5)
	if err != nil {
		t.Fatal(err)
	}
	if p := a.Params.(*ipc.OpenSession); a.Name != ipc.ActOpenSession || p.Seconds != 90 || p.MaxLovelace != 5 || p.WalletID != wallet {
		t.Errorf("%s %+v", a.Name, p)
	}
	for _, c := range []struct {
		length time.Duration
		max    uint64
	}{{0, 5}, {time.Millisecond, 5}, {(1 << 32) * time.Second, 5}, {time.Minute, 0}} {
		if _, err := OpenSession(wallet, c.length, c.max); err == nil {
			t.Errorf("%v up to %d was accepted", c.length, c.max)
		}
	}
}

// TestReleaseBudget: the wallet takes the entries sorted and without
// repeats; the caller's slice stays as it was.
func TestReleaseBudget(t *testing.T) {
	entries := [][]byte{{2}, {1}, {2}}
	p := ReleaseBudget(wallet, entries).Params.(*ipc.ReleaseBudget)
	if len(p.Entries) != 2 || p.Entries[0][0] != 1 || p.Entries[1][0] != 2 {
		t.Errorf("entries %v", p.Entries)
	}
	if entries[0][0] != 2 || entries[1][0] != 1 {
		t.Errorf("the caller's entries changed: %v", entries)
	}
}

func TestLabels(t *testing.T) {
	for _, l := range []string{"agente", "Pago de la renta", strings.Repeat("a", ipc.MaxLabel)} {
		if _, err := CreateWallet(l); err != nil {
			t.Errorf("%q: %v", l, err)
		}
	}
	for _, l := range []string{"", strings.Repeat("a", ipc.MaxLabel+1), "evil\x1b[2J", "bidi\u202e"} {
		if _, err := CreateWallet(l); err == nil {
			t.Errorf("%q was accepted", l)
		}
		if _, err := RestoreWallet(l, nil); err == nil {
			t.Errorf("%q was accepted to restore", l)
		}
	}
}
