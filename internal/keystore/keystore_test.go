// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package keystore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// fast keeps Argon2id cheap in tests; DefaultParams is checked on its own.
var fast = Params{Time: 1, MemoryKiB: 64, Threads: 1}

var (
	walletA = model.WalletID("w_aeaqcaibaeaqcaibaeaqcaibae")
	walletB = model.WalletID("w_aiaqeaibaiaqeaibaiaqeaibai")
)

func newStore(t *testing.T) (string, *Store) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keystore")
	if err := Create(dir, model.Secret("correct horse"), fast); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, fast)
	if err != nil {
		t.Fatal(err)
	}
	return dir, s
}

func TestDefaultParams(t *testing.T) {
	// RFC 9106, section 4, second recommended option.
	if p := DefaultParams(); p != (Params{Time: 3, MemoryKiB: 65536, Threads: 4}) {
		t.Errorf("DefaultParams = %+v", p)
	}
	for _, id := range []model.WalletID{walletA, walletB} {
		if id.Validate() != nil {
			t.Fatalf("test id %s", id)
		}
	}
}

func TestUnlockAndSeeds(t *testing.T) {
	dir, s := newStore(t)
	if !s.Locked() {
		t.Error("a store opens unlocked")
	}
	if _, err := s.Seed(walletA); !errors.Is(err, ErrLocked) {
		t.Errorf("seed while locked: %v", err)
	}
	if err := s.Unlock(model.Secret("wrong horse")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password: %v", err)
	}
	if err := s.Unlock(model.Secret("correct horse")); err != nil {
		t.Fatal(err)
	}
	entropy := model.Secret(bytes.Repeat([]byte{7}, 32))
	if err := s.PutSeed(walletA, entropy); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSeed(walletA, entropy); !errors.Is(err, ErrExists) {
		t.Errorf("a seed was replaced: %v", err)
	}
	got, err := s.Seed(walletA)
	if err != nil || !bytes.Equal(got, entropy) {
		t.Errorf("seed: %x, %v", []byte(got), err)
	}
	if _, err := s.Seed(walletB); !errors.Is(err, ErrNotFound) {
		t.Errorf("a missing seed: %v", err)
	}

	// Another process opening the same files with the same password reads
	// the same seed: the data key is in master.key, not in memory only.
	s2, err := Open(dir, fast)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Unlock(model.Secret("correct horse")); err != nil {
		t.Fatal(err)
	}
	if got, err := s2.Seed(walletA); err != nil || !bytes.Equal(got, entropy) {
		t.Errorf("seed after reopening: %v", err)
	}

	s.Lock()
	if !s.Locked() {
		t.Error("Lock")
	}
	if _, err := s.Seed(walletA); !errors.Is(err, ErrLocked) {
		t.Errorf("seed after Lock: %v", err)
	}
	if err := s.CheckPassword(model.Secret("correct horse")); err != nil {
		t.Errorf("CheckPassword: %v", err)
	}
	if err := s.CheckPassword(model.Secret("Correct horse")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("CheckPassword with a wrong one: %v", err)
	}
	if err := Create(dir, model.Secret("x"), fast); !errors.Is(err, ErrExists) {
		t.Errorf("a second Create: %v", err)
	}
}

func TestTamperedFiles(t *testing.T) {
	dir, s := newStore(t)
	if err := s.Unlock(model.Secret("correct horse")); err != nil {
		t.Fatal(err)
	}
	s.PutSeed(walletA, model.Secret("entropy of wallet A, 32 bytes.."))
	s.PutSeed(walletB, model.Secret("entropy of wallet B, 32 bytes.."))
	seedA, seedB := filepath.Join(dir, string(walletA)+".seed"), filepath.Join(dir, string(walletB)+".seed")

	// A seed renamed to be another wallet's does not open.
	a, _ := os.ReadFile(seedA)
	os.WriteFile(seedB, a, 0o600)
	if _, err := s.Seed(walletB); !errors.Is(err, ErrFormat) {
		t.Errorf("a swapped seed: %v", err)
	}
	// Nor one whose id field is changed to match, which the associated data
	// catches.
	var f seed
	s.codec.Unmarshal(a[5:], &f)
	f.WalletID = string(walletB)
	b, _ := s.codec.Marshal(f)
	os.WriteFile(seedB, append([]byte(seedMagic), b...), 0o600)
	if _, err := s.Seed(walletB); !errors.Is(err, ErrFormat) {
		t.Errorf("a seed of another wallet with its id changed: %v", err)
	}
	// Nor one with a byte of its ciphertext changed.
	s.codec.Unmarshal(a[5:], &f)
	f.CT[0] ^= 1
	b, _ = s.codec.Marshal(f)
	os.WriteFile(seedA, append([]byte(seedMagic), b...), 0o600)
	if _, err := s.Seed(walletA); !errors.Is(err, ErrFormat) {
		t.Errorf("a changed ciphertext: %v", err)
	}

	master := filepath.Join(dir, "master.key")
	orig, _ := os.ReadFile(master)
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"a changed ciphertext", flipLast(orig), ErrWrongPassword},
		{"another magic", append([]byte("MCPKX"), orig[5:]...), ErrFormat},
		{"another version", bytes.Replace(orig, []byte{0x61, 'v', 0x01}, []byte{0x61, 'v', 0x02}, 1), ErrFormat},
		{"cut short", orig[:len(orig)-10], ErrFormat},
		{"empty", nil, ErrFormat},
	} {
		os.WriteFile(master, tc.data, 0o600)
		if err := s.Unlock(model.Secret("correct horse")); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

func flipLast(b []byte) []byte {
	c := bytes.Clone(b)
	c[len(c)-1] ^= 1
	return c
}

// TestParamsRaised checks section 7.6: unlocking a store with weaker
// parameters writes it again with the store's, and nothing else changes.
func TestParamsRaised(t *testing.T) {
	dir, s := newStore(t)
	s.Unlock(model.Secret("correct horse"))
	s.PutSeed(walletA, model.Secret("entropy of wallet A, 32 bytes.."))

	stronger := Params{Time: 2, MemoryKiB: 128, Threads: 2}
	s2, err := Open(dir, stronger)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Unlock(model.Secret("correct horse")); err != nil {
		t.Fatal(err)
	}
	m, _ := s2.readMaster()
	if m.KDF != stronger {
		t.Errorf("parameters after unlock: %+v", m.KDF)
	}
	if got, err := s2.Seed(walletA); err != nil || string(got) != "entropy of wallet A, 32 bytes.." {
		t.Errorf("the seed after raising: %v", err)
	}
	// Unlocking with weaker targets never lowers them.
	s3, _ := Open(dir, fast)
	s3.Unlock(model.Secret("correct horse"))
	if m, _ := s3.readMaster(); m.KDF != stronger {
		t.Errorf("parameters were lowered to %+v", m.KDF)
	}
}

func TestPermissions(t *testing.T) {
	dir, s := newStore(t)
	s.Unlock(model.Secret("correct horse"))
	s.PutSeed(walletA, model.Secret("entropy of wallet A, 32 bytes.."))
	for _, f := range []string{"master.key", string(walletA) + ".seed"} {
		if fi, _ := os.Stat(filepath.Join(dir, f)); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v", f, fi.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "tmp") {
			t.Errorf("a temporary file was left: %s", e.Name())
		}
	}

	os.Chmod(filepath.Join(dir, "master.key"), 0o640)
	if _, err := Open(dir, fast); !errors.Is(err, ErrPermissions) {
		t.Errorf("master.key readable by the group: %v", err)
	}
	os.Chmod(filepath.Join(dir, "master.key"), 0o600)
	os.Chmod(filepath.Join(dir, string(walletA)+".seed"), 0o604)
	if _, err := s.Seed(walletA); !errors.Is(err, ErrPermissions) {
		t.Errorf("a seed readable by others: %v", err)
	}
	os.Chmod(dir, 0o750)
	if _, err := Open(dir, fast); !errors.Is(err, ErrPermissions) {
		t.Errorf("a directory open to the group: %v", err)
	}
	os.Chmod(dir, 0o700)

	if _, err := Open(filepath.Join(t.TempDir(), "none"), fast); !errors.Is(err, ErrNotFound) {
		t.Errorf("no store: %v", err)
	}
}

func TestErrorsNeverQuoteSecrets(t *testing.T) {
	dir, s := newStore(t)
	for _, err := range []error{
		s.Unlock(model.Secret("hunter2-hunter2")),
		s.CheckPassword(model.Secret("hunter2-hunter2")),
		Create(dir, model.Secret("hunter2-hunter2"), fast),
	} {
		if err == nil || strings.Contains(err.Error(), "hunter2") {
			t.Errorf("error %v", err)
		}
	}
}

// BenchmarkUnlockDefault measures what the person waits for at unlock and at
// each authorization: one Argon2id with DefaultParams.
func BenchmarkUnlockDefault(b *testing.B) {
	dir := filepath.Join(b.TempDir(), "keystore")
	if err := Create(dir, model.Secret("correct horse"), DefaultParams()); err != nil {
		b.Fatal(err)
	}
	s, _ := Open(dir, DefaultParams())
	for b.Loop() {
		if err := s.CheckPassword(model.Secret("correct horse")); err != nil {
			b.Fatal(err)
		}
	}
}
