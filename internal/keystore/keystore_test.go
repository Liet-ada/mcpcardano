// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package keystore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// unlock unlocks s with the password, on a machine without a key.
func unlock(s *Store, password string) error {
	_, err := s.Unlock(model.Secret(password), nil)
	return err
}

func TestDefaultParams(t *testing.T) {
	// RFC 9106, section 4, second recommended option, with 256 MiB.
	if p := DefaultParams(); p != (Params{Time: 3, MemoryKiB: 262144, Threads: 4}) || p.Check() != nil {
		t.Errorf("DefaultParams = %+v", p)
	}
	for _, p := range []Params{{3, 65535, 4}, {0, 65536, 4}, {3, 65536, 0}, fast,
		{MaxTime + 1, 65536, 4}, {3, MaxMemoryKiB + 1, 4}} {
		if p.Check() == nil {
			t.Errorf("%+v passes Check", p)
		}
	}
	if (Params{Time: 1, MemoryKiB: 65536, Threads: 1}).Check() != nil {
		t.Error("the minimum fails Check")
	}
	if (Params{Time: MaxTime, MemoryKiB: MaxMemoryKiB, Threads: 255}).Check() != nil {
		t.Error("the maximum fails Check")
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
	if err := unlock(s, "wrong horse"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password: %v", err)
	}
	if err := unlock(s, "correct horse"); err != nil {
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
	if err := unlock(s2, "correct horse"); err != nil {
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
	if err := unlock(s, "correct horse"); err != nil {
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

	masterPath := filepath.Join(dir, "master.key")
	orig, _ := os.ReadFile(masterPath)
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
		os.WriteFile(masterPath, tc.data, 0o600)
		if err := unlock(s, "correct horse"); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}

	// Argon2id parameters out of bounds never reach it: with no passes it
	// panics, and the others would hang or take all the memory. Nor does a
	// ciphertext bigger than any file the store writes.
	var m master
	s.codec.Unmarshal(orig[5:], &m)
	for _, change := range []func(*master){
		func(m *master) { m.KDF.Time = 0 },
		func(m *master) { m.KDF.Time = MaxTime + 1 },
		func(m *master) { m.KDF.MemoryKiB = MaxMemoryKiB + 1 },
		func(m *master) { m.KDF.MemoryKiB, m.KDF.Threads = 31, 4 },
		func(m *master) { m.KDF.Threads = 0 },
		func(m *master) { m.CT = make([]byte, maxFile) },
	} {
		c := m
		change(&c)
		b, _ := s.codec.Marshal(c)
		os.WriteFile(masterPath, append([]byte(masterMagic), b...), 0o600)
		if err := unlock(s, "correct horse"); !errors.Is(err, ErrFormat) {
			t.Errorf("parameters %+v and %d bytes of ciphertext: %v", c.KDF, len(c.CT), err)
		}
	}
}

func TestReadFileBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	os.WriteFile(path, make([]byte, maxFile), 0o600)
	if _, err := readFile(path); err != nil {
		t.Errorf("a file of maxFile bytes: %v", err)
	}
	os.WriteFile(path, make([]byte, maxFile+1), 0o600)
	if _, err := readFile(path); !errors.Is(err, ErrFormat) {
		t.Errorf("a file of maxFile+1 bytes: %v", err)
	}
}

// TestSeedNeverReplaced has stores on the same files, as two processes would
// be, write the same seed at once: only the first one is kept, because the
// link that puts it in place fails if there is one.
func TestSeedNeverReplaced(t *testing.T) {
	dir, _ := newStore(t)
	stores := make([]*Store, 8)
	for i := range stores {
		s, err := Open(dir, fast)
		if err != nil {
			t.Fatal(err)
		}
		if err := unlock(s, "correct horse"); err != nil {
			t.Fatal(err)
		}
		stores[i] = s
	}
	errs := make([]error, len(stores))
	var wg sync.WaitGroup
	for i, s := range stores {
		wg.Go(func() { errs[i] = s.PutSeed(walletA, model.Secret(bytes.Repeat([]byte{byte(i)}, 32))) })
	}
	wg.Wait()
	first := -1
	for i, err := range errs {
		switch {
		case err == nil && first < 0:
			first = i
		case err == nil:
			t.Errorf("stores %d and %d both wrote the seed", first, i)
		case !errors.Is(err, ErrExists):
			t.Errorf("store %d: %v", i, err)
		}
	}
	if first < 0 {
		t.Fatal("no store wrote the seed")
	}
	if got, err := stores[0].Seed(walletA); err != nil || !bytes.Equal(got, bytes.Repeat([]byte{byte(first)}, 32)) {
		t.Errorf("the seed is not the one written: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
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
	unlock(s, "correct horse")
	s.PutSeed(walletA, model.Secret("entropy of wallet A, 32 bytes.."))

	stronger := Params{Time: 2, MemoryKiB: 128, Threads: 2}
	s2, err := Open(dir, stronger)
	if err != nil {
		t.Fatal(err)
	}
	if err := unlock(s2, "correct horse"); err != nil {
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
	unlock(s3, "correct horse")
	if m, _ := s3.readMaster(); m.KDF != stronger {
		t.Errorf("parameters were lowered to %+v", m.KDF)
	}
	// Nor does raising one lower the others.
	s4, _ := Open(dir, Params{Time: 1, MemoryKiB: 256, Threads: 1})
	unlock(s4, "correct horse")
	if m, _ := s4.readMaster(); m.KDF != (Params{Time: 2, MemoryKiB: 256, Threads: 2}) {
		t.Errorf("parameters after raising the memory alone: %+v", m.KDF)
	}
}

// TestMachine follows the envelope of the machine of decision 132 through
// the restarts of a wallet: each Open is a start.
func TestMachine(t *testing.T) {
	dir, s := newStore(t)
	masterPath := filepath.Join(dir, "master.key")
	machine, other := bytes.Repeat([]byte{1}, MachineKeySize), bytes.Repeat([]byte{2}, MachineKeySize)
	entropy := model.Secret("entropy of wallet A, 32 bytes..")
	restart := func() *Store {
		t.Helper()
		s, err := Open(dir, fast)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	// A new store has no envelope: the first start with a key stays locked.
	if err := s.UnlockMachine(machine); !errors.Is(err, ErrNotBound) || !s.Locked() {
		t.Fatalf("a new store: %v", err)
	}
	// A wrong password binds nothing.
	if _, err := s.Unlock(model.Secret("wrong horse"), machine); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	if m, _ := s.readMaster(); m.Machine != nil {
		t.Fatal("a wrong password bound the machine")
	}
	// The password binds it, and the next start opens with the key alone.
	if bound, err := s.Unlock(model.Secret("correct horse"), machine); err != nil || !bound {
		t.Fatalf("binding: %v, %v", bound, err)
	}
	s.PutSeed(walletA, entropy)
	s = restart()
	if err := s.UnlockMachine(machine); err != nil || s.Locked() {
		t.Fatalf("a start with the key: %v", err)
	}
	if got, err := s.Seed(walletA); err != nil || !bytes.Equal(got, entropy) {
		t.Errorf("the seed after a start with the key: %v", err)
	}
	// Another key, or a key of another size, does not open it.
	for _, k := range [][]byte{other, machine[:31], nil} {
		s = restart()
		if err := s.UnlockMachine(k); !errors.Is(err, ErrMachineKey) || !s.Locked() {
			t.Errorf("a start with key %x: %v", k, err)
		}
	}
	// Unlocking again with the same key writes nothing.
	before, _ := os.ReadFile(masterPath)
	if bound, err := s.Unlock(model.Secret("correct horse"), machine); err != nil || !bound {
		t.Fatalf("unlocking again: %v, %v", bound, err)
	}
	if after, _ := os.ReadFile(masterPath); !bytes.Equal(before, after) {
		t.Error("master.key was written again with nothing to change")
	}
	// A new key replaces the envelope: the old one no longer opens.
	if bound, err := s.Unlock(model.Secret("correct horse"), other); err != nil || !bound {
		t.Fatalf("a new key: %v, %v", bound, err)
	}
	if s = restart(); !errors.Is(s.UnlockMachine(machine), ErrMachineKey) || s.UnlockMachine(other) != nil {
		t.Error("the envelope did not follow the new key")
	}
	// Without a key, the password still opens and removes the envelope.
	if bound, err := s.Unlock(model.Secret("correct horse"), nil); err != nil || bound {
		t.Fatalf("without a key: %v, %v", bound, err)
	}
	if s = restart(); !errors.Is(s.UnlockMachine(other), ErrNotBound) {
		t.Error("the envelope stayed without a key")
	}
	// Raising the parameters and binding go in one rewrite, and both hold.
	stronger := Params{Time: 2, MemoryKiB: 128, Threads: 1}
	s, _ = Open(dir, stronger)
	if bound, err := s.Unlock(model.Secret("correct horse"), machine); err != nil || !bound {
		t.Fatalf("raising and binding: %v, %v", bound, err)
	}
	if m, _ := s.readMaster(); m.KDF != stronger {
		t.Errorf("parameters %+v", m.KDF)
	}
	if s = restart(); s.UnlockMachine(machine) != nil {
		t.Error("the key does not open after raising the parameters")
	}

	// A changed envelope does not open, and a malformed one is refused.
	orig, _ := os.ReadFile(masterPath)
	var m master
	s.codec.Unmarshal(orig[5:], &m)
	for _, tc := range []struct {
		change func(*sealed)
		want   error
	}{
		{func(e *sealed) { e.CT[0] ^= 1 }, ErrMachineKey},
		{func(e *sealed) { e.Nonce[0] ^= 1 }, ErrMachineKey},
		{func(e *sealed) { e.Nonce = e.Nonce[1:] }, ErrFormat},
		{func(e *sealed) { e.CT = append(e.CT, 0) }, ErrFormat},
	} {
		e := sealed{Nonce: bytes.Clone(m.Machine.Nonce), CT: bytes.Clone(m.Machine.CT)}
		tc.change(&e)
		c := m
		c.Machine = &e
		b, _ := s.codec.Marshal(c)
		os.WriteFile(masterPath, append([]byte(masterMagic), b...), 0o600)
		if s.Lock(); !errors.Is(s.UnlockMachine(machine), tc.want) || !s.Locked() {
			t.Errorf("%+v: want %v", e, tc.want)
		}
	}
	// The envelope of the password cannot stand for that of the machine: they
	// differ in their associated data.
	c := m
	c.Machine = &sealed{Nonce: m.Nonce, CT: m.CT}
	b, _ := s.codec.Marshal(c)
	os.WriteFile(masterPath, append([]byte(masterMagic), b...), 0o600)
	if err := s.UnlockMachine(machine); !errors.Is(err, ErrMachineKey) {
		t.Errorf("the envelope of the password as the machine's: %v", err)
	}
}

func TestPermissions(t *testing.T) {
	dir, s := newStore(t)
	unlock(s, "correct horse")
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
		unlock(s, "hunter2-hunter2"),
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
