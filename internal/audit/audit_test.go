// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package audit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
)

var ctx = context.Background()

type event struct {
	Wallet string `cbor:"wallet"`
	Amount uint64 `cbor:"amount"`
}

func opts() Options {
	return Options{Kind: "ledger", Now: func() time.Time { return time.Unix(1_760_000_000, 0) }}
}

// write creates a log at a fresh path with n events and returns the path.
func write(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.log")
	l, _, err := Open(ctx, path, opts())
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := l.Append(ctx, "reserved", event{Wallet: "w_a", Amount: uint64(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func read(t *testing.T, path string) []Entry {
	t.Helper()
	entries, rec, err := Read(ctx, path, opts())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Discarded != 0 {
		t.Fatalf("unexpected recovery %+v", rec)
	}
	return entries
}

func TestAppendAndReopen(t *testing.T) {
	path := write(t, 3)
	l, rec, err := Open(ctx, path, opts())
	if err != nil || rec.Discarded != 0 {
		t.Fatal(err, rec)
	}
	e, err := l.Append(ctx, "signed", event{Wallet: "w_a", Amount: 9})
	if err != nil {
		t.Fatal(err)
	}
	if e.Seq != 5 {
		t.Fatalf("seq %d after a header and three entries", e.Seq)
	}
	l.Close()

	entries := read(t, path)
	if len(entries) != 5 || entries[0].Type != HeaderType || entries[4].Type != "signed" {
		t.Fatalf("entries %+v", entries)
	}
	for i, e := range entries {
		if e.Seq != uint64(i+1) || e.Time != 1_760_000_000 {
			t.Errorf("entry %d: %+v", i, e)
		}
		if i > 0 && !bytes.Equal(e.Prev, entries[i-1].Hash) {
			t.Errorf("entry %d is not chained", i)
		}
	}
	if !bytes.Equal(entries[0].Prev, make([]byte, 32)) {
		t.Error("the first prev must be all zeros")
	}
	var got event
	c, _ := cborx.New(cborx.RecordLimits())
	if err := c.Unmarshal(entries[4].Body, &got); err != nil || got.Amount != 9 {
		t.Fatalf("body %+v, %v", got, err)
	}
}

func TestFilePermissions(t *testing.T) {
	path := write(t, 0)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

// tamper rewrites the file at path and expects Open and Read to refuse it,
// leaving it untouched.
func tamper(t *testing.T, name string, change func([]byte) []byte) {
	t.Helper()
	path := write(t, 3)
	orig, _ := os.ReadFile(path)
	bad := change(bytes.Clone(orig))
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(ctx, path, opts()); !errors.Is(err, ErrBrokenChain) {
		t.Errorf("%s: Read got %v, want ErrBrokenChain", name, err)
	}
	if _, _, err := Open(ctx, path, opts()); !errors.Is(err, ErrBrokenChain) {
		t.Errorf("%s: Open got %v, want ErrBrokenChain", name, err)
	}
	if now, _ := os.ReadFile(path); !bytes.Equal(now, bad) {
		t.Errorf("%s: a broken log was modified", name)
	}
}

// frames splits a log file into its frames.
func frames(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	r := bytes.NewReader(b)
	for r.Len() > 0 {
		f, err := cborx.ReadFrame(r, DefaultMaxEntrySize)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

func join(fs [][]byte) []byte {
	var buf bytes.Buffer
	for _, f := range fs {
		cborx.WriteFrame(&buf, f, DefaultMaxEntrySize)
	}
	return buf.Bytes()
}

func TestTamperingIsDetected(t *testing.T) {
	tamper(t, "changed amount", func(b []byte) []byte {
		fs := frames(t, b)
		i := bytes.Index(fs[2], []byte("amount"))
		fs[2][i+len("amount")] ^= 0x01
		return join(fs)
	})
	tamper(t, "deleted entry", func(b []byte) []byte {
		fs := frames(t, b)
		return join(append(fs[:2], fs[3:]...))
	})
	tamper(t, "swapped entries", func(b []byte) []byte {
		fs := frames(t, b)
		fs[1], fs[2] = fs[2], fs[1]
		return join(fs)
	})
	tamper(t, "empty frame", func(b []byte) []byte {
		return append(b, 0, 0, 0, 0)
	})
	tamper(t, "garbage frame", func(b []byte) []byte {
		return join(append(frames(t, b), []byte{0xa0}))
	})
	tamper(t, "replayed entry", func(b []byte) []byte {
		fs := frames(t, b)
		return join(append(fs, fs[3]))
	})
}

func TestIncompleteLastEntry(t *testing.T) {
	path := write(t, 2)
	full, _ := os.ReadFile(path)
	cut := full[:len(full)-5]
	if err := os.WriteFile(path, cut, 0o600); err != nil {
		t.Fatal(err)
	}
	fs := frames(t, full)
	last := int64(cborx.FrameHeaderSize + len(fs[len(fs)-1]) - 5)

	entries, rec, err := Read(ctx, path, opts())
	if err != nil || len(entries) != 2 || rec.Discarded != last {
		t.Fatalf("Read: %d entries, %+v, %v", len(entries), rec, err)
	}
	if now, _ := os.ReadFile(path); !bytes.Equal(now, cut) {
		t.Fatal("Read modified the file")
	}

	l, rec, err := Open(ctx, path, opts())
	if err != nil || rec.Discarded != last {
		t.Fatalf("Open: %+v, %v", rec, err)
	}
	e, err := l.Append(ctx, "released", event{})
	if err != nil || e.Seq != 3 {
		t.Fatalf("append after repair: %+v, %v", e, err)
	}
	l.Close()
	if n := len(read(t, path)); n != 3 {
		t.Fatalf("%d entries after repair", n)
	}
}

func TestCrashBeforeHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte{0, 0, 0, 40, 0xa6}, 0o600); err != nil {
		t.Fatal(err)
	}
	o := opts()
	o.Kind = "audit"
	l, rec, err := Open(ctx, path, o)
	if err != nil || rec.Discarded != 5 {
		t.Fatalf("%+v, %v", rec, err)
	}
	l.Close()
	entries, _, err := Read(ctx, path, o)
	if err != nil || len(entries) != 1 || entries[0].Type != HeaderType {
		t.Fatalf("%+v, %v", entries, err)
	}
}

func TestWrongKind(t *testing.T) {
	path := write(t, 1)
	o := opts()
	o.Kind = "audit"
	if _, _, err := Open(ctx, path, o); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("got %v", err)
	}
	if _, _, err := Read(ctx, path, o); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("got %v", err)
	}
}

func TestAppendRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.log")
	l, _, err := Open(ctx, path, opts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(ctx, HeaderType, event{}); err == nil {
		t.Error("a second header was accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := l.Append(canceled, "reserved", event{}); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled context: %v", err)
	}
	if _, err := l.Append(ctx, "reserved", make([]byte, DefaultMaxEntrySize)); !errors.Is(err, cborx.ErrFrameTooLarge) {
		t.Errorf("oversized entry: %v", err)
	}
	// An entry that was too large is rejected before writing, so the log
	// stays usable.
	if _, err := l.Append(ctx, "reserved", event{}); err != nil {
		t.Errorf("after an oversized entry: %v", err)
	}
	l.Close()
	if _, err := l.Append(ctx, "reserved", event{}); !errors.Is(err, ErrClosed) {
		t.Errorf("closed log: %v", err)
	}
	if n := len(read(t, path)); n != 2 {
		t.Errorf("%d entries", n)
	}
}

func TestConcurrentAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.log")
	l, _, err := Open(ctx, path, opts())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	for i := range 8 {
		go func() {
			var err error
			for j := range 10 {
				if _, e := l.Append(ctx, "reserved", event{Amount: uint64(i*10 + j)}); e != nil {
					err = e
				}
			}
			done <- err
		}()
	}
	for range 8 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	if n := len(read(t, path)); n != 81 {
		t.Fatalf("%d entries, want 81", n)
	}
}

// FuzzScan checks that reading arbitrary bytes as a log never panics, and that
// whatever it accepts is a chain it would have written itself.
func FuzzScan(f *testing.F) {
	dir := f.TempDir()
	path := filepath.Join(dir, "seed.log")
	l, _, err := Open(ctx, path, opts())
	if err != nil {
		f.Fatal(err)
	}
	l.Append(ctx, "reserved", event{Wallet: "w_a", Amount: 1})
	l.Close()
	seed, _ := os.ReadFile(path)
	f.Add(seed)
	f.Add(seed[:len(seed)-3])
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, 0xa0})

	c, _ := cborx.New(cborx.RecordLimits())
	f.Fuzz(func(t *testing.T, data []byte) {
		st, err := scan(ctx, bytes.NewReader(data), c, opts().withDefaults())
		if err != nil {
			return
		}
		if st.good > int64(len(data)) || (!st.partial && st.good != int64(len(data))) {
			t.Fatalf("good %d of %d bytes, partial %v", st.good, len(data), st.partial)
		}
		prev := make([]byte, 32)
		for i, e := range st.entries {
			h, err := hashEntry(c, e)
			if err != nil || !bytes.Equal(h, e.Hash) || !bytes.Equal(e.Prev, prev) || e.Seq != uint64(i+1) {
				t.Fatalf("accepted an entry that does not chain: %+v", e)
			}
			prev = e.Hash
		}
	})
}
