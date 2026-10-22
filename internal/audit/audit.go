// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package audit implements the append-only, hash-chained records of section
// 7.3 of the specification. The audit log of each process and the wallet's
// spending record share this format; they differ only in their kind and in
// the entry types they write.
//
// Each entry is a length-prefixed canonical CBOR map with seq, time, prev,
// type, body and hash, where hash = SHA-256(prev || entry without hash).
// The first entry of every log is a header with the format version and the
// kind. Deleting or changing an entry breaks the chain.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
)

// FormatVersion is the version this package writes.
const FormatVersion = 1

// HeaderType is the type of the first entry of every log.
const HeaderType = "log.header"

// DefaultMaxEntrySize matches the largest message between processes.
const DefaultMaxEntrySize = 256 << 10

var (
	// ErrBrokenChain reports a log that was changed, reordered or cut in the
	// middle. A process must not start on such a log.
	ErrBrokenChain = errors.New("audit: broken hash chain")
	// ErrWrongKind reports a log of another kind, or of an unknown version.
	ErrWrongKind = errors.New("audit: unexpected log kind or version")
	// ErrClosed reports a write on a closed or failed log.
	ErrClosed = errors.New("audit: log is closed or failed")
)

// Entry is one record.
type Entry struct {
	Seq  uint64    `cbor:"seq"`
	Time int64     `cbor:"time"` // Unix seconds
	Prev []byte    `cbor:"prev"`
	Type string    `cbor:"type"`
	Body cborx.Raw `cbor:"body"`
	Hash []byte    `cbor:"hash,omitempty"`
}

type header struct {
	V    uint64 `cbor:"v"`
	Kind string `cbor:"kind"`
}

// Options configure a log.
type Options struct {
	Kind         string           // "audit" or "ledger"; checked on open
	Now          func() time.Time // defaults to time.Now
	MaxEntrySize int              // defaults to DefaultMaxEntrySize
}

func (o Options) withDefaults() Options {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxEntrySize == 0 {
		o.MaxEntrySize = DefaultMaxEntrySize
	}
	return o
}

// Recovery reports what Open had to repair.
type Recovery struct {
	// Discarded is the length of an incomplete last entry that was cut off:
	// a crash in the middle of a write. The caller records it in its audit
	// log (section 7.3).
	Discarded int64
}

// Log is an open log ready for appending. It is safe for concurrent use.
type Log struct {
	mu    sync.Mutex
	f     *os.File
	codec *cborx.Codec
	opts  Options
	seq   uint64
	last  []byte
	err   error // set after a failed write; the log must be reopened
}

func newCodec() *cborx.Codec {
	c, err := cborx.New(cborx.RecordLimits())
	if err != nil {
		panic(err) // the limits are constants
	}
	return c
}

func hashEntry(c *cborx.Codec, e Entry) ([]byte, error) {
	e.Hash = nil
	b, err := c.Marshal(e)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(e.Prev)
	h.Write(b)
	return h.Sum(nil), nil
}

// state is where a verified chain ends.
type state struct {
	entries []Entry
	good    int64 // bytes of complete, verified entries
	partial bool  // an incomplete entry follows the good bytes
}

// scan reads and verifies every entry of r.
func scan(ctx context.Context, r io.Reader, c *cborx.Codec, opts Options) (state, error) {
	var st state
	prev := make([]byte, sha256.Size)
	for {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		frame, err := cborx.ReadFrame(r, opts.MaxEntrySize)
		switch {
		case errors.Is(err, io.EOF):
			return st, nil
		case errors.Is(err, io.ErrUnexpectedEOF):
			st.partial = true
			return st, nil
		case err != nil:
			return st, fmt.Errorf("%w: entry %d: %v", ErrBrokenChain, len(st.entries)+1, err)
		}
		var e Entry
		if err := c.Unmarshal(frame, &e); err != nil {
			return st, fmt.Errorf("%w: entry %d: %v", ErrBrokenChain, len(st.entries)+1, err)
		}
		if err := verify(c, frame, e, uint64(len(st.entries))+1, prev); err != nil {
			return st, fmt.Errorf("%w: entry %d: %v", ErrBrokenChain, len(st.entries)+1, err)
		}
		if e.Seq == 1 {
			if err := checkHeader(c, e, opts.Kind); err != nil {
				return st, err
			}
		}
		prev = e.Hash
		st.entries = append(st.entries, e)
		st.good += int64(cborx.FrameHeaderSize + len(frame))
	}
}

func verify(c *cborx.Codec, frame []byte, e Entry, seq uint64, prev []byte) error {
	if e.Seq != seq {
		return fmt.Errorf("sequence %d, want %d", e.Seq, seq)
	}
	if !bytes.Equal(e.Prev, prev) {
		return errors.New("prev does not match the previous hash")
	}
	if err := c.CheckCanonical(e.Body); err != nil {
		return fmt.Errorf("body: %v", err)
	}
	// The bytes on disk must be exactly the canonical encoding, so the hash
	// covers what is stored and nothing else.
	b, err := c.Marshal(e)
	if err != nil || !bytes.Equal(b, frame) {
		return errors.New("entry is not canonical")
	}
	h, err := hashEntry(c, e)
	if err != nil {
		return err
	}
	if !bytes.Equal(h, e.Hash) {
		return errors.New("hash mismatch")
	}
	return nil
}

func checkHeader(c *cborx.Codec, e Entry, kind string) error {
	var h header
	if e.Type != HeaderType || c.Unmarshal(e.Body, &h) != nil || h.Kind != kind || h.V == 0 || h.V > FormatVersion {
		return fmt.Errorf("%w: want a %q log of version %d or lower", ErrWrongKind, kind, FormatVersion)
	}
	return nil
}

// Read returns the verified entries of the log at path without changing it,
// for `mcpcardano audit show` and `audit verify`. An incomplete last entry is
// reported in Recovery and left in place.
func Read(ctx context.Context, path string, opts Options) ([]Entry, Recovery, error) {
	opts = opts.withDefaults()
	f, err := os.Open(path)
	if err != nil {
		return nil, Recovery{}, err
	}
	defer f.Close()
	st, err := scan(ctx, f, newCodec(), opts)
	if err != nil {
		return nil, Recovery{}, err
	}
	var rec Recovery
	if st.partial {
		size, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			return nil, Recovery{}, err
		}
		rec.Discarded = size - st.good
	}
	return st.entries, rec, nil
}

// Open opens the log at path for appending, creating it with its header if it
// does not exist. It verifies the whole chain first and cuts off an
// incomplete last entry; any other damage is an error wrapping
// ErrBrokenChain, and the log stays untouched.
func Open(ctx context.Context, path string, opts Options) (*Log, Recovery, error) {
	l, _, rec, err := OpenEntries(ctx, path, opts)
	return l, rec, err
}

// OpenEntries is Open that also returns the verified entries, header
// included, for a log whose state is rebuilt from them, such as the wallet's
// spending record.
func OpenEntries(ctx context.Context, path string, opts Options) (*Log, []Entry, Recovery, error) {
	opts = opts.withDefaults()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, Recovery{}, err
	}
	l, entries, rec, err := open(ctx, f, path, opts)
	if err != nil {
		f.Close()
		return nil, nil, Recovery{}, err
	}
	return l, entries, rec, nil
}

func open(ctx context.Context, f *os.File, path string, opts Options) (*Log, []Entry, Recovery, error) {
	c := newCodec()
	st, err := scan(ctx, f, c, opts)
	if err != nil {
		return nil, nil, Recovery{}, err
	}
	var rec Recovery
	if st.partial {
		size, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			return nil, nil, Recovery{}, err
		}
		rec.Discarded = size - st.good
		if err := f.Truncate(st.good); err != nil {
			return nil, nil, Recovery{}, fmt.Errorf("audit: cutting an incomplete entry: %w", err)
		}
		if err := f.Sync(); err != nil {
			return nil, nil, Recovery{}, err
		}
	}
	if _, err := f.Seek(st.good, io.SeekStart); err != nil {
		return nil, nil, Recovery{}, err
	}
	l := &Log{f: f, codec: c, opts: opts, last: make([]byte, sha256.Size)}
	if n := len(st.entries); n > 0 {
		l.seq = st.entries[n-1].Seq
		l.last = st.entries[n-1].Hash
		return l, st.entries, rec, nil
	}
	// A new log, or one that crashed before its header was complete.
	h, err := l.append(HeaderType, header{V: FormatVersion, Kind: opts.Kind})
	if err != nil {
		return nil, nil, Recovery{}, err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return nil, nil, Recovery{}, err
	}
	return l, []Entry{h}, rec, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("audit: sync directory: %w", err)
	}
	return nil
}

// Append encodes body canonically, adds it as the next entry and waits for
// it to reach the disk. When Append returns nil the entry is durable.
func (l *Log) Append(ctx context.Context, typ string, body any) (Entry, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	if typ == HeaderType {
		return Entry{}, fmt.Errorf("audit: %q is reserved", HeaderType)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.append(typ, body)
}

func (l *Log) append(typ string, body any) (Entry, error) {
	if l.f == nil || l.err != nil {
		return Entry{}, ErrClosed
	}
	b, err := l.codec.Marshal(body)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{Seq: l.seq + 1, Time: l.opts.Now().Unix(), Prev: l.last, Type: typ, Body: b}
	if e.Hash, err = hashEntry(l.codec, e); err != nil {
		return Entry{}, err
	}
	frame, err := l.codec.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	// A failed or partial write leaves the file in an unknown state; the log
	// refuses further writes until it is reopened, which repairs it.
	if err := cborx.WriteFrame(l.f, frame, l.opts.MaxEntrySize); err != nil {
		if !errors.Is(err, cborx.ErrFrameTooLarge) {
			l.err = err
		}
		return Entry{}, err
	}
	if err := l.f.Sync(); err != nil {
		l.err = err
		return Entry{}, fmt.Errorf("audit: sync: %w", err)
	}
	l.seq, l.last = e.Seq, e.Hash
	return e, nil
}

// Close closes the log.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
