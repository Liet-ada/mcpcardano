// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package keystore is the wallet's encrypted key store (section 7.2 of the
// specification). It uses envelope encryption: a random 32-byte data key
// encrypts the entropy of each wallet, and the data key is kept wrapped by the
// person's password, with Argon2id and XChaCha20-Poly1305. So the password can
// change without encrypting the wallets again, and a second wrapping, by the
// machine, can arrive in H-3.
//
//	keystore/master.key         "MCPKS" || CBOR {v, kdf, salt, nonce, ct}
//	keystore/<wallet_id>.seed   "MCPWS" || CBOR {v, wallet_id, nonce, ct}
//
// A wrong password shows as a failed authentication tag; no verifier is kept.
// A seed file binds its wallet id and version as associated data, so it does
// not open if it is renamed or swapped for another.
package keystore

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// FormatVersion is the version of both files.
const FormatVersion = 1

const (
	masterMagic = "MCPKS"
	seedMagic   = "MCPWS"
	masterFile  = "master.key"
	seedSuffix  = ".seed"
	keySize     = chacha20poly1305.KeySize
	saltSize    = 16
)

var (
	ErrWrongPassword = errors.New("keystore: wrong password")
	ErrLocked        = errors.New("keystore: locked")
	ErrExists        = errors.New("keystore: already exists")
	ErrNotFound      = errors.New("keystore: no such key store or seed")
	ErrFormat        = errors.New("keystore: not a key store file of a known version")
	ErrPermissions   = errors.New("keystore: permissions are more open than 0700 for the directory or 0600 for a file")
)

// Params are the Argon2id parameters, kept in master.key so that they can be
// raised later.
type Params struct {
	Time      uint32 `cbor:"time"`       // passes
	MemoryKiB uint32 `cbor:"memory_kib"` // memory
	Threads   uint8  `cbor:"threads"`
}

// DefaultParams are 3 passes over 256 MiB with 4 lanes: the second
// recommended option of RFC 9106 with four times its memory. The wallet
// unlocks once at start and Argon2id runs again only when the person
// authorizes something, so it can afford them; what they cost is the memory
// of an attacker who tries passwords against a stolen master.key.
func DefaultParams() Params { return Params{Time: 3, MemoryKiB: 256 << 10, Threads: 4} }

// MinMemoryKiB is the least memory the wallet's configuration may set, for
// small machines: the 64 MiB of RFC 9106's second option.
const MinMemoryKiB = 64 << 10

// Check reports whether p may be configured: at least one pass and one lane,
// and at least MinMemoryKiB. A store is never lowered once written, so a
// small machine sets them before the store is created.
func (p Params) Check() error {
	if p.Time < 1 || p.Threads < 1 || p.MemoryKiB < MinMemoryKiB {
		return fmt.Errorf("keystore: Argon2id needs at least 1 pass, 1 lane and %d MiB", MinMemoryKiB>>10)
	}
	return nil
}

// weaker reports whether p falls short of q in any parameter.
func (p Params) weaker(q Params) bool {
	return p.Time < q.Time || p.MemoryKiB < q.MemoryKiB || p.Threads < q.Threads
}

type master struct {
	V     uint64 `cbor:"v"`
	KDF   Params `cbor:"kdf"`
	Salt  []byte `cbor:"salt"`
	Nonce []byte `cbor:"nonce"`
	CT    []byte `cbor:"ct"`
}

type seed struct {
	V        uint64 `cbor:"v"`
	WalletID string `cbor:"wallet_id"`
	Nonce    []byte `cbor:"nonce"`
	CT       []byte `cbor:"ct"`
}

func newCodec() *cborx.Codec {
	c, err := cborx.New(cborx.RecordLimits())
	if err != nil {
		panic(err) // the limits are constants
	}
	return c
}

// Store is an open key store. It is safe for concurrent use.
type Store struct {
	dir    string
	params Params // what Unlock raises the file to
	codec  *cborx.Codec

	mu  sync.Mutex
	key *[keySize]byte // the data key; nil while locked
}

// Create makes a key store in dir, which it creates with mode 0700 if
// missing, with a new data key wrapped by password. It fails with ErrExists
// if there is already one.
func Create(dir string, password model.Secret, p Params) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	if err := checkMode(dir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, masterFile)); err == nil {
		return ErrExists
	}
	var key [keySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	defer clear(key[:])
	return writeMaster(newCodec(), dir, &key, password, p)
}

// Open reads the key store in dir, locked. Unlock raises its Argon2id
// parameters to p if they are lower. It refuses a directory or file that
// other users could read (section 7.1).
func Open(dir string, p Params) (*Store, error) {
	if err := checkMode(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, params: p, codec: newCodec()}
	if _, err := s.readMaster(); err != nil {
		return nil, err
	}
	return s, nil
}

func checkMode(path string, max fs.FileMode) error {
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	if fi.Mode().Perm()&^max != 0 {
		return fmt.Errorf("%w: %s is %v", ErrPermissions, filepath.Base(path), fi.Mode().Perm())
	}
	return nil
}

func (s *Store) readMaster() (master, error) {
	var m master
	path := filepath.Join(s.dir, masterFile)
	if err := checkMode(path, 0o600); err != nil {
		return m, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return m, fmt.Errorf("keystore: %w", err)
	}
	body, ok := bytes.CutPrefix(b, []byte(masterMagic))
	if !ok || s.codec.Unmarshal(body, &m) != nil || m.V != FormatVersion ||
		len(m.Salt) != saltSize || len(m.Nonce) != chacha20poly1305.NonceSizeX || m.KDF.Threads == 0 {
		return m, ErrFormat
	}
	return m, nil
}

// wrapKey derives the key that wraps the data key.
func wrapKey(password []byte, salt []byte, p Params) []byte {
	return argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, keySize)
}

// associated is the associated data of a file: its magic, its version and,
// for a seed, the wallet id.
func associated(magic string, id string) []byte {
	return append([]byte(magic), append([]byte{FormatVersion}, id...)...)
}

func writeMaster(c *cborx.Codec, dir string, key *[keySize]byte, password model.Secret, p Params) error {
	m := master{V: FormatVersion, KDF: p, Salt: make([]byte, saltSize), Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	rand.Read(m.Salt)
	rand.Read(m.Nonce)
	wk := wrapKey(password, m.Salt, p)
	defer clear(wk)
	aead, err := chacha20poly1305.NewX(wk)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	m.CT = aead.Seal(nil, m.Nonce, key[:], associated(masterMagic, ""))
	b, err := c.Marshal(m)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	return writeFile(dir, masterFile, append([]byte(masterMagic), b...))
}

// unwrap returns the data key in master.key, or ErrWrongPassword.
func (s *Store) unwrap(m master, password model.Secret) (*[keySize]byte, error) {
	wk := wrapKey(password, m.Salt, m.KDF)
	defer clear(wk)
	aead, err := chacha20poly1305.NewX(wk)
	if err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}
	pt, err := aead.Open(nil, m.Nonce, m.CT, associated(masterMagic, ""))
	if err != nil {
		return nil, ErrWrongPassword
	}
	defer clear(pt)
	if len(pt) != keySize {
		return nil, ErrFormat
	}
	key := new([keySize]byte)
	copy(key[:], pt)
	return key, nil
}

// Unlock opens the data key with the password and keeps it in memory. If
// master.key has weaker Argon2id parameters than the store's, it is written
// again with them and a new salt, as section 7.6 asks; the data key, and so
// the seeds, stay the same.
func (s *Store) Unlock(password model.Secret) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readMaster()
	if err != nil {
		return err
	}
	key, err := s.unwrap(m, password)
	if err != nil {
		return err
	}
	if m.KDF.weaker(s.params) {
		if err := writeMaster(s.codec, s.dir, key, password, s.params); err != nil {
			clear(key[:])
			return err
		}
	}
	if s.key != nil {
		clear(s.key[:])
	}
	s.key = key
	return nil
}

// CheckPassword reports whether password opens the key store, without
// changing anything: ErrWrongPassword if not.
func (s *Store) CheckPassword(password model.Secret) error {
	m, err := s.readMaster()
	if err != nil {
		return err
	}
	key, err := s.unwrap(m, password)
	if err != nil {
		return err
	}
	clear(key[:])
	return nil
}

// Locked reports whether the data key is not in memory.
func (s *Store) Locked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.key == nil
}

// Lock wipes the data key from memory.
func (s *Store) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		clear(s.key[:])
		s.key = nil
	}
}

func (s *Store) aead() (cipher.AEAD, error) {
	if s.key == nil {
		return nil, ErrLocked
	}
	return chacha20poly1305.NewX(s.key[:])
}

func seedPath(dir string, id model.WalletID) string { return filepath.Join(dir, string(id)+seedSuffix) }

// PutSeed stores the entropy of a wallet's recovery phrase. It never
// replaces a seed: ErrExists if the wallet has one.
func (s *Store) PutSeed(id model.WalletID, entropy model.Secret) error {
	if err := id.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	aead, err := s.aead()
	if err != nil {
		return err
	}
	if _, err := os.Stat(seedPath(s.dir, id)); err == nil {
		return ErrExists
	}
	f := seed{V: FormatVersion, WalletID: string(id), Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	rand.Read(f.Nonce)
	f.CT = aead.Seal(nil, f.Nonce, entropy, associated(seedMagic, string(id)))
	b, err := s.codec.Marshal(f)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	return writeFile(s.dir, string(id)+seedSuffix, append([]byte(seedMagic), b...))
}

// Seed returns the entropy of a wallet's recovery phrase. The caller wipes it.
func (s *Store) Seed(id model.WalletID) (model.Secret, error) {
	if err := id.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	aead, err := s.aead()
	if err != nil {
		return nil, err
	}
	path := seedPath(s.dir, id)
	if err := checkMode(path, 0o600); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}
	var f seed
	body, ok := bytes.CutPrefix(b, []byte(seedMagic))
	if !ok || s.codec.Unmarshal(body, &f) != nil || f.V != FormatVersion ||
		f.WalletID != string(id) || len(f.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrFormat
	}
	// The associated data is the id asked for, not the one in the file, so
	// a seed of another wallet fails to open even if its id field is changed
	// to match.
	pt, err := aead.Open(nil, f.Nonce, f.CT, associated(seedMagic, string(id)))
	if err != nil {
		return nil, fmt.Errorf("%w: the seed of %s does not open with this key store", ErrFormat, id)
	}
	return model.Secret(pt), nil
}
