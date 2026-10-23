// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package keystore is the wallet's encrypted key store (section 7.2 of the
// specification). It uses envelope encryption: a random 32-byte data key
// encrypts the entropy of each wallet, and the data key is kept wrapped by the
// person's password, with Argon2id and XChaCha20-Poly1305. So the password can
// change without encrypting the wallets again. A second wrapping, by a key of
// the machine that systemd keeps sealed by the TPM2, is optional: with it the
// wallet starts unlocked (decision 132).
//
//	keystore/master.key         "MCPKS" || CBOR {v, kdf, salt, nonce, ct, machine?: {nonce, ct}}
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
	"crypto/subtle"
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
	machineID   = "machine" // in the associated data of the envelope of the machine
)

// MachineKeySize is the size of the key of the machine.
const MachineKeySize = keySize

var (
	ErrWrongPassword = errors.New("keystore: wrong password")
	ErrMachineKey    = errors.New("keystore: the key of the machine does not open the key store")
	ErrNotBound      = errors.New("keystore: the key store has no envelope of the machine")
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

// MaxMemoryKiB and MaxTime bound what a master.key may ask of Argon2id, so
// that a damaged one is refused instead of taking all the memory or hanging.
const (
	MaxMemoryKiB = 4 << 20
	MaxTime      = 64
)

// Check reports whether p may be configured: at least one pass and one lane,
// and from MinMemoryKiB to MaxMemoryKiB. A store is never lowered once
// written, so a small machine sets them before the store is created.
func (p Params) Check() error {
	if !p.valid() || p.MemoryKiB < MinMemoryKiB {
		return fmt.Errorf("keystore: Argon2id needs 1 to %d passes, at least 1 lane and %d to %d MiB",
			MaxTime, MinMemoryKiB>>10, MaxMemoryKiB>>10)
	}
	return nil
}

// valid reports whether a master.key may hold p: what Argon2id accepts, with
// 8 KiB per lane at least (RFC 9106, section 3.1), up to MaxTime and
// MaxMemoryKiB. With no passes, Argon2id panics.
func (p Params) valid() bool {
	return p.Time >= 1 && p.Time <= MaxTime && p.Threads >= 1 &&
		p.MemoryKiB >= 8*uint32(p.Threads) && p.MemoryKiB <= MaxMemoryKiB
}

// raised returns p with each parameter that falls short of q's raised to it,
// so that no parameter is ever lowered.
func (p Params) raised(q Params) Params {
	return Params{Time: max(p.Time, q.Time), MemoryKiB: max(p.MemoryKiB, q.MemoryKiB), Threads: max(p.Threads, q.Threads)}
}

type master struct {
	V       uint64  `cbor:"v"`
	KDF     Params  `cbor:"kdf"`
	Salt    []byte  `cbor:"salt"`
	Nonce   []byte  `cbor:"nonce"`
	CT      []byte  `cbor:"ct"`
	Machine *sealed `cbor:"machine,omitempty"`
}

// sealed is the data key wrapped by the key of the machine.
type sealed struct {
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
	var key [keySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	defer clear(key[:])
	m := master{V: FormatVersion}
	if err := sealPassword(&m, &key, password, p); err != nil {
		return err
	}
	return writeMaster(newCodec(), dir, m, false)
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
	b, err := readFile(filepath.Join(s.dir, masterFile))
	if err != nil {
		return m, err
	}
	body, ok := bytes.CutPrefix(b, []byte(masterMagic))
	if !ok || s.codec.Unmarshal(body, &m) != nil || m.V != FormatVersion ||
		len(m.Salt) != saltSize || len(m.Nonce) != chacha20poly1305.NonceSizeX || !m.KDF.valid() ||
		m.Machine != nil && (len(m.Machine.Nonce) != chacha20poly1305.NonceSizeX || len(m.Machine.CT) != keySize+chacha20poly1305.Overhead) {
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

// sealPassword wraps key in m with the password, under the parameters p and
// a new salt.
func sealPassword(m *master, key *[keySize]byte, password model.Secret, p Params) error {
	m.KDF, m.Salt, m.Nonce = p, make([]byte, saltSize), make([]byte, chacha20poly1305.NonceSizeX)
	rand.Read(m.Salt)
	rand.Read(m.Nonce)
	wk := wrapKey(password, m.Salt, p)
	defer clear(wk)
	aead, err := chacha20poly1305.NewX(wk)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	m.CT = aead.Seal(nil, m.Nonce, key[:], associated(masterMagic, ""))
	return nil
}

// sealMachine wraps key with the key of the machine.
func sealMachine(key *[keySize]byte, machine []byte) (*sealed, error) {
	aead, err := chacha20poly1305.NewX(machine)
	if err != nil {
		return nil, ErrMachineKey
	}
	e := &sealed{Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	rand.Read(e.Nonce)
	e.CT = aead.Seal(nil, e.Nonce, key[:], associated(masterMagic, machineID))
	return e, nil
}

// openMachine returns the data key that e wraps, or ErrMachineKey.
func openMachine(e *sealed, machine []byte) (*[keySize]byte, error) {
	aead, err := chacha20poly1305.NewX(machine)
	if err != nil {
		return nil, ErrMachineKey
	}
	pt, err := aead.Open(nil, e.Nonce, e.CT, associated(masterMagic, machineID))
	if err != nil {
		return nil, ErrMachineKey
	}
	defer clear(pt)
	key := new([keySize]byte)
	copy(key[:], pt)
	return key, nil
}

// writeMaster writes m as master.key. Without replace, it fails with
// ErrExists if there is one.
func writeMaster(c *cborx.Codec, dir string, m master, replace bool) error {
	b, err := c.Marshal(m)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	return writeFile(dir, masterFile, append([]byte(masterMagic), b...), replace)
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

// Unlock opens the data key with the password and keeps it in memory. Then
// it brings master.key up to date, and writes it again if anything changes;
// the data key, and so the seeds, stay the same:
//   - an Argon2id parameter lower than the store's is raised, with a new
//     salt, as section 7.6 asks;
//   - the envelope of the machine follows machine, the key of the machine
//     if the wallet has one: it is added, or made again for a new key, and
//     without a key it is removed (decision 132).
//
// It reports whether master.key has the envelope of the machine.
func (s *Store) Unlock(password model.Secret, machine []byte) (bool, error) {
	if machine != nil && len(machine) != MachineKeySize {
		return false, ErrMachineKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readMaster()
	if err != nil {
		return false, err
	}
	key, err := s.unwrap(m, password)
	if err != nil {
		return false, err
	}
	changed := false
	if p := m.KDF.raised(s.params); p != m.KDF {
		err = sealPassword(&m, key, password, p)
		changed = true
	}
	if err == nil && !machineFollows(m.Machine, machine, key) {
		m.Machine = nil
		if machine != nil {
			m.Machine, err = sealMachine(key, machine)
		}
		changed = true
	}
	if err == nil && changed {
		err = writeMaster(s.codec, s.dir, m, true)
	}
	if err != nil {
		clear(key[:])
		return false, err
	}
	if s.key != nil {
		clear(s.key[:])
	}
	s.key = key
	return m.Machine != nil, nil
}

// machineFollows reports whether e is what machine asks for: no envelope
// without a key, or one that the key opens to key.
func machineFollows(e *sealed, machine []byte, key *[keySize]byte) bool {
	if machine == nil || e == nil {
		return machine == nil && e == nil
	}
	k, err := openMachine(e, machine)
	if err != nil {
		return false
	}
	defer clear(k[:])
	return subtle.ConstantTimeCompare(k[:], key[:]) == 1
}

// UnlockMachine opens the data key with the key of the machine and keeps it
// in memory: the unlock at start of decision 132. It fails with ErrNotBound
// if master.key has no envelope of the machine, and with ErrMachineKey if
// machine does not open it. It changes nothing on disk: only an unlock with
// the password raises the parameters or changes the envelope.
func (s *Store) UnlockMachine(machine []byte) error {
	if len(machine) != MachineKeySize {
		return ErrMachineKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readMaster()
	if err != nil {
		return err
	}
	if m.Machine == nil {
		return ErrNotBound
	}
	key, err := openMachine(m.Machine, machine)
	if err != nil {
		return err
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
	f := seed{V: FormatVersion, WalletID: string(id), Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	rand.Read(f.Nonce)
	f.CT = aead.Seal(nil, f.Nonce, entropy, associated(seedMagic, string(id)))
	b, err := s.codec.Marshal(f)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	return writeFile(s.dir, string(id)+seedSuffix, append([]byte(seedMagic), b...), false)
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
	b, err := readFile(seedPath(s.dir, id))
	if err != nil {
		return nil, err
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
