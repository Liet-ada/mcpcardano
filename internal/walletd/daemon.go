// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package walletd is the wallet process (sections 5, 6, 7 and 9 of the
// specification). It keeps the keys of the wallets of modes B and C, reads
// every transaction with its own decoder, evaluates it against the policy and
// the spending record, and signs only what they allow. It answers the server
// on the service socket and the person, through the CLI, on the admin socket.
// Every request after the greeting goes through one lock, in order (section
// 9.1): the volume of one person and their agents does not call for more.
package walletd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/authz"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/keystore"
	"github.com/Liet-ada/mcpcardano/internal/ledger"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

var (
	// ErrNotIsolated reports a wallet that could reach the network (section
	// 10.3). It does not start.
	ErrNotIsolated = errors.New("walletd: the wallet is not isolated from the network")
	// ErrPermissions reports a file or directory more open than section 7.1
	// allows. The wallet does not start.
	ErrPermissions = errors.New("walletd: permissions too open")
)

// Options are what a Daemon needs besides its configuration.
type Options struct {
	Version string           // of the binary, sent in Hello
	Now     func() time.Time // the wallet's own clock; time.Now by default
	Logger  *slog.Logger     // operation log (section 10.4); never a secret
}

// Daemon is a running wallet.
type Daemon struct {
	cfg     Config
	version string
	now     func() time.Time
	log     *slog.Logger
	codec   *ipc.Codec

	store  *keystore.Store
	ledger *ledger.Ledger
	audit  *audit.Log
	authz  *authz.Authorizer

	mu        sync.Mutex // the single lock (section 9.1)
	st        state
	sessions  map[string]*session  // by wallet id, in memory (section 7.1)
	approvals map[string]*approval // by approval id, in memory

	// crash stops the process at a point of SignDraft, for the crash tests
	// of section 9.1; it does nothing outside them.
	crash func(point string)
}

// session is an open session: until when, and the lovelace it still allows.
type session struct {
	expires   time.Time
	remaining uint64
}

// Init creates the data directory and the key store, with the password and
// the Argon2id parameters of the configuration, before the wallet first
// starts (decision 109).
func Init(cfg Config, password model.Secret) error {
	if err := cfg.Check(); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	if err := checkMode(cfg.DataDir, 0o700); err != nil {
		return err
	}
	return keystore.Create(cfg.keystoreDir(), password, cfg.KeystoreParams())
}

// Open opens the files of the wallet: its audit log, its spending record,
// its key store, locked, and its state. A spending record that does not
// verify keeps the wallet from starting (section 7.3).
func Open(ctx context.Context, cfg Config, o Options) (*Daemon, error) {
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if err := checkMode(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	d := &Daemon{cfg: cfg, version: o.Version, now: o.Now, log: o.Logger, codec: ipc.NewCodec(),
		sessions: map[string]*session{}, approvals: map[string]*approval{}, crash: crashHook()}

	var err error
	var rec audit.Recovery
	if d.audit, rec, err = audit.Open(ctx, cfg.auditPath(), audit.Options{Kind: "audit", Now: o.Now}); err != nil {
		return nil, err
	}
	if rec.Discarded > 0 {
		d.record("audit.recovered", map[string]any{"discarded": rec.Discarded})
	}
	if d.ledger, rec, err = ledger.Open(ctx, cfg.ledgerPath(), o.Now); err != nil {
		d.audit.Close()
		return nil, err
	}
	if rec.Discarded > 0 {
		d.record("ledger.recovered", map[string]any{"discarded": rec.Discarded})
	}
	if d.store, err = keystore.Open(cfg.keystoreDir(), cfg.KeystoreParams()); err != nil {
		d.Close()
		return nil, fmt.Errorf("walletd: key store: %w", err)
	}
	if d.st, err = loadState(cfg.statePath(), cfg.Network); err != nil {
		d.Close()
		return nil, err
	}
	if err := checkMode(cfg.statePath(), 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
		d.Close()
		return nil, err
	}
	d.authz = authz.New(cfg.Network)
	d.authz.Now = o.Now
	d.record("start", map[string]any{"version": o.Version, "network": string(cfg.Network), "development": cfg.Development})
	return d, nil
}

// Close closes the files. The data key leaves memory.
func (d *Daemon) Close() error {
	if d.store != nil {
		d.store.Lock()
	}
	var errs []error
	if d.ledger != nil {
		errs = append(errs, d.ledger.Close())
	}
	if d.audit != nil {
		errs = append(errs, d.audit.Close())
	}
	return errors.Join(errs...)
}

// slot is the current slot by the wallet's own clock (section 9.3).
func (d *Daemon) slot() uint64 { return d.cfg.Network.Clock().Slot(d.now()) }

// record writes an entry of the audit log. A failed write goes to the
// operation log; the spending record, not the audit, is what limits spending.
func (d *Daemon) record(typ string, body map[string]any) {
	if _, err := d.audit.Append(context.Background(), typ, body); err != nil {
		d.log.Error("audit log", "type", typ, "err", err)
	}
}

// checkMode refuses a file or directory that others could read or write.
func checkMode(path string, max fs.FileMode) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&^max != 0 {
		return fmt.Errorf("%w: %s is %v", ErrPermissions, path, fi.Mode().Perm())
	}
	return nil
}
