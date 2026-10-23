// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/keystore"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// ErrConfig reports a configuration the wallet does not accept.
var ErrConfig = errors.New("walletd: invalid configuration")

// maxConfigBytes bounds config.json.
const maxConfigBytes = 64 << 10

// Config is the wallet's config.json (section 7.5): the network, where its
// files and sockets live, and who may connect to each socket. It holds no
// secret.
type Config struct {
	Network       model.Network `json:"network"`
	DataDir       string        `json:"data_dir"`
	ServiceSocket string        `json:"service_socket"`
	AdminSocket   string        `json:"admin_socket"`
	// ServiceUID and AdminUID are the users the kernel must certify at the
	// other end of each socket: the server's and the person's (section 5.1).
	ServiceUID *uint32 `json:"service_uid"`
	AdminUID   *uint32 `json:"admin_uid"`
	// Argon2MemoryMiB is the memory of Argon2id for a key store created with
	// this configuration: 256 by default, from 64 to 4096 (decision 104).
	Argon2MemoryMiB uint32 `json:"argon2_memory_mib,omitempty"`
	// AllowSyncedKeys accepts FIDO2 credentials that may be synced to a
	// cloud, which the wallet refuses by default (paper, section 6.6).
	AllowSyncedKeys bool `json:"allow_synced_keys,omitempty"`
	// RecoveryWaitHours is how long a recovery without keys keeps the
	// wallets frozen before it removes the keys: 72 by default.
	RecoveryWaitHours uint32 `json:"recovery_wait_hours,omitempty"`
	// Development skips the isolation check, and the audit log records that
	// it did (section 10.3).
	Development bool `json:"development,omitempty"`
}

// defaultRecoveryWait is the wait of a recovery without keys.
const defaultRecoveryWait = 72 * time.Hour

// recoveryWait returns the wait of a recovery without keys.
func (c Config) recoveryWait() time.Duration {
	if c.RecoveryWaitHours == 0 {
		return defaultRecoveryWait
	}
	return time.Duration(c.RecoveryWaitHours) * time.Hour
}

// LoadConfig reads config.json strictly: an unknown field, or data after the
// object, is an error. The result is checked.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return Config{}, err
	}
	if len(data) > maxConfigBytes {
		return Config{}, fmt.Errorf("%w: %s is larger than %d bytes", ErrConfig, path, maxConfigBytes)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%w: %s: %v", ErrConfig, path, err)
	}
	if dec.More() {
		return Config{}, fmt.Errorf("%w: %s: data after the configuration", ErrConfig, path)
	}
	return c, c.Check()
}

// Check validates a configuration. Mainnet waits for milestone H-4.
func (c Config) Check() error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrConfig}, args...)...)
	}
	switch {
	case !c.Network.Valid():
		return fail("unknown network %q", c.Network)
	case c.Network == model.Mainnet:
		return fail("mainnet is not enabled before milestone H-4")
	case !filepath.IsAbs(c.DataDir):
		return fail("data_dir must be an absolute path")
	case !filepath.IsAbs(c.ServiceSocket) || !filepath.IsAbs(c.AdminSocket):
		return fail("the sockets must be absolute paths")
	case c.ServiceSocket == c.AdminSocket:
		return fail("the two sockets must be different")
	case c.ServiceUID == nil || c.AdminUID == nil:
		return fail("service_uid and admin_uid are required")
	case c.Argon2MemoryMiB > keystore.MaxMemoryKiB>>10:
		// Checked before KeystoreParams, whose shift to KiB would overflow.
		return fail("argon2_memory_mib may be at most %d", keystore.MaxMemoryKiB>>10)
	}
	if err := c.KeystoreParams().Check(); err != nil {
		return fail("argon2_memory_mib: %v", err)
	}
	return nil
}

// KeystoreParams returns the Argon2id parameters of a key store created with
// this configuration, and the ones Unlock raises a weaker store to.
func (c Config) KeystoreParams() keystore.Params {
	p := keystore.DefaultParams()
	if c.Argon2MemoryMiB != 0 {
		p.MemoryKiB = c.Argon2MemoryMiB << 10
	}
	return p
}

// keystoreDir, ledgerPath, auditPath and statePath are the files of section
// 7.1, inside the data directory.
func (c Config) keystoreDir() string { return filepath.Join(c.DataDir, "keystore") }
func (c Config) ledgerPath() string  { return filepath.Join(c.DataDir, "ledger.log") }
func (c Config) auditPath() string   { return filepath.Join(c.DataDir, "audit.log") }
func (c Config) statePath() string   { return filepath.Join(c.DataDir, "state.cbor") }
