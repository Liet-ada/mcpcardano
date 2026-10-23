// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Liet-ada/mcpcardano/internal/keystore"
)

// machineCredential is the name of the systemd credential that holds the key
// of the machine: 32 random bytes that systemd-creds sealed with the TPM2
// and the host's key, and that the unit hands over with
// LoadCredentialEncrypted (decision 132).
const machineCredential = "unlock"

// machineKey reads the key of the machine from the credentials that systemd
// hands over, or returns nil if there is none: the person did not choose the
// unlock bound to the machine. The caller wipes it.
func (d *Daemon) machineKey() ([]byte, error) {
	if d.credentials == "" {
		return nil, nil
	}
	k, err := os.ReadFile(filepath.Join(d.credentials, machineCredential))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("walletd: the key of the machine: %w", err)
	}
	if len(k) != keystore.MachineKeySize {
		clear(k)
		return nil, fmt.Errorf("walletd: the key of the machine has %d bytes, not %d", len(k), keystore.MachineKeySize)
	}
	return k, nil
}

// unlockByMachine unlocks the key store at start with the key of the
// machine, if the person chose the unlock bound to it. If there is no key,
// or the key store is not bound to it yet, the wallet waits for the
// password, as without the choice; the first unlock with the password binds
// it.
func (d *Daemon) unlockByMachine() {
	k, err := d.machineKey()
	if k == nil && err == nil {
		return
	}
	if err == nil {
		err = d.store.UnlockMachine(k)
		clear(k)
	}
	e := map[string]any{"ok": err == nil, "by": "machine"}
	switch {
	case errors.Is(err, keystore.ErrNotBound):
		e["error"] = "not bound to the machine yet: the next unlock with the password binds it"
	case err != nil:
		e["error"] = err.Error()
	}
	d.record("unlock", e)
	if err != nil {
		d.log.Warn("unlock by the machine", "err", e["error"])
	}
}
