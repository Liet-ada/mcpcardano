// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/authz"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
)

// The FIDO2 key in the wallet (paper, section 6.6; decision 123). With a key
// registered, its touch replaces the password for every action; the password
// keeps only Unlock and the start of a recovery without keys.

// needsPIN lists the actions that take the key's PIN besides the touch: those
// that change who controls the wallets, or show a seed (decision 123).
var needsPIN = map[string]bool{
	ipc.ActChangePolicy:       true,
	ipc.ActSetTemplate:        true,
	ipc.ActAddKey:             true,
	ipc.ActRemoveKey:          true,
	ipc.ActShowRecoveryPhrase: true,
}

// method is how an action is authorized now: by a registered key's touch if
// there is one, by the password otherwise. A recovery starts with the
// password, since it is for a person who lost every key. Only a key cancels
// it, since a recovery waits only while there are keys, so whoever stole the
// password cannot stop the person from cancelling it (section 6.1).
func (d *Daemon) method(action string) string {
	if action != ipc.ActStartRecovery && len(d.st.Keys) > 0 {
		return ipc.MethodKey
	}
	return ipc.MethodPassword
}

// challenge is the answer to BeginAuthorization for an open authorization,
// with what the key needs when the key is the method.
func (d *Daemon) challenge(au *authz.Authorization, summary []string) *ipc.Challenge {
	ch := &ipc.Challenge{AuthID: au.ID[:], Summary: fit(summary), Methods: []string{d.method(au.Action)}, ExpiresAt: au.Expires.Unix()}
	if ch.Methods[0] == ipc.MethodKey {
		h := sha256.Sum256(au.Message)
		ch.RPID, ch.PIN, ch.ClientDataHash = authz.RPID, needsPIN[au.Action], h[:]
		for _, k := range d.st.Keys {
			ch.Credentials = append(ch.Credentials, k.CredentialID)
		}
	}
	return ch
}

// check verifies the password or the key's assertion against an open
// authorization, by the method the action takes now: one that changed since
// BeginAuthorization, because a key was added or removed meanwhile, is the
// one that counts.
func (d *Daemon) check(au *authz.Authorization, b *ipc.CompleteAuthorization) error {
	if d.method(au.Action) == ipc.MethodPassword {
		if b.Password == nil {
			return fail(ipc.AuthFailed, "this authorization takes the password")
		}
		return d.authz.Attempt(func() error { return d.checkPassword(b.Password) })
	}
	if b.Assertion == nil {
		return fail(ipc.AuthFailed, "this authorization takes a touch of a registered key")
	}
	return d.checkKey(au, b.Assertion)
}

// checkKey verifies a key's assertion over the authorization's message and
// keeps the key's new counter. A refusal goes to the audit log.
func (d *Daemon) checkKey(au *authz.Authorization, a *ipc.Assertion) error {
	i := d.st.key(a.CredentialID)
	var n uint32
	err := authz.ErrKeyUnknown
	if i >= 0 {
		n, err = authz.Verify(d.st.Keys[i].authz(), au.Message,
			authz.Assertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, Signature: a.Signature},
			authz.Rules{PIN: needsPIN[au.Action], AllowSynced: d.cfg.AllowSyncedKeys})
	}
	if err != nil {
		d.record("key.refused", map[string]any{"action": au.Action, "key": authz.KeyID(a.CredentialID), "error": err.Error()})
		return err
	}
	if n == d.st.Keys[i].Counter {
		return nil
	}
	return d.update(func(st *state) error { st.Keys[i].Counter = n; return nil })
}

// newKey reads the credential of add_key and checks that it can join the
// registered keys.
func (d *Daemon) newKey(p *ipc.AddKey) (authz.Key, error) {
	k, err := d.authz.Credential(p.AuthenticatorData, authz.Rules{AllowSynced: d.cfg.AllowSyncedKeys})
	if err != nil {
		return authz.Key{}, fail(ipc.Malformed, "the new key: %v", err)
	}
	switch {
	case len(d.st.Keys) >= ipc.MaxKeys:
		return authz.Key{}, fail(ipc.Malformed, "the wallet keeps at most %d keys", ipc.MaxKeys)
	case d.st.key(k.CredentialID) >= 0:
		return authz.Key{}, fail(ipc.Malformed, "the key is already registered")
	}
	for _, r := range d.st.Keys {
		if r.Name == p.Name {
			return authz.Key{}, fail(ipc.Malformed, "there is already a key named %q", p.Name)
		}
	}
	return k, nil
}

// prepareKey prepares the actions of keys and recovery (section 6.3).
func (d *Daemon) prepareKey(action string, params ipc.Body) (prepared, error) {
	switch p := params.(type) {
	case *ipc.AddKey:
		k, err := d.newKey(p)
		if err != nil {
			return prepared{}, err
		}
		// The message covers the credential, so the touch or the password
		// authorizes exactly this key (decision 123).
		det := map[string]any{"credential_id": k.CredentialID, "alg": k.Alg, "public_key": k.PublicKey}
		lines := []string{fmt.Sprintf("Register the security key %q (%s, %s)", p.Name, algName(k.Alg), authz.KeyID(k.CredentialID))}
		if len(d.st.Keys) == 0 {
			lines = append(lines, "From then on every authorization takes a touch of a registered key instead of the password.")
		}
		return prepared{"", det, lines}, nil
	case *ipc.KeyRef:
		i := d.st.key(p.CredentialID)
		if i < 0 {
			return prepared{}, fail(ipc.NotFound, "no key %s", authz.KeyID(p.CredentialID))
		}
		k := d.st.Keys[i]
		lines := []string{fmt.Sprintf("Remove the security key %q (%s, %s)", k.Name, algName(k.Alg), authz.KeyID(k.CredentialID))}
		if len(d.st.Keys) == 1 {
			lines = append(lines, "With no key left, the password authorizes again.")
		}
		return prepared{"", map[string]any{"credential_id": k.CredentialID}, lines}, nil
	}
	switch action {
	case ipc.ActStartRecovery:
		if err := d.canStartRecovery(); err != nil {
			return prepared{}, err
		}
		wait := d.cfg.recoveryWait()
		keys := fmt.Sprintf("the %d registered keys are", len(d.st.Keys))
		if len(d.st.Keys) == 1 {
			keys = "the registered key is"
		}
		return prepared{"", map[string]any{"seconds": uint64(wait / time.Second)}, []string{
			fmt.Sprintf("Start a recovery without keys: every wallet is frozen now, and after %s %s removed and the password authorizes again.",
				hours(wait), keys),
			"Until then, a touch of a registered key cancels it (mcpcardano recover cancel).",
		}}, nil
	case ipc.ActCancelRecovery:
		r := d.st.Recovery
		if r == nil {
			return prepared{}, fail(ipc.NotFound, "no recovery is waiting")
		}
		return prepared{"", nil, []string{
			"Cancel the recovery that started at " + time.Unix(r.StartedAt, 0).UTC().Format(time.RFC3339) + ".",
			"The wallets stay frozen until you unfreeze them.",
		}}, nil
	}
	return prepared{}, fail(ipc.Malformed, "unknown action %s", action)
}

func (d *Daemon) canStartRecovery() error {
	switch {
	case len(d.st.Keys) == 0:
		return fail(ipc.NotFound, "there is no key to recover from: the password already authorizes")
	case d.st.Recovery != nil:
		return fail(ipc.Malformed, "a recovery is already waiting, until %s",
			time.Unix(d.st.Recovery.EndsAt, 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// runKey carries out the actions of keys and recovery, once authorized.
func (d *Daemon) runKey(au *authz.Authorization) (ipc.Body, error) {
	switch p := au.Params.(type) {
	case *ipc.AddKey:
		k, err := d.newKey(p)
		if err != nil {
			return nil, err
		}
		r := keyRecord{Name: p.Name, CredentialID: k.CredentialID, Alg: k.Alg, PublicKey: k.PublicKey,
			Counter: k.Counter, Added: d.now().Unix()}
		if err := d.update(func(st *state) error { st.Keys = append(st.Keys, r); return nil }); err != nil {
			return nil, err
		}
		d.record("key.added", map[string]any{"name": r.Name, "key": authz.KeyID(r.CredentialID), "alg": algName(r.Alg)})
		return &ipc.Empty{}, nil
	case *ipc.KeyRef:
		i := d.st.key(p.CredentialID)
		if i < 0 {
			return nil, fail(ipc.NotFound, "no key %s", authz.KeyID(p.CredentialID))
		}
		name := d.st.Keys[i].Name
		err := d.update(func(st *state) error {
			st.Keys = slices.Delete(st.Keys, i, i+1)
			if len(st.Keys) == 0 {
				st.Recovery = nil // nothing left to recover from
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		d.record("key.removed", map[string]any{"name": name, "key": authz.KeyID(p.CredentialID)})
		return &ipc.Empty{}, nil
	}
	switch au.Action {
	case ipc.ActStartRecovery:
		if err := d.canStartRecovery(); err != nil {
			return nil, err
		}
		now := d.now()
		r := &ipc.Recovery{StartedAt: now.Unix(), EndsAt: now.Add(d.cfg.recoveryWait()).Unix()}
		err := d.update(func(st *state) error {
			st.Recovery = r
			for i := range st.Wallets {
				st.Wallets[i].Policy.Frozen = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		d.record("recovery.started", map[string]any{"ends_at": r.EndsAt, "cancelled": d.authz.Cancel("")})
		return r, nil
	case ipc.ActCancelRecovery:
		if d.st.Recovery == nil {
			return nil, fail(ipc.NotFound, "no recovery is waiting")
		}
		if err := d.update(func(st *state) error { st.Recovery = nil; return nil }); err != nil {
			return nil, err
		}
		d.record("recovery.cancelled", map[string]any{})
		return &ipc.Empty{}, nil
	}
	return nil, fail(ipc.Malformed, "unknown action %s", au.Action)
}

// settleRecovery ends a recovery whose wait is over by the wallet's clock:
// the registered keys are removed and the password authorizes again. The
// wallets stay frozen until the person unfreezes them (decision 123).
func (d *Daemon) settleRecovery() error {
	r := d.st.Recovery
	if r == nil || d.now().Unix() < r.EndsAt {
		return nil
	}
	n := len(d.st.Keys)
	if err := d.update(func(st *state) error { st.Keys, st.Recovery = nil, nil; return nil }); err != nil {
		return err
	}
	d.record("recovery.completed", map[string]any{"keys_removed": n})
	return nil
}

// hours writes a wait of whole hours as hours, and any other as Go does.
func hours(d time.Duration) string {
	switch {
	case d == time.Hour:
		return "1 hour"
	case d%time.Hour == 0:
		return fmt.Sprintf("%d hours", d/time.Hour)
	}
	return d.String()
}

func algName(alg int) string {
	if alg == ipc.AlgEdDSA {
		return "EdDSA"
	}
	return "ES256"
}
