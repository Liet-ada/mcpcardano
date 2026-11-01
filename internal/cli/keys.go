// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/actions"
	"github.com/Liet-ada/mcpcardano/internal/fido"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
)

// The FIDO2 key in the CLI (paper, section 6.6; decision 123). The CLI only
// carries what the key returns: the wallet checks it.

// keys is how the CLI reaches a security key: fido.Open, or a key in software
// in the tests, and how long it waits for one to be inserted.
type keys struct {
	open fido.Opener
	wait time.Duration
}

// defaultKeys reaches the attached key, waiting two minutes for one.
var defaultKeys = keys{open: fido.Open, wait: 2 * time.Minute}

// rpID is the relying party of the wallet's keys; the wallet refuses a
// credential of any other.
const rpID = "mcpcardano"

// errKeyRefused reports that the key did not do what was asked: a wrong PIN,
// no touch in time, or a key that holds no registered credential. To the
// person it is an authorization refused (section 6.5).
var errKeyRefused = errors.New("the security key refused")

// key opens the attached security key. If none is attached it asks for one,
// saying which, and waits.
func (a *admin) key(which string) (fido.Key, error) {
	deadline := time.Now().Add(a.keys.wait)
	asked := false
	for {
		k, err := a.keys.open(a.ctx)
		if !errors.Is(err, fido.ErrNoKey) {
			return k, err
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("no security key was inserted")
		}
		if !asked {
			fmt.Fprintf(a.errOut, "Insert %s.\n", which)
			asked = true
		}
		select {
		case <-a.ctx.Done():
			return nil, a.ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// pin asks for the PIN of k, saying how many tries are left when few are.
// An empty answer declines.
func (a *admin) pin(k fido.Key, info fido.Info) (string, error) {
	if !info.PIN {
		return "", fmt.Errorf("%s has no PIN: set one with its maker's tool, then try again", k.Name())
	}
	if info.Retries <= 3 {
		fmt.Fprintf(a.errOut, "%s locks after %d more wrong PINs.\n", k.Name(), info.Retries)
	}
	pin, err := a.secret(fmt.Sprintf("PIN of %s (empty to decline): ", k.Name()))
	if err != nil {
		return "", err
	}
	defer clear(pin)
	return string(pin), nil
}

// assert answers a challenge with the key: its PIN if the action needs it,
// then a touch.
func (a *admin) assert(ch *ipc.Challenge) (*ipc.Assertion, error) {
	k, err := a.key("a registered security key")
	if err != nil {
		return nil, err
	}
	defer k.Close()
	pin := ""
	if ch.PIN {
		info, err := k.Info(a.ctx)
		if err != nil {
			return nil, err
		}
		if pin, err = a.pin(k, info); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(a.errOut, "Touch %s before %s.\n", k.Name(), clock(ch.ExpiresAt))
	as, err := k.Assert(a.ctx, ch.RPID, ch.ClientDataHash, ch.Credentials, pin)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errKeyRefused, err)
	}
	return &ipc.Assertion{CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, Signature: as.Signature}, nil
}

// warnRecovery says, at every use of the CLI, that a recovery without keys
// is waiting, and how to cancel it (decision 123).
func (a *admin) warnRecovery(st *ipc.StatusReport) {
	if strings.HasPrefix(a.command, "recover ") {
		return // the recover commands say it themselves
	}
	if r := st.Recovery; r != nil {
		fmt.Fprintf(a.errOut, "A recovery without keys is waiting: at %s the registered keys will be removed and the password will authorize again.\n"+
			"If you did not start it, cancel it now with a registered key: mcpcardano recover cancel\n", clock(r.EndsAt))
	}
}

// suggestKey recommends a key once a wallet may hold relevant funds, if
// there is none (decision 31).
func (a *admin) suggestKey() {
	if a.st != nil && len(a.st.Keys) == 0 {
		fmt.Fprintln(a.errOut, "Consider a security key (mcpcardano key add -name …): with one, a stolen password is not enough to approve payments, open sessions or change policies.")
	}
}

func nameFlag(fs *flag.FlagSet, o *options) {
	fs.StringVar(&o.name, "name", "", "the key's name")
}

// nameArg checks a key's name.
func nameArg(name string) error {
	if actions.CheckKeyName(name) != nil {
		return usageError("-name must be 1 to %d bytes of visible text", ipc.MaxLabel)
	}
	return nil
}

// statusReport asks the wallet for its status.
func (a *admin) statusReport() (*ipc.StatusReport, error) {
	var st ipc.StatusReport
	if err := a.call(ipc.MsgStatus, &ipc.Empty{}, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (a *admin) keyAdd(o *options, _ []string) error {
	if err := nameArg(o.name); err != nil {
		return err
	}
	st, err := a.statusReport()
	if err != nil {
		return err
	}
	k, err := a.key("the new security key")
	if err != nil {
		return err
	}
	info, err := k.Info(a.ctx)
	if err == nil && !info.PIN {
		err = fmt.Errorf("%s has no PIN, and policies, keys and recovery phrases take one: set it with its maker's tool, then try again", k.Name())
	}
	pin := ""
	if err == nil && info.PINToRegister {
		pin, err = a.pin(k, info)
	}
	var data []byte
	if err == nil {
		fmt.Fprintf(a.errOut, "Touch %s to create its credential.\n", k.Name())
		if data, err = k.Register(a.ctx, rpID, pin); err != nil {
			err = fmt.Errorf("%w: %v", errKeyRefused, err)
		}
	}
	k.Close()
	if err != nil {
		return err
	}
	if len(st.Keys) > 0 {
		fmt.Fprint(a.errOut, "Now insert a registered key in its place, and press Enter.")
		if _, err := readLine(a.in); err != nil && !errors.Is(err, errCancelled) {
			return err
		}
		fmt.Fprintln(a.errOut)
	}
	act, err := actions.AddKey(o.name, data)
	if err != nil {
		return usageError("%v", err)
	}
	if err := a.authorize(act.Name, act.Params, nil); err != nil {
		return err
	}
	a.printf("The security key %q is registered.\n", o.name)
	if len(st.Keys) == 0 {
		a.printf("From now on the wallet asks for its touch instead of the password. Register a second key as a backup: with every key lost, a recovery takes days, 72 hours by default.\n")
	}
	return nil
}

func (a *admin) keyRemove(o *options, _ []string) error {
	if err := nameArg(o.name); err != nil {
		return err
	}
	st, err := a.statusReport()
	if err != nil {
		return err
	}
	for _, k := range st.Keys {
		if k.Name == o.name {
			act := actions.RemoveKey(k.CredentialID)
			if err := a.authorize(act.Name, act.Params, nil); err != nil {
				return err
			}
			a.printf("The security key %q is removed.\n", o.name)
			return nil
		}
	}
	return fmt.Errorf("no registered key is named %q: see mcpcardano key list", o.name)
}

func (a *admin) keyList(*options, []string) error {
	st, err := a.statusReport()
	if err != nil {
		return err
	}
	if len(st.Keys) == 0 {
		a.printf("No security key is registered: the password authorizes.\n")
		return nil
	}
	for _, k := range st.Keys {
		alg := "ES256"
		if k.Alg == ipc.AlgEdDSA {
			alg = "EdDSA"
		}
		a.printf("%s  %s, added %s\n", k.Name, alg, time.Unix(k.Added, 0).Format(time.DateOnly))
	}
	return nil
}

func (a *admin) recoverStart(*options, []string) error {
	var r ipc.Recovery
	act := actions.StartRecovery()
	if err := a.authorize(act.Name, act.Params, &r); err != nil {
		return err
	}
	a.printf("The recovery started: every wallet is frozen, and at %s the registered keys will be removed.\n", clock(r.EndsAt))
	a.printf("Then register a new key with mcpcardano key add, and unfreeze the wallets.\n")
	return nil
}

func (a *admin) recoverStatus(*options, []string) error {
	st, err := a.statusReport()
	if err != nil {
		return err
	}
	if st.Recovery == nil {
		a.printf("No recovery is waiting.\n")
		return nil
	}
	a.printf("A recovery started at %s; at %s the registered keys will be removed and the password will authorize again.\n",
		clock(st.Recovery.StartedAt), clock(st.Recovery.EndsAt))
	a.printf("If you did not start it, cancel it now with a registered key: mcpcardano recover cancel\n")
	return nil
}

func (a *admin) recoverCancel(*options, []string) error {
	act := actions.CancelRecovery()
	if err := a.authorize(act.Name, act.Params, nil); err != nil {
		return err
	}
	a.printf("The recovery is cancelled. The wallets stay frozen until you unfreeze them.\n")
	return nil
}
