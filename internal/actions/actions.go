// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package actions builds what the person asks the wallet to authorize, once
// for the CLI and the view (decision 142): an action's name with its
// parameters, after checking what the person gave. The wallet decides; these
// checks give the same answer in both before it is asked.
package actions

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Action is an action for BeginAuthorization.
type Action struct {
	Name   string
	Params ipc.Body
}

// ApproveDraft approves a payment waiting for the person.
func ApproveDraft(approvalID string) Action {
	return Action{ipc.ActApproveDraft, &ipc.ApproveDraft{ApprovalID: approvalID}}
}

// Unfreeze unfreezes a wallet.
func Unfreeze(walletID string) Action {
	return Action{ipc.ActUnfreeze, &ipc.WalletRef{WalletID: walletID}}
}

// ShowPhrase asks for the recovery phrase of a wallet.
func ShowPhrase(walletID string) Action {
	return Action{ipc.ActShowRecoveryPhrase, &ipc.WalletRef{WalletID: walletID}}
}

// OpenSession opens a session on a wallet for length, up to maxLovelace.
func OpenSession(walletID string, length time.Duration, maxLovelace uint64) (Action, error) {
	if length < time.Second || length/time.Second > math.MaxUint32 {
		return Action{}, errors.New("a session lasts a duration such as 30m or 2h")
	}
	if maxLovelace == 0 {
		return Action{}, errors.New("a session's maximum must be above zero")
	}
	return Action{ipc.ActOpenSession, &ipc.OpenSession{WalletID: walletID, Seconds: uint32(length / time.Second), MaxLovelace: maxLovelace}}, nil
}

// ReleaseBudget releases expired_unconfirmed entries of a wallet (section
// 9.2), sorted and without repeats, as the wallet takes them.
func ReleaseBudget(walletID string, entries [][]byte) Action {
	entries = slices.Clone(entries)
	slices.SortFunc(entries, bytes.Compare)
	return Action{ipc.ActReleaseBudget, &ipc.ReleaseBudget{WalletID: walletID, Entries: slices.CompactFunc(entries, bytes.Equal)}}
}

// CreateWallet creates a wallet from the template.
func CreateWallet(label string) (Action, error) {
	if err := checkLabel(label); err != nil {
		return Action{}, err
	}
	return Action{ipc.ActCreateWallet, &ipc.CreateWallet{Label: label}}, nil
}

// RestoreWallet restores a wallet from its recovery phrase. The caller wipes
// the phrase.
func RestoreWallet(label string, phrase model.Secret) (Action, error) {
	if err := checkLabel(label); err != nil {
		return Action{}, err
	}
	return Action{ipc.ActRestoreWallet, &ipc.RestoreWallet{Label: label, Phrase: phrase}}, nil
}

// CheckKeyName checks the name of a security key: the wallet takes the same
// text as a label. The CLI and the view ask it before touching the key.
func CheckKeyName(name string) error {
	if n := len(name); n == 0 || n > ipc.MaxLabel || ipc.Detail(name) != name {
		return fmt.Errorf("a key's name is 1 to %d bytes of visible text", ipc.MaxLabel)
	}
	return nil
}

// AddKey registers a security key with what it said when it made its
// credential.
func AddKey(name string, authenticatorData []byte) (Action, error) {
	if err := CheckKeyName(name); err != nil {
		return Action{}, err
	}
	return Action{ipc.ActAddKey, &ipc.AddKey{Name: name, AuthenticatorData: authenticatorData}}, nil
}

// RemoveKey removes a registered key.
func RemoveKey(credentialID []byte) Action {
	return Action{ipc.ActRemoveKey, &ipc.KeyRef{CredentialID: credentialID}}
}

// StartRecovery starts a recovery without keys.
func StartRecovery() Action { return Action{ipc.ActStartRecovery, &ipc.Empty{}} }

// CancelRecovery cancels a recovery that is waiting.
func CancelRecovery() Action { return Action{ipc.ActCancelRecovery, &ipc.Empty{}} }

// checkLabel accepts the visible text the wallet accepts as a label.
func checkLabel(label string) error {
	if n := len(label); n == 0 || n > ipc.MaxLabel || ipc.Detail(label) != label {
		return fmt.Errorf("a label is 1 to %d bytes of visible text", ipc.MaxLabel)
	}
	return nil
}

// ParseADA reads an amount of ADA with up to six decimals, as 40 or 12.5, in
// lovelace.
func ParseADA(s string) (uint64, error) {
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" || len(frac) > 6 {
		return 0, model.ErrInvalidAmount
	}
	digits := strings.TrimLeft(whole+frac+strings.Repeat("0", 6-len(frac)), "0")
	if digits == "" {
		return 0, nil
	}
	return model.ParseAmount(digits)
}
