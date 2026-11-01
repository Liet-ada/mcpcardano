// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Liet-ada/mcpcardano/internal/actions"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// readPolicyFile reads a policy from a file, strictly.
func readPolicyFile(path string) (actions.PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return actions.PolicyFile{}, fmt.Errorf("cli: %w", err)
	}
	f, err := actions.ParsePolicy(data)
	if err != nil {
		return actions.PolicyFile{}, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// currentPolicy reads the policy of -wallet with its mode, or the template.
func (a *admin) currentPolicy(o *options) (string, ipc.Policy, error) {
	if o.template == (o.wallet != "") {
		return "", ipc.Policy{}, usageError("name either -wallet or -template")
	}
	if o.template {
		var t ipc.Template
		err := a.call(ipc.MsgShowTemplate, &ipc.Empty{}, &t)
		return t.Mode, t.Policy, err
	}
	if err := walletArg(o.wallet, true); err != nil {
		return "", ipc.Policy{}, err
	}
	var w ipc.WalletPolicy
	err := a.call(ipc.MsgShowPolicy, &ipc.WalletRef{WalletID: o.wallet}, &w)
	return w.Mode, w.Policy, err
}

func (a *admin) policyShow(o *options, _ []string) error {
	mode, p, err := a.currentPolicy(o)
	if err != nil {
		return err
	}
	text, err := json.MarshalIndent(actions.PolicyFromWire(mode, p), "", "  ")
	if err != nil {
		return err
	}
	a.printf("%s\n", text)
	return nil
}

// policySet changes the policy of a wallet, with its mode (decision 41), or
// the template, from a file in the format of policy show. The wallet stays
// frozen or not as it is.
func (a *admin) policySet(o *options, args []string) error {
	_, current, err := a.currentPolicy(o)
	if err != nil {
		return err
	}
	f, err := readPolicyFile(args[0])
	if err != nil {
		return err
	}
	n := model.Network(a.network)
	mode, p, err := f.Wire(n)
	if err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	p.Frozen = current.Frozen
	for _, w := range actions.Warnings(n, mode, p) {
		fmt.Fprintln(a.errOut, "warning:", w)
	}
	act := actions.ChangePolicy(o.wallet, mode, p)
	if o.template {
		act = actions.SetTemplate(mode, p)
	}
	var h ipc.PolicyHash
	if err := a.authorize(act.Name, act.Params, &h); err != nil {
		return err
	}
	a.printf("Done. The audit log records it as %x.\n", h.Hash)
	a.suggestKey()
	return nil
}
