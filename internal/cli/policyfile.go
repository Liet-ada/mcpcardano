// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// policyFile is a policy with its mode as the person reads and writes it:
// the JSON of the policies in the server's config.json (section 7.5), plus
// the mode, session_required and structure of the wallets of modes B and C.
// Freezing is not in it: freeze and unfreeze change it. Amounts are
// lovelace as decimal strings; an empty one is zero, and zero forbids
// (decision 38).
type policyFile struct {
	Mode            string            `json:"mode"`
	SessionRequired bool              `json:"session_required"`
	Networks        []string          `json:"networks"`
	Limits          limitsFile        `json:"limits"`
	Destinations    destinationsFile  `json:"destinations"`
	Assets          map[string]string `json:"assets"`
	Structure       structureFile     `json:"structure"`
	UTxO            utxoFile          `json:"utxo"`
}

type limitsFile struct {
	PerTx                  string `json:"per_tx"`
	PerHour                string `json:"per_hour"`
	PerDay                 string `json:"per_day"`
	Budget                 string `json:"budget"`
	ApprovalThreshold      string `json:"approval_threshold"`
	MaxFee                 string `json:"max_fee"`
	TxPerHour              uint32 `json:"tx_per_hour"`
	NewDestinationsPerHour uint32 `json:"new_destinations_per_hour"`
	NewDestinationsPerDay  uint32 `json:"new_destinations_per_day"`
	MaxLiveDrafts          uint32 `json:"max_live_drafts"`
	MaxTTLSeconds          uint32 `json:"max_ttl_seconds"`
}

// destinationsFile is either any address or a list of bech32 addresses.
type destinationsFile struct {
	Any     bool     `json:"any"`
	Allowed []string `json:"allowed"`
}

type structureFile struct {
	Certificates      bool `json:"certificates"`
	Withdrawals       bool `json:"withdrawals"`
	Mint              bool `json:"mint"`
	InternalTransfers bool `json:"internal_transfers"`
}

type utxoFile struct {
	TargetADAOnly uint32 `json:"target_ada_only"`
	MinSplit      string `json:"min_split"`
	DustThreshold string `json:"dust_threshold"`
	MaxDustSweep  uint32 `json:"max_dust_sweep"`
}

// policyFromWire writes a policy with every field, for the person to edit.
func policyFromWire(mode string, p ipc.Policy) policyFile {
	f, l := model.FormatAmount, p.Limits
	out := policyFile{
		Mode: mode, SessionRequired: p.SessionRequired, Networks: append([]string{}, p.Networks...),
		Limits: limitsFile{
			PerTx: f(l.PerTx), PerHour: f(l.PerHour), PerDay: f(l.PerDay), Budget: f(l.Budget),
			ApprovalThreshold: f(l.ApprovalThreshold), MaxFee: f(l.MaxFee), TxPerHour: l.TxPerHour,
			NewDestinationsPerHour: l.NewDestinationsPerHour, NewDestinationsPerDay: l.NewDestinationsPerDay,
			MaxLiveDrafts: l.MaxLiveDrafts, MaxTTLSeconds: l.MaxTTLSeconds,
		},
		Destinations: destinationsFile{Any: p.Destinations.Any, Allowed: []string{}},
		Assets:       map[string]string{},
		Structure:    structureFile(p.Structure),
		UTxO: utxoFile{TargetADAOnly: p.UTxO.TargetADAOnly, MinSplit: f(p.UTxO.MinSplit),
			DustThreshold: f(p.UTxO.DustThreshold), MaxDustSweep: p.UTxO.MaxDustSweep},
	}
	for _, a := range p.Destinations.Allowed {
		out.Destinations.Allowed = append(out.Destinations.Allowed, model.Address{Raw: a}.Bech32())
	}
	for _, a := range p.Assets {
		id, _ := model.NewAssetID(a.Policy, a.Name)
		out.Assets[id.String()] = f(a.Cap)
	}
	return out
}

// readPolicyFile reads a policy file strictly: an unknown field or data
// after the policy is an error, as in config.json.
func readPolicyFile(path string) (policyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return policyFile{}, fmt.Errorf("cli: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f policyFile
	if err := dec.Decode(&f); err != nil {
		return policyFile{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return policyFile{}, fmt.Errorf("%s: data after the policy", path)
	}
	return f, nil
}

// wire checks the file against network n and converts it, with its lists in
// their wire order.
func (f policyFile) wire(n model.Network) (string, ipc.Policy, error) {
	fail := func(format string, args ...any) (string, ipc.Policy, error) {
		return "", ipc.Policy{}, fmt.Errorf(format, args...)
	}
	if f.Mode != string(model.ModeB) && f.Mode != string(model.ModeC) {
		return fail(`mode must be "B" or "C"; mode A wallets live in the server's config.json`)
	}
	p := ipc.Policy{
		SessionRequired: f.SessionRequired, Networks: []string{},
		Destinations: ipc.Destinations{Any: f.Destinations.Any, Allowed: [][]byte{}},
		Assets:       []ipc.AssetCap{}, Structure: ipc.Structure(f.Structure),
	}
	for _, x := range f.Networks {
		if !model.Network(x).Valid() {
			return fail("networks: %q", x)
		}
		p.Networks = append(p.Networks, x)
	}
	amounts := []struct {
		name, text string
		to         *uint64
	}{
		{"limits.per_tx", f.Limits.PerTx, &p.Limits.PerTx},
		{"limits.per_hour", f.Limits.PerHour, &p.Limits.PerHour},
		{"limits.per_day", f.Limits.PerDay, &p.Limits.PerDay},
		{"limits.budget", f.Limits.Budget, &p.Limits.Budget},
		{"limits.approval_threshold", f.Limits.ApprovalThreshold, &p.Limits.ApprovalThreshold},
		{"limits.max_fee", f.Limits.MaxFee, &p.Limits.MaxFee},
		{"utxo.min_split", f.UTxO.MinSplit, &p.UTxO.MinSplit},
		{"utxo.dust_threshold", f.UTxO.DustThreshold, &p.UTxO.DustThreshold},
	}
	for _, a := range amounts {
		if a.text == "" {
			continue
		}
		v, err := model.ParseAmount(a.text)
		if err != nil {
			return fail("%s: %w", a.name, err)
		}
		*a.to = v
	}
	l := f.Limits
	p.Limits.TxPerHour, p.Limits.NewDestinationsPerHour, p.Limits.NewDestinationsPerDay = l.TxPerHour, l.NewDestinationsPerHour, l.NewDestinationsPerDay
	p.Limits.MaxLiveDrafts, p.Limits.MaxTTLSeconds = l.MaxLiveDrafts, l.MaxTTLSeconds
	p.UTxO.TargetADAOnly, p.UTxO.MaxDustSweep = f.UTxO.TargetADAOnly, f.UTxO.MaxDustSweep
	for _, s := range f.Destinations.Allowed {
		a, err := model.ParseAddress(n, s)
		if err != nil {
			return fail("destinations: %q: %w", s, err)
		}
		p.Destinations.Allowed = append(p.Destinations.Allowed, a.Raw)
	}
	ids := make([]model.AssetID, 0, len(f.Assets))
	for k := range f.Assets {
		id, err := model.ParseAssetID(k)
		if err != nil {
			return fail("assets: %q: %w", k, err)
		}
		ids = append(ids, id)
	}
	slices.SortFunc(ids, model.AssetID.Compare)
	for _, id := range ids {
		q, err := model.ParseAmount(f.Assets[id.String()])
		if err != nil {
			return fail("assets: %s: %w", id, err)
		}
		p.Assets = append(p.Assets, ipc.AssetCap{Policy: id.Policy[:], Name: []byte(id.Name), Cap: q})
	}
	// A network or an address twice is the wallet's to refuse.
	slices.Sort(p.Networks)
	slices.SortFunc(p.Destinations.Allowed, bytes.Compare)
	return f.Mode, p, nil
}

// warnings are the values that forbid every payment (decision 38), as the
// server warns of them in its config.json.
func warnings(n model.Network, mode string, p ipc.Policy) []string {
	var out []string
	zero := func(v uint64, name string) {
		if v == 0 {
			out = append(out, name+" is zero, which forbids every payment")
		}
	}
	l := p.Limits
	zero(l.PerTx, "limits.per_tx")
	zero(l.PerHour, "limits.per_hour")
	zero(l.PerDay, "limits.per_day")
	zero(l.MaxFee, "limits.max_fee")
	zero(uint64(l.TxPerHour), "limits.tx_per_hour")
	zero(uint64(l.MaxLiveDrafts), "limits.max_live_drafts")
	zero(uint64(l.MaxTTLSeconds), "limits.max_ttl_seconds")
	if mode == string(model.ModeC) {
		zero(l.Budget, "limits.budget")
	}
	if !p.Destinations.Any && len(p.Destinations.Allowed) == 0 {
		out = append(out, "destinations allow nobody, which forbids every payment")
	}
	if !slices.Contains(p.Networks, string(n)) {
		out = append(out, fmt.Sprintf("networks does not include %s, which blocks the wallet", n))
	}
	return out
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
	text, err := json.MarshalIndent(policyFromWire(mode, p), "", "  ")
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
	mode, p, err := f.wire(n)
	if err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	p.Frozen = current.Frozen
	for _, w := range warnings(n, mode, p) {
		fmt.Fprintln(a.errOut, "warning:", w)
	}
	var h ipc.PolicyHash
	if o.template {
		err = a.authorize(ipc.ActSetTemplate, &ipc.Template{Mode: mode, Policy: p}, &h)
	} else {
		err = a.authorize(ipc.ActChangePolicy, &ipc.WalletPolicy{WalletID: o.wallet, Mode: mode, Policy: p}, &h)
	}
	if err != nil {
		return err
	}
	a.printf("Done. The audit log records it as %x.\n", h.Hash)
	return nil
}
