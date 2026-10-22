// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// txSummary is what the person reads before approving a transaction (paper,
// section 5.4). The wallet computes it from the bytes it signs, never from
// what the server says; the server's inputs are not even shown, since the
// spend does not depend on them.
func (d *Daemon) txSummary(r *record, a *approval) []string {
	wallet, _ := r.model(d.cfg.Network)
	v := a.tx.View(wallet.Address)
	lines := []string{fmt.Sprintf("Wallet %s (%s), mode %s", r.Label, r.ID, r.Mode)}
	for i, o := range v.Outputs {
		if o.Own {
			lines = append(lines, fmt.Sprintf("Output %d: %s back to the wallet", i, ada(o.Value.Lovelace)))
		} else {
			lines = append(lines, fmt.Sprintf("Output %d: %s to %s", i, ada(o.Value.Lovelace), o.Address.Bech32()))
		}
		lines = append(lines, tokenLines(o.Value.Assets)...)
	}
	lines = append(lines, "Fee: "+ada(v.Fee))
	if v.TTL != nil {
		lines = append(lines, fmt.Sprintf("Valid until slot %d, %s", *v.TTL, d.cfg.Network.Clock().Time(*v.TTL).Format(time.RFC3339)))
	}
	if len(v.Mint) > 0 {
		lines = append(lines, fmt.Sprintf("Mints or burns %d tokens", len(v.Mint)))
	}
	for _, w := range v.Withdrawals {
		lines = append(lines, fmt.Sprintf("Withdraws %s of rewards from %s", ada(w.Amount), model.Address{Raw: w.Account}.Bech32()))
	}
	for _, m := range a.tx.Message {
		// The message comes from the agent: quoted, with its invisible
		// characters escaped, so it cannot pass for the wallet's text.
		lines = append(lines, "Message: "+strings.Trim(fmt.Sprintf("%+q", m), `"`))
	}
	lines = append(lines, "Spend: "+ada(a.spend.Lovelace))
	lines = append(lines, tokenLines(a.spend.Assets)...)
	return lines
}

func tokenLines(assets map[model.AssetID]uint64) []string {
	ids := make([]model.AssetID, 0, len(assets))
	for a := range assets {
		ids = append(ids, a)
	}
	slices.SortFunc(ids, model.AssetID.Compare)
	var lines []string
	for _, a := range ids {
		lines = append(lines, fmt.Sprintf("  and %d of %s", assets[a], a))
	}
	return lines
}

// policyLines describes a policy with its mode, for the person to read
// before changing it.
func policyLines(mode string, p ipc.Policy) []string {
	l := p.Limits
	lines := []string{
		"Mode " + mode,
		fmt.Sprintf("Per transaction %s, per hour %s, per day %s, budget %s", ada(l.PerTx), ada(l.PerHour), ada(l.PerDay), ada(l.Budget)),
		fmt.Sprintf("Approval threshold %s, maximum fee %s, maximum TTL %v", ada(l.ApprovalThreshold), ada(l.MaxFee),
			time.Duration(l.MaxTTLSeconds)*time.Second),
		fmt.Sprintf("%d transactions per hour, %d new destinations per hour and %d per day, %d live drafts",
			l.TxPerHour, l.NewDestinationsPerHour, l.NewDestinationsPerDay, l.MaxLiveDrafts),
		fmt.Sprintf("Networks: %s; session required: %s; frozen: %s", strings.Join(p.Networks, ", "),
			yes(p.SessionRequired), yes(p.Frozen)),
		fmt.Sprintf("Certificates: %s; withdrawals: %s; mint: %s", yes(p.Structure.Certificates),
			yes(p.Structure.Withdrawals), yes(p.Structure.Mint)),
	}
	if p.Destinations.Any {
		lines = append(lines, "Destinations: any address, within the limits on new destinations")
	} else {
		lines = append(lines, fmt.Sprintf("Destinations: %d addresses", len(p.Destinations.Allowed)))
		for _, a := range p.Destinations.Allowed {
			lines = append(lines, "  "+model.Address{Raw: a}.Bech32())
		}
	}
	if len(p.Assets) == 0 {
		lines = append(lines, "Tokens that may leave: none")
	}
	for _, a := range p.Assets {
		id, _ := model.NewAssetID(a.Policy, a.Name)
		lines = append(lines, fmt.Sprintf("Token %s may leave, up to %d per transaction", id, a.Cap))
	}
	return lines
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ada writes lovelace as ADA with six decimals.
func ada(lovelace uint64) string {
	return fmt.Sprintf("%d.%06d ADA", lovelace/1_000_000, lovelace%1_000_000)
}

// fit makes a summary valid on the wire: each line visible text within
// ipc.MaxSummaryLine bytes, at most ipc.MaxSummaryLines lines.
func fit(lines []string) []string {
	out := make([]string, 0, min(len(lines), ipc.MaxSummaryLines))
	for i, l := range lines {
		if len(out) == ipc.MaxSummaryLines-1 && i < len(lines)-1 {
			out = append(out, fmt.Sprintf("... and %d more lines", len(lines)-i))
			break
		}
		if l = ipc.Detail(l); l == "" {
			l = "-"
		}
		out = append(out, l)
	}
	return out
}
