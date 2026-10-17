// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package txdecode

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// ErrIntentMismatch reports a built transaction that does not do what its
// intent asked. It is a builder bug: the agent gets INTERNAL and the audit
// log the detail (section 8.6).
var ErrIntentMismatch = errors.New("txdecode: transaction does not match the intent")

// cip20Label is the metadata label of transaction messages (CIP-20).
const cip20Label = 674

// CheckIntent checks a transaction the server built for wallet against the
// intent it was built for (section 8.6):
//
//   - a payment holds every requested output, with the same address and
//     value, and every other output is own;
//   - a consolidation holds only own outputs;
//   - the metadata is the requested CIP-20 message, or none;
//   - the body has nothing an MVP intent does not ask for: no certificates,
//     withdrawals, mint, governance, donation, scripts, datums or collateral.
//
// A requested output without lovelace must hold the ledger's minimum for its
// own size, which is what the builder gives it (section 8.1, step 2).
func (t *Tx) CheckIntent(wallet model.Address, intent model.Intent, coinsPerUTxOByte uint64) error {
	if err := intent.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrIntentMismatch, err)
	}
	v := t.View(wallet)
	if err := plain(v); err != nil {
		return err
	}
	matched := make([]bool, len(v.Outputs))
	var msg string
	if intent.Kind == model.IntentPayment {
		msg = intent.Payment.Message
		for i, want := range intent.Payment.Outputs {
			j := t.find(v.Outputs, matched, want, coinsPerUTxOByte)
			if j < 0 {
				return fmt.Errorf("%w: requested output %d is missing", ErrIntentMismatch, i)
			}
			matched[j] = true
		}
	}
	for j, o := range v.Outputs {
		if !matched[j] && !o.Own {
			return fmt.Errorf("%w: output %d pays an address the intent does not name", ErrIntentMismatch, j)
		}
	}
	return t.checkMessage(msg)
}

// find returns the first output not yet matched that pays want, or -1.
func (t *Tx) find(outs []model.Output, matched []bool, want model.PaymentOutput, coinsPerUTxOByte uint64) int {
	for j, o := range outs {
		if matched[j] || !o.Address.Equal(want.Address) || !sameAssets(o.Value.Assets, want.Value.Assets) {
			continue
		}
		lovelace := want.Value.Lovelace
		if lovelace == 0 {
			lovelace = (160 + uint64(t.d.OutputSizes[j])) * coinsPerUTxOByte
		}
		if o.Value.Lovelace == lovelace {
			return j
		}
	}
	return -1
}

func sameAssets(a, b map[model.AssetID]uint64) bool {
	nonZero := func(m map[model.AssetID]uint64) map[model.AssetID]uint64 {
		out := map[model.AssetID]uint64{}
		for id, q := range m {
			if q != 0 {
				out[id] = q
			}
		}
		return out
	}
	return maps.Equal(nonZero(a), nonZero(b))
}

// plain rejects every body field beyond inputs, outputs, fee, validity and
// the metadata hash.
func plain(v model.TxView) error {
	var extra []string
	add := func(present bool, what string) {
		if present {
			extra = append(extra, what)
		}
	}
	add(len(v.Certificates) > 0, "certificates")
	add(len(v.Withdrawals) > 0, "withdrawals")
	add(len(v.Mint) > 0, "mint")
	add(v.Votes > 0 || v.Proposals > 0, "governance")
	add(v.Donation > 0, "donation")
	add(v.ScriptDataHash || v.ReferenceInputs > 0 || len(v.RequiredSigners) > 0, "scripts or required signers")
	add(v.Collateral > 0 || v.CollateralReturn || v.TotalCollateral != nil, "collateral")
	for _, o := range v.Outputs {
		add(o.HasDatum || o.HasScript, "an output with a datum or a script")
	}
	if len(extra) > 0 {
		return fmt.Errorf("%w: the body has %s", ErrIntentMismatch, strings.Join(slices.Compact(extra), ", "))
	}
	return nil
}

// checkMessage requires the metadata to be exactly the requested message:
// label 674 alone, whose strings joined give it back, or no metadata at all.
func (t *Tx) checkMessage(want string) error {
	labels := t.d.MetadataLabels
	if want == "" {
		if len(labels) > 0 {
			return fmt.Errorf("%w: metadata the intent does not ask for", ErrIntentMismatch)
		}
		return nil
	}
	if !slices.Equal(labels, []uint64{cip20Label}) || t.d.Message == nil || strings.Join(t.d.Message, "") != want {
		return fmt.Errorf("%w: the message is not the requested one", ErrIntentMismatch)
	}
	return nil
}
