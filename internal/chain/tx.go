// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package chain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// ErrInvalidTransaction reports bytes that are not a Conway transaction.
var ErrInvalidTransaction = errors.New("chain: invalid transaction")

// cip20Label is the metadata label of transaction messages (CIP-20).
const cip20Label = 674

// DecodedTx is a transaction decoded by gouroboros into the project's types.
// Nothing in it has been checked against a wallet or a policy.
type DecodedTx struct {
	ID     [32]byte
	Inputs []TxIn
	// View is the transaction as policy sees it (section 3.5). No output is
	// marked as own: only the caller knows the wallet.
	View model.TxView
	// OutputSizes holds the encoded size of each output, in body order; the
	// minimum ADA of an output follows from it.
	OutputSizes []int
	// Accounts holds the text form of each reward account in
	// View.Withdrawals, in the same order.
	Accounts []string
	// MetadataLabels are the labels of the metadata, in ascending order.
	MetadataLabels []uint64
	// Message holds the strings of a CIP-20 message, as found on the chain.
	// It is nil when label 674 is absent or does not follow CIP-20.
	Message []string
	// Metadata is the whole metadata as a JSON-like tree, nil if there is
	// none, as cardano-db-sync renders it but for integers, which are decimal
	// strings: maps by label, bytes as 0x and hex, also as keys. A map with a
	// list or a map as a key becomes a list of entries {k, v}.
	Metadata map[string]any
}

// DecodeTransaction decodes a Conway transaction. The caller bounds its size
// first, which bounds the decoding time (decision 39).
func DecodeTransaction(raw []byte) (*DecodedTx, error) {
	tx, err := conway.NewConwayTransactionFromCbor(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTransaction, err)
	}
	b := &tx.Body
	d := &DecodedTx{ID: [32]byte(tx.Id())}
	for _, in := range tx.Inputs() {
		d.Inputs = append(d.Inputs, TxIn{TxID: [32]byte(in.Id()), Index: in.Index()})
	}

	v := &d.View
	v.NetworkID = b.TxNetworkId
	v.Fee = b.TxFee
	if b.Ttl != 0 {
		v.TTL = &b.Ttl
	}
	if b.TxValidityIntervalStart != 0 {
		v.ValidityStart = &b.TxValidityIntervalStart
	}
	for i := range b.TxOutputs {
		o := &b.TxOutputs[i]
		out, err := output(o)
		if err != nil {
			return nil, fmt.Errorf("%w: output %d: %v", ErrInvalidTransaction, i, err)
		}
		v.Outputs = append(v.Outputs, out)
		d.OutputSizes = append(d.OutputSizes, len(o.Cbor()))
	}
	for _, c := range tx.Certificates() {
		v.Certificates = append(v.Certificates, model.Certificate{Kind: certificateKind(c.Type())})
	}
	if err := d.withdrawals(b.TxWithdrawals); err != nil {
		return nil, err
	}
	if v.Mint, err = mint(b.TxMint); err != nil {
		return nil, err
	}
	v.Collateral = len(tx.Collateral())
	v.CollateralReturn = b.TxCollateralReturn != nil
	if b.TxTotalCollateral != 0 {
		v.TotalCollateral = &b.TxTotalCollateral
	}
	for _, h := range tx.RequiredSigners() {
		v.RequiredSigners = append(v.RequiredSigners, [28]byte(h))
	}
	v.ReferenceInputs = len(tx.ReferenceInputs())
	v.ScriptDataHash = b.TxScriptDataHash != nil
	for _, votes := range b.TxVotingProcedures {
		v.Votes += len(votes)
	}
	v.Proposals = len(b.TxProposalProcedures)
	v.Donation = b.TxDonation

	if md := tx.Metadata(); md != nil {
		d.MetadataLabels, d.Message = metadata(md)
		if top, ok := metadatumJSON(md).(map[string]any); ok {
			d.Metadata = top
		}
	}
	return d, nil
}

// output converts an output. Byron addresses are kept, with header type 8 and
// no credentials, so a summary can show where every lovelace goes.
func output(o common.TransactionOutput) (model.Output, error) {
	addr, err := outputAddress(o.Address())
	if err != nil {
		return model.Output{}, err
	}
	amount := o.Amount()
	if !amount.IsUint64() {
		return model.Output{}, errors.New("lovelace out of range")
	}
	out := model.Output{
		Address:   addr,
		Value:     model.Value{Lovelace: amount.Uint64()},
		HasDatum:  o.DatumHash() != nil || o.Datum() != nil,
		HasScript: o.ScriptRef() != nil,
	}
	if ma := o.Assets(); ma != nil {
		for _, p := range ma.Policies() {
			for _, name := range ma.Assets(p) {
				q := ma.Asset(p, name)
				if q == nil || !q.IsUint64() {
					return model.Output{}, errors.New("token quantity out of range")
				}
				if q.Sign() == 0 {
					continue
				}
				id, err := model.NewAssetID(p[:], name)
				if err != nil {
					return model.Output{}, err
				}
				if out.Value.Assets == nil {
					out.Value.Assets = make(map[model.AssetID]uint64)
				}
				out.Value.Assets[id] = q.Uint64()
			}
		}
	}
	return out, nil
}

func outputAddress(a common.Address) (model.Address, error) {
	if a.Type() != common.AddressTypeByron {
		return fromLedger(a)
	}
	raw, err := a.Bytes()
	if err != nil {
		return model.Address{}, err
	}
	return model.Address{Raw: raw, Type: common.AddressTypeByron, NetworkID: uint8(a.NetworkId())}, nil
}

// AddressText returns the text form of an output address: bech32 for Shelley
// addresses, base58 for Byron ones.
func AddressText(m model.Address) (string, error) {
	a, err := common.NewAddressFromBytes(m.Raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	return a.String(), nil
}

// withdrawals converts the withdrawal map, ordered by reward account so the
// same transaction always gives the same view.
func (d *DecodedTx) withdrawals(m map[*common.Address]uint64) error {
	type w struct {
		raw    []byte
		text   string
		amount uint64
	}
	var ws []w
	for a, amount := range m {
		raw, err := a.Bytes()
		if err != nil {
			return fmt.Errorf("%w: withdrawal: %v", ErrInvalidTransaction, err)
		}
		ws = append(ws, w{raw, a.String(), amount})
	}
	slices.SortFunc(ws, func(x, y w) int { return bytes.Compare(x.raw, y.raw) })
	for _, x := range ws {
		d.View.Withdrawals = append(d.View.Withdrawals, model.Withdrawal{Account: x.raw, Amount: x.amount})
		d.Accounts = append(d.Accounts, x.text)
	}
	return nil
}

func mint(ma *common.MultiAsset[common.MultiAssetTypeMint]) (map[model.AssetID]int64, error) {
	if ma == nil {
		return nil, nil
	}
	var m map[model.AssetID]int64
	for _, p := range ma.Policies() {
		for _, name := range ma.Assets(p) {
			q := ma.Asset(p, name)
			if q == nil || !q.IsInt64() {
				return nil, fmt.Errorf("%w: mint quantity out of range", ErrInvalidTransaction)
			}
			if q.Sign() == 0 {
				continue
			}
			id, err := model.NewAssetID(p[:], name)
			if err != nil {
				return nil, fmt.Errorf("%w: mint: %v", ErrInvalidTransaction, err)
			}
			if m == nil {
				m = make(map[model.AssetID]int64)
			}
			m[id] = q.Int64()
		}
	}
	return m, nil
}

// certificateKinds are the names of the certificates in the Conway CDDL. They
// are stable: they reach the agent and the audit log.
var certificateKinds = [...]string{
	common.CertificateTypeStakeRegistration:               "stake_registration",
	common.CertificateTypeStakeDeregistration:             "stake_deregistration",
	common.CertificateTypeStakeDelegation:                 "stake_delegation",
	common.CertificateTypePoolRegistration:                "pool_registration",
	common.CertificateTypePoolRetirement:                  "pool_retirement",
	common.CertificateTypeGenesisKeyDelegation:            "genesis_key_delegation",
	common.CertificateTypeMoveInstantaneousRewards:        "move_instantaneous_rewards_cert",
	common.CertificateTypeRegistration:                    "reg_cert",
	common.CertificateTypeDeregistration:                  "unreg_cert",
	common.CertificateTypeVoteDelegation:                  "vote_deleg_cert",
	common.CertificateTypeStakeVoteDelegation:             "stake_vote_deleg_cert",
	common.CertificateTypeStakeRegistrationDelegation:     "stake_reg_deleg_cert",
	common.CertificateTypeVoteRegistrationDelegation:      "vote_reg_deleg_cert",
	common.CertificateTypeStakeVoteRegistrationDelegation: "stake_vote_reg_deleg_cert",
	common.CertificateTypeAuthCommitteeHot:                "auth_committee_hot_cert",
	common.CertificateTypeResignCommitteeCold:             "resign_committee_cold_cert",
	common.CertificateTypeRegistrationDrep:                "reg_drep_cert",
	common.CertificateTypeDeregistrationDrep:              "unreg_drep_cert",
	common.CertificateTypeUpdateDrep:                      "update_drep_cert",
}

func certificateKind(t uint) string {
	if t < uint(len(certificateKinds)) {
		return certificateKinds[t]
	}
	return fmt.Sprintf("unknown_%d", t)
}

// metadata returns the labels of the metadata and the strings of a CIP-20
// message: label 674 holding a map whose key "msg" is a list of strings.
func metadata(md common.TransactionMetadatum) ([]uint64, []string) {
	top, ok := md.(common.MetaMap)
	if !ok {
		return nil, nil
	}
	var labels []uint64
	var msg []string
	for _, p := range top.Pairs {
		k, ok := p.Key.(common.MetaInt)
		if !ok || k.Value == nil || !k.Value.IsUint64() {
			continue
		}
		label := k.Value.Uint64()
		labels = append(labels, label)
		if label == cip20Label {
			msg = cip20Message(p.Value)
		}
	}
	slices.Sort(labels)
	return labels, msg
}

func cip20Message(v common.TransactionMetadatum) []string {
	m, ok := v.(common.MetaMap)
	if !ok {
		return nil
	}
	for _, p := range m.Pairs {
		if k, ok := p.Key.(common.MetaText); !ok || k.Value != "msg" {
			continue
		}
		list, ok := p.Value.(common.MetaList)
		if !ok {
			return nil
		}
		lines := make([]string, 0, len(list.Items))
		for _, item := range list.Items {
			t, ok := item.(common.MetaText)
			if !ok {
				return nil
			}
			lines = append(lines, t.Value)
		}
		return lines
	}
	return nil
}

// Fingerprint returns the CIP-14 fingerprint of an asset (asset1...).
func Fingerprint(a model.AssetID) string {
	return common.NewAssetFingerprint(a.Policy[:], []byte(a.Name)).String()
}

// metadatumJSON turns metadata into a JSON-like tree.
func metadatumJSON(m common.TransactionMetadatum) any {
	switch m := m.(type) {
	case common.MetaInt:
		if m.Value == nil {
			return nil
		}
		return m.Value.String()
	case common.MetaBytes:
		return "0x" + hex.EncodeToString(m.Value)
	case common.MetaText:
		return m.Value
	case common.MetaList:
		out := make([]any, 0, len(m.Items))
		for _, x := range m.Items {
			out = append(out, metadatumJSON(x))
		}
		return out
	case common.MetaMap:
		obj := make(map[string]any, len(m.Pairs))
		for _, p := range m.Pairs {
			var key string
			switch k := p.Key.(type) {
			case common.MetaText:
				key = k.Value
			case common.MetaInt:
				if k.Value == nil {
					return pairs(m)
				}
				key = k.Value.String()
			case common.MetaBytes:
				key = "0x" + hex.EncodeToString(k.Value)
			default:
				return pairs(m)
			}
			if _, dup := obj[key]; dup {
				return pairs(m)
			}
			obj[key] = metadatumJSON(p.Value)
		}
		return obj
	}
	return nil
}

// pairs keeps a map with a list or a map as a key as a list of entries.
func pairs(m common.MetaMap) []any {
	out := make([]any, 0, len(m.Pairs))
	for _, p := range m.Pairs {
		out = append(out, map[string]any{"k": metadatumJSON(p.Key), "v": metadatumJSON(p.Value)})
	}
	return out
}

// StakeAddress returns the reward address, in bech32, of a stake credential.
func StakeAddress(n model.Network, c model.Credential) (string, error) {
	header := byte(0xe0) // key hash
	if c.Kind == model.ScriptHash {
		header = 0xf0
	}
	a, err := common.NewAddressFromBytes(append([]byte{header | n.AddressID()}, c.Hash[:]...))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	return a.String(), nil
}
