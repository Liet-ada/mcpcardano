// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package chain

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	gcbor "github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	"github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// ErrPhase1 reports a transaction that the Conway phase-1 rules reject.
var ErrPhase1 = errors.New("chain: phase-1 validation failed")

// SlotClock converts between slots and time on a network. After the Byron
// era every network uses one-second slots.
type SlotClock struct {
	ShelleySlot uint64 // first slot of the Shelley era
	ShelleyTime int64  // Unix time of that slot
}

// Clock returns the slot clock of a network, from its genesis files.
func Clock(n model.Network) SlotClock {
	switch n {
	case model.Mainnet:
		return SlotClock{ShelleySlot: 4_492_800, ShelleyTime: 1_596_059_091}
	case model.Preprod:
		return SlotClock{ShelleySlot: 86_400, ShelleyTime: 1_655_769_600}
	default: // preview has no Byron era
		return SlotClock{ShelleySlot: 0, ShelleyTime: 1_666_656_000}
	}
}

// Time returns the start of a Shelley-era slot.
func (c SlotClock) Time(slot uint64) time.Time {
	return time.Unix(c.ShelleyTime+int64(slot-c.ShelleySlot), 0).UTC()
}

// Slot returns the slot that contains t, which must be in the Shelley era.
func (c SlotClock) Slot(t time.Time) uint64 {
	return c.ShelleySlot + uint64(t.Unix()-c.ShelleyTime)
}

// Spent is an input of a transaction with the output it consumes, in CBOR.
type Spent struct {
	In     TxIn
	Output []byte
}

// ValidateDraft runs the Conway phase-1 rules on an unsigned draft (section
// 8.1, step 8). tx must carry placeholder witnesses of the real size, so the
// fee rule measures the signed size; the rules about signatures and witness
// keys are left out, since nobody has signed yet.
func ValidateDraft(n model.Network, p ProtocolParameters, slot uint64, tx []byte, spent []Spent) error {
	return validate(n, p, slot, tx, spent, map[common.UtxoValidationRuleId]bool{
		common.UtxoValidationRuleSignatures:              true,
		common.UtxoValidationRuleRequiredVKeyWitnesses:   true,
		common.UtxoValidationRuleCollateralVKeyWitnesses: true,
	})
}

// ValidateSigned runs every Conway phase-1 rule on a signed transaction.
func ValidateSigned(n model.Network, p ProtocolParameters, slot uint64, tx []byte, spent []Spent) error {
	return validate(n, p, slot, tx, spent, nil)
}

func validate(n model.Network, p ProtocolParameters, slot uint64, txBytes []byte, spent []Spent, skip map[common.UtxoValidationRuleId]bool) error {
	tx, err := conway.NewConwayTransactionFromCbor(txBytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPhase1, err)
	}
	state := &ledgerState{network: n, clock: Clock(n), utxos: make(map[TxIn]common.Utxo, len(spent))}
	for _, s := range spent {
		out, err := babbage.NewBabbageTransactionOutputFromCbor(s.Output)
		if err != nil {
			return fmt.Errorf("%w: spent output %s: %v", ErrPhase1, s.In, err)
		}
		state.utxos[s.In] = common.Utxo{
			Id:     shelley.ShelleyTransactionInput{TxId: common.Blake2b256(s.In.TxID), OutputIndex: s.In.Index},
			Output: out,
		}
	}
	var descriptors []common.UtxoValidationRuleDescriptor
	for _, d := range conway.UtxoValidationRuleDescriptors() {
		if !skip[d.Id] {
			descriptors = append(descriptors, d)
		}
	}
	rules, err := common.UtxoValidationRulesFromDescriptors(descriptors)
	if err != nil || len(rules) == 0 {
		return fmt.Errorf("%w: rule set: %v", ErrPhase1, err)
	}
	if err := common.VerifyTransaction(tx, slot, state, conwayParameters(p), rules); err != nil {
		return fmt.Errorf("%w: %v", ErrPhase1, err)
	}
	return nil
}

func rat(r Rational) *gcbor.Rat { return &gcbor.Rat{Rat: r.Rat()} }

// conwayParameters fills gouroboros's parameter type with the fields phase 1
// reads for transactions without scripts or governance.
func conwayParameters(p ProtocolParameters) *conway.ConwayProtocolParameters {
	return &conway.ConwayProtocolParameters{
		MinFeeA:                    uint(p.MinFeeA),
		MinFeeB:                    uint(p.MinFeeB),
		MaxTxSize:                  uint(p.MaxTxSize),
		KeyDeposit:                 uint(p.KeyDeposit),
		PoolDeposit:                uint(p.PoolDeposit),
		ProtocolVersion:            common.ProtocolParametersProtocolVersion{Major: uint(p.ProtocolMajor), Minor: uint(p.ProtocolMinor)},
		AdaPerUtxoByte:             p.CoinsPerUTxOByte,
		ExecutionCosts:             common.ExUnitPrice{MemPrice: rat(p.PriceMem), StepPrice: rat(p.PriceStep)},
		MaxTxExUnits:               common.ExUnits{Memory: int64(p.MaxTxExMem), Steps: int64(p.MaxTxExSteps)},
		MaxValueSize:               uint(p.MaxValueSize),
		CollateralPercentage:       uint(p.CollateralPercent),
		MaxCollateralInputs:        uint(p.MaxCollateralInputs),
		GovActionDeposit:           p.GovActionDeposit,
		DRepDeposit:                p.DRepDeposit,
		MinFeeRefScriptCostPerByte: rat(p.MinFeeRefScriptByte),
		A0:                         &gcbor.Rat{Rat: new(big.Rat)},
		Rho:                        &gcbor.Rat{Rat: new(big.Rat)},
		Tau:                        &gcbor.Rat{Rat: new(big.Rat)},
	}
}

// errNotKnown answers every ledger-state question a transaction without
// certificates, withdrawals or governance never asks.
var errNotKnown = errors.New("chain: not known to the draft validator")

// ledgerState is the slice of ledger state phase 1 needs for the MVP: the
// outputs being spent, the network and the slot clock. Everything else is
// empty.
type ledgerState struct {
	network model.Network
	clock   SlotClock
	utxos   map[TxIn]common.Utxo
}

var _ common.LedgerState = (*ledgerState)(nil)

func (s *ledgerState) UtxoById(in common.TransactionInput) (common.Utxo, error) {
	u, ok := s.utxos[TxIn{TxID: [32]byte(in.Id()), Index: in.Index()}]
	if !ok {
		return common.Utxo{}, fmt.Errorf("chain: input %s#%d is not being spent", in.Id(), in.Index())
	}
	return u, nil
}

func (s *ledgerState) NetworkId() uint { return uint(s.network.AddressID()) }

func (s *ledgerState) SlotToTime(slot uint64) (time.Time, error) { return s.clock.Time(slot), nil }

func (s *ledgerState) TimeToSlot(t time.Time) (uint64, error) { return s.clock.Slot(t), nil }

func (s *ledgerState) CostModels() map[common.PlutusLanguage]common.CostModel { return nil }

func (s *ledgerState) StakeRegistration([]byte) ([]common.StakeRegistrationCertificate, error) {
	return nil, nil
}

func (s *ledgerState) IsStakeCredentialRegistered(common.Credential) bool { return false }

func (s *ledgerState) PoolCurrentState(common.PoolKeyHash) (*common.PoolRegistrationCertificate, *uint64, error) {
	return nil, nil, nil
}

func (s *ledgerState) IsPoolRegistered(common.PoolKeyHash) bool { return false }

func (s *ledgerState) IsVrfKeyInUse(common.Blake2b256) (bool, common.PoolKeyHash, error) {
	return false, common.PoolKeyHash{}, nil
}

func (s *ledgerState) CalculateRewards(common.AdaPots, common.RewardSnapshot, common.RewardParameters) (*common.RewardCalculationResult, error) {
	return nil, errNotKnown
}

func (s *ledgerState) GetAdaPots() common.AdaPots { return common.AdaPots{} }

func (s *ledgerState) UpdateAdaPots(common.AdaPots) error { return errNotKnown }

func (s *ledgerState) GetRewardSnapshot(uint64) (common.RewardSnapshot, error) {
	return common.RewardSnapshot{}, errNotKnown
}

func (s *ledgerState) IsRewardAccountRegistered(common.Credential) bool { return false }

func (s *ledgerState) RewardAccountBalance(common.Credential) (*uint64, error) { return nil, nil }

func (s *ledgerState) CommitteeMember(common.Blake2b224) (*common.CommitteeMember, error) {
	return nil, nil
}

func (s *ledgerState) CommitteeMembers() ([]common.CommitteeMember, error) { return nil, nil }

func (s *ledgerState) DRepRegistration(common.Credential) (*common.DRepRegistration, error) {
	return nil, nil
}

func (s *ledgerState) DRepRegistrations() ([]common.DRepRegistration, error) { return nil, nil }

func (s *ledgerState) Constitution() (*common.Constitution, error) { return nil, nil }

func (s *ledgerState) TreasuryValue() (uint64, error) { return 0, nil }

func (s *ledgerState) GovActionById(common.GovActionId) (*common.GovActionState, error) {
	return nil, nil
}

func (s *ledgerState) GovActionExists(common.GovActionId) bool { return false }
