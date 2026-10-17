// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package model

// Policy is the per-wallet policy of section 3.6. Whatever it does not allow
// expressly is forbidden, so zero values forbid: a zero limit allows nothing
// and an empty list allows nobody.
//
// The mode is not here but in Wallet, so there is a single source for it;
// a Template carries the mode next to its policy.
type Policy struct {
	Frozen          bool
	SessionRequired bool
	Networks        []Network // networks the wallet may use

	Limits       Limits
	Destinations Destinations
	Assets       map[AssetID]uint64 // tokens that may leave, with a cap in units per transaction
	Structure    Structure
	UTxO         UTxOPolicy
}

// Limits are amounts in lovelace and counts. Only lovelace counts towards
// limits and budgets; tokens are capped by Policy.Assets.
type Limits struct {
	PerTx             uint64
	PerHour           uint64
	PerDay            uint64
	Budget            uint64 // total, mode C
	ApprovalThreshold uint64 // mode B
	MaxFee            uint64

	TxPerHour              uint32
	NewDestinationsPerHour uint32
	NewDestinationsPerDay  uint32
	MaxLiveDrafts          uint32
	MaxTTLSeconds          uint32
}

// Destinations is either any address or a fixed list.
type Destinations struct {
	Any     bool
	Allowed []Address
}

// Permits reports whether a may receive funds.
func (d Destinations) Permits(a Address) bool {
	if d.Any {
		return true
	}
	for _, x := range d.Allowed {
		if x.Equal(a) {
			return true
		}
	}
	return false
}

// Structure lists the transaction features a wallet may use beyond plain
// outputs.
type Structure struct {
	Certificates      bool
	Withdrawals       bool
	Mint              bool
	InternalTransfers bool // payments between the person's own wallets
}

// UTxOPolicy steers change and input selection (sections 8.2 and 8.3).
type UTxOPolicy struct {
	TargetADAOnly uint32 // target number of ADA-only UTxOs
	MinSplit      uint64 // smallest piece when splitting change
	DustThreshold uint64 // ADA-only UTxOs below this are dust
	MaxDustSweep  uint32 // dust inputs added per transaction
}

// Template is a policy plus a mode, applied to the wallets the agent creates
// (section 3.7).
type Template struct {
	Mode   Mode
	Policy Policy
}
