// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package chain

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

// TxIn references a transaction output.
type TxIn struct {
	TxID  [32]byte
	Index uint32
}

// String returns the form txid#index.
func (in TxIn) String() string {
	return hex.EncodeToString(in.TxID[:]) + "#" + strconv.FormatUint(uint64(in.Index), 10)
}

// Compare orders by transaction id and then by index, the tie-break of input
// selection (section 8.2).
func (in TxIn) Compare(o TxIn) int {
	if c := bytes.Compare(in.TxID[:], o.TxID[:]); c != 0 {
		return c
	}
	return cmp.Compare(in.Index, o.Index)
}

// UTxO is an unspent output as the server sees it.
type UTxO struct {
	In        TxIn
	Address   model.Address
	Value     model.Value
	HasDatum  bool // datum hash or inline datum
	HasScript bool // reference script
}

// Rational is an exact non-negative fraction, used for the protocol
// parameters that are not integers. It is always reduced and Den > 0.
type Rational struct {
	Num, Den uint64
}

// ErrInvalidRational reports a value that is not a non-negative fraction
// within uint64.
var ErrInvalidRational = errors.New("chain: invalid rational")

// ParseDecimal reads a decimal such as "0.0577" or "7.21e-05" exactly, without
// going through floating point. The text comes from a data source, so its
// shape is checked first: big.Rat would otherwise expand an exponent such as
// "1e999999999" into a huge number.
func ParseDecimal(s string) (Rational, error) {
	if !plainDecimal(s) {
		return Rational{}, fmt.Errorf("%w: %q", ErrInvalidRational, s)
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Sign() < 0 {
		return Rational{}, fmt.Errorf("%w: %q", ErrInvalidRational, s)
	}
	if !r.Num().IsUint64() || !r.Denom().IsUint64() {
		return Rational{}, fmt.Errorf("%w: %q is out of range", ErrInvalidRational, s)
	}
	return Rational{Num: r.Num().Uint64(), Den: r.Denom().Uint64()}, nil
}

// plainDecimal accepts digits, an optional fraction and an optional exponent
// of at most two digits, in at most 40 characters.
func plainDecimal(s string) bool {
	if len(s) == 0 || len(s) > 40 {
		return false
	}
	i, digits := 0, 0
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		digits++
	}
	if i < len(s) && s[i] == '.' {
		for i++; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
			digits++
		}
	}
	if digits == 0 {
		return false
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		exp := 0
		for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
			exp++
		}
		if exp == 0 || exp > 2 {
			return false
		}
	}
	return i == len(s)
}

// Rat returns r as a big.Rat for exact arithmetic.
func (r Rational) Rat() *big.Rat {
	return new(big.Rat).SetFrac(new(big.Int).SetUint64(r.Num), new(big.Int).SetUint64(r.Den))
}

// ProtocolParameters are the Conway parameters the server needs to build and
// check transactions (section 4.2, get_protocol_parameters).
type ProtocolParameters struct {
	Epoch uint64

	MinFeeA          uint64 // lovelace per byte
	MinFeeB          uint64 // lovelace
	MaxTxSize        uint32 // bytes
	MaxValueSize     uint32 // bytes
	CoinsPerUTxOByte uint64

	KeyDeposit       uint64
	PoolDeposit      uint64
	DRepDeposit      uint64
	GovActionDeposit uint64

	PriceMem            Rational
	PriceStep           Rational
	MaxTxExMem          uint64
	MaxTxExSteps        uint64
	CollateralPercent   uint32
	MaxCollateralInputs uint32
	MinFeeRefScriptByte Rational // lovelace per byte of reference scripts

	ProtocolMajor uint32
	ProtocolMinor uint32
}

// ErrImplausibleParameters reports parameters that cannot be right for
// Conway. A data source is only semi-trusted (paper, section 6.5), so the
// server checks them before building with them.
var ErrImplausibleParameters = errors.New("chain: implausible protocol parameters")

// Validate checks bounds that every Conway network has met. They catch a
// broken or lying source, not every wrong value: a wrong fee only makes the
// node reject the transaction.
func (p ProtocolParameters) Validate() error {
	var problems []string
	check := func(ok bool, what string) {
		if !ok {
			problems = append(problems, what)
		}
	}
	check(p.ProtocolMajor >= 9, "protocol version before Conway")
	check(p.MinFeeA > 0 && p.MinFeeA <= 10_000, "min_fee_a")
	check(p.MinFeeB > 0 && p.MinFeeB <= 10_000_000, "min_fee_b")
	check(p.MaxTxSize >= 4096 && p.MaxTxSize <= 65_536, "max_tx_size")
	check(p.MaxValueSize >= 1000 && p.MaxValueSize <= 65_536, "max_val_size")
	check(p.CoinsPerUTxOByte > 0 && p.CoinsPerUTxOByte <= 100_000, "coins_per_utxo_size")
	check(p.PriceMem.Den > 0 && p.PriceStep.Den > 0 && p.MinFeeRefScriptByte.Den > 0, "prices")
	check(p.CollateralPercent >= 100, "collateral_percent")
	check(p.MaxCollateralInputs > 0, "max_collateral_inputs")
	if len(problems) > 0 {
		return fmt.Errorf("%w: %v", ErrImplausibleParameters, problems)
	}
	return nil
}
