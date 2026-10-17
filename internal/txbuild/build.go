// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package txbuild builds the transactions of the MVP, payments and
// consolidations, following section 8.1 of the specification: input
// selection with MACS and a dust sweep, change by policy and target number
// of UTxOs, a fee found by fixed point, canonical CBOR (CIP-21) and the
// Conway phase-1 rules. It has no network, clock or state: the server passes
// in everything it needs.
package txbuild

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/txdecode"
)

var (
	// ErrInsufficientFunds reports that the free UTxOs cannot pay the
	// outputs, the fee and the change.
	ErrInsufficientFunds = errors.New("txbuild: insufficient funds")
	// ErrNoFreeUTxOs reports a wallet whose UTxOs are all reserved.
	ErrNoFreeUTxOs = errors.New("txbuild: no free UTxOs")
	// ErrInvalidOutput reports a requested output the ledger would reject,
	// such as one below the minimum ADA; the agent must change it.
	ErrInvalidOutput = errors.New("txbuild: invalid output")
	// ErrTooLarge reports a transaction above the maximum size.
	ErrTooLarge = errors.New("txbuild: transaction too large")
	// ErrInternal reports a builder bug, such as a draft the phase-1 rules
	// reject. The agent never receives such a draft (section 8.1, step 8).
	ErrInternal = errors.New("txbuild: internal error")
)

// BelowMinimumError reports an output with less lovelace than the ledger's
// minimum, with the minimum for the hint (section 8.1, step 2).
type BelowMinimumError struct {
	Index   int
	Minimum uint64
}

func (e *BelowMinimumError) Error() string {
	return fmt.Sprintf("txbuild: output %d needs at least %d lovelace", e.Index, e.Minimum)
}

func (e *BelowMinimumError) Unwrap() error { return ErrInvalidOutput }

// DefaultMinChange is Apollo's MinChange: MACS avoids inputs that would leave
// less than this as change, which could not become an output of its own.
const DefaultMinChange = 1_500_000

// Input is everything a build needs.
type Input struct {
	Network model.Network
	Wallet  model.Address // receives the change; every input belongs to it
	Intent  model.Intent

	// Available are the wallet's UTxOs that no draft holds and that are not
	// being spent (section 8.1, step 1).
	Available []chain.UTxO
	// ReservedADAOnly counts the wallet's ADA-only UTxOs held by other
	// drafts, which still count towards the target number of UTxOs.
	ReservedADAOnly int

	Params chain.ProtocolParameters
	UTxO   model.UTxOPolicy
	MaxFee uint64 // a leftover too small for change goes to the fee only within this

	TipSlot    uint64
	TTLSeconds uint32

	// Verified tells which tokens the person knows; inputs with other tokens
	// are used only when the payment needs them (section 8.2, step 6).
	Verified func(model.AssetID) bool
	// MinChange steers MACS away from change in the dead band; zero means
	// DefaultMinChange.
	MinChange uint64
}

// Tx is a built, unsigned transaction.
type Tx struct {
	ID      [32]byte
	Body    []byte
	AuxData []byte // nil without a message
	Inputs  []chain.UTxO
	Outputs []model.Output // in body order; Own marks the wallet's
	Fee     uint64
	TTL     uint64
	// Size is the ledger's size of the signed transaction the fee was
	// computed for: its length without the is_valid byte, which the ledger
	// leaves out when it measures a transaction for fees and for the maximum
	// size.
	Size int
	// Decoded is the unsigned transaction as read back from its bytes. The
	// draft takes its view and its summary from here, never from what the
	// builder meant to write.
	Decoded *txdecode.Tx
}

// Unsigned returns the transaction with an empty witness set, as hardware
// wallets take it.
func (t *Tx) Unsigned() ([]byte, error) {
	c := newCodec()
	empty, err := c.Marshal(map[uint64]any{})
	if err != nil {
		return nil, err
	}
	return assemble(c, t.Body, empty, t.AuxData)
}

// builder carries what every step of one build shares.
type builder struct {
	in      Input
	c       *cborx.Codec
	aux     []byte
	auxHash []byte
	pay     []model.Output // the requested outputs, with their minimum ADA
	payout  model.Value    // their sum
	wits    []byte
}

// Build builds the transaction of in.Intent.
func Build(in Input) (*Tx, error) {
	b := &builder{in: in, c: newCodec()}
	if err := b.check(); err != nil {
		return nil, err
	}
	var err error
	if b.aux, err = auxDataCBOR(b.c, message(in.Intent)); err != nil {
		return nil, err
	}
	if b.aux != nil {
		h := blake2b256(b.aux)
		b.auxHash = h[:]
	}
	if b.wits, err = placeholderWitnesses(b.c, 1); err != nil {
		return nil, err
	}
	var tx *Tx
	switch in.Intent.Kind {
	case model.IntentPayment:
		if err := b.requestedOutputs(); err != nil {
			return nil, err
		}
		tx, err = b.payment()
	case model.IntentConsolidation:
		tx, err = b.consolidation()
	default:
		err = fmt.Errorf("%w: unknown intent %q", ErrInvalidOutput, in.Intent.Kind)
	}
	if err != nil {
		return nil, err
	}
	if err := b.validate(tx); err != nil {
		return nil, err
	}
	if err := b.checkIntent(tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func (b *builder) check() error {
	in := b.in
	if err := in.Intent.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidOutput, err)
	}
	if err := in.Params.Validate(); err != nil {
		return err
	}
	if !in.Network.Valid() || in.Wallet.NetworkID != in.Network.AddressID() {
		return fmt.Errorf("%w: the wallet address is not on %s", ErrInternal, in.Network)
	}
	if in.Wallet.Payment.Kind != model.KeyHash {
		return fmt.Errorf("%w: the MVP only spends from key addresses", ErrInternal)
	}
	if in.TTLSeconds == 0 {
		return fmt.Errorf("%w: no TTL", ErrInternal)
	}
	for _, u := range in.Available {
		if !u.Address.Equal(in.Wallet) {
			return fmt.Errorf("%w: input %s is not at the wallet address", ErrInternal, u.In)
		}
	}
	return nil
}

// message returns the CIP-20 message of a payment, if any.
func message(i model.Intent) string {
	if i.Payment == nil {
		return ""
	}
	return i.Payment.Message
}

// requestedOutputs checks the requested outputs and gives a tokens-only
// output its minimum ADA, which counts as spend (section 8.1, step 2).
func (b *builder) requestedOutputs() error {
	p := b.in.Params
	for i, o := range b.in.Intent.Payment.Outputs {
		if o.Address.NetworkID != b.in.Network.AddressID() {
			return fmt.Errorf("%w: output %d is not on %s", ErrInvalidOutput, i, b.in.Network)
		}
		need, err := minADA(b.c, o.Address, o.Value.Assets, p.CoinsPerUTxOByte)
		if err != nil {
			return err
		}
		v := cloneValue(o.Value)
		switch {
		case v.Lovelace == 0:
			v.Lovelace = need
		case v.Lovelace < need:
			return &BelowMinimumError{Index: i, Minimum: need}
		}
		if size, err := valueSize(b.c, v); err != nil || size > int(p.MaxValueSize) {
			return fmt.Errorf("%w: output %d carries too many tokens", ErrInvalidOutput, i)
		}
		b.pay = append(b.pay, model.Output{Address: o.Address, Value: v, Own: o.Address.Equal(b.in.Wallet)})
		if b.payout, err = b.payout.Add(v); err != nil {
			return fmt.Errorf("%w: outputs overflow", ErrInvalidOutput)
		}
	}
	return nil
}

// spendable are the UTxOs a build may use. A UTxO with a reference script
// would raise the fee by the script's size, so the MVP leaves it alone.
func (b *builder) spendable() []chain.UTxO {
	var out []chain.UTxO
	for _, u := range b.in.Available {
		if !u.HasScript {
			out = append(out, u)
		}
	}
	return out
}

func (b *builder) verified(u chain.UTxO) bool {
	for a, q := range u.Value.Assets {
		if q > 0 && (b.in.Verified == nil || !b.in.Verified(a)) {
			return false
		}
	}
	return true
}

func (b *builder) selectOptions() selectOptions {
	minChange := b.in.MinChange
	if minChange == 0 {
		minChange = DefaultMinChange
	}
	return selectOptions{DustThreshold: b.in.UTxO.DustThreshold, MaxDust: int(b.in.UTxO.MaxDustSweep), MinChange: minChange}
}

// choose runs MACS over the UTxOs without unverified tokens and, if they do
// not cover the target, over all of them.
func (b *builder) choose(pool []chain.UTxO, target model.Value) ([]chain.UTxO, error) {
	var clean []chain.UTxO
	for _, u := range pool {
		if b.verified(u) {
			clean = append(clean, u)
		}
	}
	if len(clean) < len(pool) {
		if sel, err := selectMACS(clean, target, b.selectOptions()); err == nil {
			return sel, nil
		}
	}
	return selectMACS(pool, target, b.selectOptions())
}

func (b *builder) minFee(size int) uint64 {
	return b.in.Params.MinFeeA*uint64(size) + b.in.Params.MinFeeB
}

// payment selects inputs for the requested outputs and settles fee and
// change. When the change comes out short, it selects again for that much
// more (section 8.1, step 5, and 8.3, step 4).
func (b *builder) payment() (*Tx, error) {
	pool := b.spendable()
	if len(pool) == 0 {
		return nil, ErrNoFreeUTxOs
	}
	// A first guess at the fee; the fixed point below finds the real one.
	target := cloneValue(b.payout)
	target.Lovelace += b.minFee(250 + 120*len(b.pay))
	var fallback *Tx
	for range 8 {
		sel, err := b.choose(pool, target)
		if err != nil {
			break
		}
		tx, plan, err := b.settle(sel, b.pay, len(pool)-len(sel))
		if err != nil {
			return nil, err
		}
		if plan.short == 0 {
			return tx, nil
		}
		if tx != nil && (fallback == nil || tx.Fee < fallback.Fee) {
			fallback = tx
		}
		// Ask for what these inputs hold plus what is missing, which no
		// longer fits in the same selection: MACS has to add an input.
		var held uint64
		for _, u := range sel {
			held += u.Value.Lovelace
		}
		target.Lovelace = max(target.Lovelace+1, held+plan.short)
	}
	// No selection leaves a valid change; the best that gives a dead-band
	// remainder to the fee, within the policy's maximum, will do.
	if fallback != nil {
		return fallback, nil
	}
	return nil, ErrInsufficientFunds
}

// consolidation spends every spendable UTxO back to the wallet, as change
// split per the target number of UTxOs. If they do not fit in one
// transaction, it takes the smallest that fit, so dust goes first.
func (b *builder) consolidation() (*Tx, error) {
	pool := b.spendable()
	if len(pool) == 0 {
		return nil, ErrNoFreeUTxOs
	}
	slices.SortFunc(pool, func(x, y chain.UTxO) int {
		if c := cmp.Compare(x.Value.Lovelace, y.Value.Lovelace); c != 0 {
			return c
		}
		return x.In.Compare(y.In)
	})
	try := func(n int) (*Tx, changePlan, error) {
		return b.settle(pool[:n], nil, len(pool)-n)
	}
	tx, plan, err := try(len(pool))
	if errors.Is(err, ErrTooLarge) {
		lo, hi := 1, len(pool) // the largest n that fits is in [lo, hi)
		for lo+1 < hi {
			mid := (lo + hi) / 2
			if _, _, err := try(mid); errors.Is(err, ErrTooLarge) {
				hi = mid
			} else {
				lo = mid
			}
		}
		tx, plan, err = try(lo)
	}
	if err != nil {
		return nil, err
	}
	if plan.short > 0 && tx == nil {
		return nil, ErrInsufficientFunds
	}
	return tx, nil
}

// settle finds the fee by fixed point for a selection: with the change of
// the current fee, encode, measure the signed size, and repeat until the fee
// covers that size (section 8.1, step 5). The fee only grows, so the loop
// ends; it may overpay by the few bytes that a smaller change saves. More
// than four rounds is a builder bug.
//
// If the change comes out short, plan.short says by how much, and tx is
// either nil or a fallback that gives a dead-band remainder to the fee,
// which is only offered within the policy's maximum fee.
func (b *builder) settle(sel []chain.UTxO, pay []model.Output, others int) (*Tx, changePlan, error) {
	var inSum model.Value
	for _, u := range sel {
		var err error
		if inSum, err = inSum.Add(u.Value); err != nil {
			return nil, changePlan{}, fmt.Errorf("%w: inputs overflow", ErrInternal)
		}
	}
	var payout model.Value
	for _, o := range pay {
		payout, _ = payout.Add(o.Value) // checked in requestedOutputs
	}
	adaOnly := b.in.ReservedADAOnly + others - b.tokenUTxOsOutside(sel)
	var fee uint64
	for range 5 {
		surplus, ok := subtract(inSum, payout, fee)
		if !ok {
			short := payout.Lovelace + fee - min(inSum.Lovelace, payout.Lovelace+fee)
			return nil, changePlan{short: max(short, 1)}, nil
		}
		plan, err := planChange(b.c, b.in.Wallet, surplus, adaOnly, b.in.UTxO, b.in.Params.CoinsPerUTxOByte)
		if err != nil {
			return nil, changePlan{}, err
		}
		if plan.short > 0 {
			return b.absorb(sel, pay, plan, fee), plan, nil
		}
		tx, err := b.encode(sel, pay, plan.outputs, fee)
		if err != nil {
			return nil, changePlan{}, err
		}
		need := b.minFee(tx.Size)
		if need <= fee {
			return tx, plan, nil
		}
		fee = need
	}
	return nil, changePlan{}, fmt.Errorf("%w: the fee does not converge", ErrInternal)
}

// tokenUTxOsOutside counts the unselected spendable UTxOs that carry tokens,
// which others (all unselected ones) must not count as ADA-only.
func (b *builder) tokenUTxOsOutside(sel []chain.UTxO) int {
	in := make(map[chain.TxIn]bool, len(sel))
	for _, u := range sel {
		in[u.In] = true
	}
	n := 0
	for _, u := range b.spendable() {
		if !in[u.In] && u.Value.HasAssets() {
			n++
		}
	}
	return n
}

// subtract returns inputs − outputs − fee, or false if lovelace runs out.
// Tokens of the outputs always come from the inputs, since MACS covered them.
func subtract(in, out model.Value, fee uint64) (model.Value, bool) {
	need := out.Lovelace + fee
	if in.Lovelace < need {
		return model.Value{}, false
	}
	s := model.Value{Lovelace: in.Lovelace - need}
	for a, q := range in.Assets {
		left := q - min(q, out.Assets[a])
		if left > 0 {
			if s.Assets == nil {
				s.Assets = map[model.AssetID]uint64{}
			}
			s.Assets[a] = left
		}
	}
	return s, true
}

// absorb returns the transaction that gives a dead-band remainder to the fee,
// or nil if there is none or the fee would pass the policy's maximum or fall
// short of the minimum: never more to the fee than the policy allows (section
// 8.1, step 5).
func (b *builder) absorb(sel []chain.UTxO, pay []model.Output, plan changePlan, fee uint64) *Tx {
	if plan.dust == 0 || fee+plan.dust > b.in.MaxFee {
		return nil
	}
	tx, err := b.encode(sel, pay, plan.outputs, fee+plan.dust)
	if err != nil || b.minFee(tx.Size) > tx.Fee {
		return nil
	}
	return tx
}

// encode builds the body and measures the signed size.
func (b *builder) encode(sel []chain.UTxO, pay []model.Output, change []model.Value, fee uint64) (*Tx, error) {
	ins := make([]chain.TxIn, len(sel))
	for i, u := range sel {
		ins[i] = u.In
	}
	outs := slices.Clone(pay)
	for _, v := range change {
		outs = append(outs, model.Output{Address: b.in.Wallet, Value: v, Own: true})
	}
	ttl := b.in.TipSlot + uint64(b.in.TTLSeconds)
	body, err := body{inputs: ins, outputs: outs, fee: fee, ttl: ttl, auxHash: b.auxHash}.encode(b.c)
	if err != nil {
		return nil, err
	}
	signed, err := assemble(b.c, body, b.wits, b.aux)
	if err != nil {
		return nil, err
	}
	size := len(signed) - 1 // without is_valid, as the ledger measures it
	if size > int(b.in.Params.MaxTxSize) {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, size)
	}
	sorted := slices.Clone(sel)
	slices.SortFunc(sorted, func(x, y chain.UTxO) int { return x.In.Compare(y.In) })
	return &Tx{
		ID: blake2b256(body), Body: body, AuxData: b.aux,
		Inputs: sorted, Outputs: outs, Fee: fee, TTL: ttl, Size: size,
	}, nil
}

// validate runs the Conway phase-1 rules on the draft with placeholder
// witnesses (section 8.1, step 8) and checks the body is canonical. A
// failure is a builder bug.
func (b *builder) validate(tx *Tx) error {
	if err := b.c.CheckCanonical(tx.Body); err != nil {
		return fmt.Errorf("%w: body: %v", ErrInternal, err)
	}
	signed, err := assemble(b.c, tx.Body, b.wits, tx.AuxData)
	if err != nil {
		return err
	}
	spent := make([]chain.Spent, len(tx.Inputs))
	for i, u := range tx.Inputs {
		out, err := b.c.Marshal(outputCBOR(u.Address, u.Value))
		if err != nil {
			return err
		}
		spent[i] = chain.Spent{In: u.In, Output: out}
	}
	if err := chain.ValidateDraft(b.in.Network, b.in.Params, b.in.TipSlot, signed, spent); err != nil {
		return fmt.Errorf("%w: %v", ErrInternal, err)
	}
	return nil
}

// checkIntent reads the unsigned transaction back from its bytes and checks
// it against the intent (section 8.1, step 9). A mismatch is a builder bug.
func (b *builder) checkIntent(tx *Tx) error {
	raw, err := tx.Unsigned()
	if err != nil {
		return err
	}
	d, err := txdecode.Decode(raw, int(b.in.Params.MaxTxSize))
	if err != nil {
		return fmt.Errorf("%w: reading the draft back: %w", ErrInternal, err)
	}
	if err := d.CheckIntent(b.in.Wallet, b.in.Intent, b.in.Params.CoinsPerUTxOByte); err != nil {
		return fmt.Errorf("%w: %w", ErrInternal, err)
	}
	tx.Decoded = d
	return nil
}
