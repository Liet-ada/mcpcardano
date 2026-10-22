// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package corpus holds the differential test between the two decoders of the
// project (R-03; criterion 1 of milestone H-2): chain, with gouroboros, in
// the server, and txcheck in the wallet (section 8.4). Whatever txcheck
// accepts, the server must read the same way. txcheck may reject more: it
// accepts only what the MVP signs, in canonical form.
package corpus

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/txbuild"
	"github.com/Liet-ada/mcpcardano/internal/txcheck"
	"github.com/Liet-ada/mcpcardano/internal/txdecode"
)

// load returns the real transactions of the corpus by network and note.
func load(t testing.TB) map[string][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("*", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var e struct{ Network, Note, CBOR string }
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		raw, err := hex.DecodeString(e.CBOR)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out[e.Network+"/"+e.Note] = raw
	}
	return out
}

var codec = func() *cborx.Codec {
	c, err := cborx.New(cborx.Limits{MaxDepth: 32, MaxArrayElements: 1 << 16, MaxMapPairs: 1 << 16, AllowTags: true})
	if err != nil {
		panic(err)
	}
	return c
}()

// assemble encodes [body, {}, true, auxiliary data or null], a transaction
// without witnesses.
func assemble(t testing.TB, body, aux []byte) []byte {
	t.Helper()
	var auxItem any
	if len(aux) > 0 {
		auxItem = cborx.Raw(aux)
	}
	raw, err := codec.Marshal([]any{cborx.Raw(body), map[uint64]any{}, true, auxItem})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// same fails unless txcheck read the transaction raw as the server does:
// the same id, inputs and message, and the same view for a wallet that owns
// no output and for the owner of each output.
func same(t testing.TB, name string, raw []byte, got *txcheck.Tx) {
	t.Helper()
	d, err := chain.DecodeTransaction(raw)
	if err != nil {
		t.Fatalf("%s: txcheck accepts what the server cannot decode: %v", name, err)
	}
	server, err := txdecode.Decode(raw, len(raw))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if got.ID != d.ID {
		t.Errorf("%s: id %x, the server's %x", name, got.ID, d.ID)
	}
	if len(got.Inputs) != len(d.Inputs) {
		t.Fatalf("%s: %d inputs, the server reads %d", name, len(got.Inputs), len(d.Inputs))
	}
	for i, in := range got.Inputs {
		if in.TxID != d.Inputs[i].TxID || uint32(in.Index) != d.Inputs[i].Index {
			t.Errorf("%s: input %d is %x#%d, the server's %s", name, i, in.TxID, in.Index, d.Inputs[i])
		}
	}
	if !slices.Equal(got.Message, d.Message) {
		t.Errorf("%s: message %q, the server's %q", name, got.Message, d.Message)
	}
	wallets := []model.Address{{}}
	for _, o := range d.View.Outputs {
		wallets = append(wallets, o.Address)
	}
	for _, w := range wallets {
		have, want := got.View(w), server.View(w)
		// gouroboros keeps an absent TTL or validity start and a value of 0
		// alike; txcheck tells them apart.
		if have.TTL != nil && *have.TTL == 0 {
			have.TTL = nil
		}
		if have.ValidityStart != nil && *have.ValidityStart == 0 {
			have.ValidityStart = nil
		}
		if !reflect.DeepEqual(have, want) {
			t.Fatalf("%s: for wallet %x txcheck reads\n%+v\nand the server\n%+v", name, w.Raw, have, want)
		}
	}
}

// rejected says why txcheck rejects each real transaction. Most carry
// something the MVP never signs; four are not canonical. The other three
// must be read exactly as the server reads them.
var rejected = map[string]struct {
	err    error
	detail string
}{
	"mainnet/Byron output":                               {txcheck.ErrUnsupportedField, "address type 8"},
	"mainnet/mint and burn":                              {txcheck.ErrUnsupportedField, "script_data_hash"},
	"mainnet/Plutus script, tokens, collateral return":   {txcheck.ErrUnsupportedField, "script_data_hash"},
	"mainnet/reward withdrawal":                          {txcheck.ErrUnsupportedField, "script_data_hash"},
	"mainnet/stake registration and pool delegation":     {txcheck.ErrUnsupportedField, "certificates"},
	"mainnet/vote delegation":                            {txcheck.ErrUnsupportedField, "certificates"},
	"preprod/burn":                                       {txcheck.ErrNotCanonical, "body"},
	"preprod/Byron output":                               {txcheck.ErrUnsupportedField, "address type 8"},
	"preprod/CIP-20 message":                             {txcheck.ErrUnsupportedField, "script_data_hash"},
	"preprod/CIP-25 mint with metadata 721":              {txcheck.ErrNotCanonical, "auxiliary data"},
	"preprod/collateral return, reference input":         {txcheck.ErrUnsupportedField, "script_data_hash"},
	"preprod/combined registration and vote delegation":  {txcheck.ErrUnsupportedField, "certificates"},
	"preprod/datum hash":                                 {txcheck.ErrUnsupportedField, "script_data_hash"},
	"preprod/DRep registration, reference script output": {txcheck.ErrUnsupportedField, "certificates"},
	"preprod/DRep retirement":                            {txcheck.ErrUnsupportedField, "certificates"},
	"preprod/DRep update":                                {txcheck.ErrUnsupportedField, "certificates"},
	"preprod/mint":                                       {txcheck.ErrUnsupportedField, "script_data_hash"},
	"preprod/native script":                              {txcheck.ErrNotCanonical, "body"},
	"preprod/other metadata":                             {txcheck.ErrNotCanonical, "auxiliary data"},
	"preprod/Plutus script, validity start":              {txcheck.ErrUnsupportedField, "script_data_hash"},
	"preprod/pool delegation":                            {txcheck.ErrUnsupportedField, "certificates"},
	"preprod/proposal":                                   {txcheck.ErrUnsupportedField, "script_data_hash"},
	"preprod/reward withdrawal":                          {txcheck.ErrNotCanonical, "body"},
	"preprod/stake deregistration":                       {txcheck.ErrUnsupportedField, "certificates"},
	"preprod/tokens, inline datum, no TTL":               {txcheck.ErrUnsupportedField, "a datum is not supported"},
	"preprod/treasury donation":                          {txcheck.ErrUnsupportedField, "current_treasury_value"},
	"preprod/vote":                                       {txcheck.ErrUnsupportedField, "script_data_hash"},
}

func TestCorpus(t *testing.T) {
	accepted := 0
	for name, raw := range load(t) {
		d, err := chain.DecodeTransaction(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := txcheck.Decode(d.Body, d.AuxData)
		r, isRejected := rejected[name]
		switch {
		case isRejected && (!errors.Is(err, r.err) || !strings.Contains(err.Error(), r.detail)):
			t.Errorf("%s: got %v, want %v about %q", name, err, r.err, r.detail)
		case !isRejected && err != nil:
			t.Errorf("%s: %v", name, err)
		case !isRejected:
			same(t, name, raw, got)
			accepted++
		}
	}
	if accepted != 3 {
		t.Errorf("%d real transactions accepted, want 3", accepted)
	}
}

// reduce keeps of a real transaction what txcheck accepts, encoded
// canonically: its inputs, its outputs without a datum, a script or an
// address of another kind, its fee, validity, withdrawals, mint, required
// signers and network id. It returns the body and the view the server must
// read from it.
func reduce(t testing.TB, d *chain.DecodedTx) ([]byte, model.TxView) {
	t.Helper()
	v := d.View
	ins := make([]any, len(d.Inputs))
	for i, in := range d.Inputs {
		ins[i] = []any{in.TxID[:], uint64(in.Index)}
	}
	want := model.TxView{
		NetworkID: v.NetworkID, Fee: v.Fee, TTL: v.TTL, ValidityStart: v.ValidityStart,
		Withdrawals: v.Withdrawals, Mint: v.Mint, RequiredSigners: v.RequiredSigners,
	}
	outs := []any{}
	for _, o := range v.Outputs {
		switch {
		case o.HasDatum, o.HasScript, o.Address.Type > 7, o.Address.Type == 4, o.Address.Type == 5:
			continue
		}
		outs = append(outs, []any{o.Address.Raw, valueCBOR(o.Value)})
		want.Outputs = append(want.Outputs, o)
	}
	body := map[uint64]any{0: cborx.Tag{Number: 258, Content: ins}, 1: outs, 2: v.Fee}
	if v.TTL != nil {
		body[3] = *v.TTL
	}
	if len(v.Withdrawals) > 0 {
		w := map[cborx.ByteString]uint64{}
		for _, x := range v.Withdrawals {
			w[cborx.ByteString(x.Account)] = x.Amount
		}
		body[5] = w
	}
	if v.ValidityStart != nil {
		body[8] = *v.ValidityStart
	}
	if len(v.Mint) > 0 {
		m := map[cborx.ByteString]map[cborx.ByteString]int64{}
		for a, q := range v.Mint {
			p := cborx.ByteString(a.Policy[:])
			if m[p] == nil {
				m[p] = map[cborx.ByteString]int64{}
			}
			m[p][cborx.ByteString(a.Name)] = q
		}
		body[9] = m
	}
	if len(v.RequiredSigners) > 0 {
		s := make([]any, len(v.RequiredSigners))
		for i, h := range v.RequiredSigners {
			s[i] = h[:]
		}
		body[14] = cborx.Tag{Number: 258, Content: s}
	}
	if v.NetworkID != nil {
		body[15] = uint64(*v.NetworkID)
	}
	b, err := codec.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return b, want
}

func valueCBOR(v model.Value) any {
	if !v.HasAssets() {
		return v.Lovelace
	}
	ma := map[cborx.ByteString]map[cborx.ByteString]uint64{}
	for a, q := range v.Assets {
		p := cborx.ByteString(a.Policy[:])
		if ma[p] == nil {
			ma[p] = map[cborx.ByteString]uint64{}
		}
		ma[p][cborx.ByteString(a.Name)] = q
	}
	return []any{v.Lovelace, ma}
}

// TestReducedCorpus runs the differential on every real transaction, reduced
// to what txcheck accepts: real addresses, tokens, mints, burns, withdrawals
// and required signers, in the canonical encoding.
func TestReducedCorpus(t *testing.T) {
	var outputs, tokens, mint, withdrawals, signers int
	for name, raw := range load(t) {
		d, err := chain.DecodeTransaction(raw)
		if err != nil {
			t.Fatal(err)
		}
		body, want := reduce(t, d)
		reduced := assemble(t, body, nil)
		// First the reduction itself: the server reads what it kept.
		r, err := chain.DecodeTransaction(reduced)
		if err != nil {
			t.Fatalf("%s: the reduced transaction does not decode: %v", name, err)
		}
		if !reflect.DeepEqual(r.View, want) {
			t.Fatalf("%s: the reduction changed the transaction:\n%+v\n%+v", name, r.View, want)
		}
		got, err := txcheck.Decode(body, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		same(t, name, reduced, got)

		outputs += len(want.Outputs)
		for _, o := range want.Outputs {
			tokens += len(o.Value.Assets)
		}
		mint += len(want.Mint)
		withdrawals += len(want.Withdrawals)
		signers += len(want.RequiredSigners)
	}
	// The corpus must keep exercising each part of the decoder.
	if outputs < 40 || tokens < 1000 || mint < 14 || withdrawals < 3 || signers < 3 {
		t.Errorf("thin corpus: %d outputs, %d tokens, %d mints, %d withdrawals, %d signers",
			outputs, tokens, mint, withdrawals, signers)
	}
}

// The parameters of preprod at epoch 319.
func params() chain.ProtocolParameters {
	return chain.ProtocolParameters{
		Epoch: 319, MinFeeA: 44, MinFeeB: 155381, MaxTxSize: 16384, MaxValueSize: 5000, CoinsPerUTxOByte: 4310,
		KeyDeposit: 2_000_000, PoolDeposit: 500_000_000, DRepDeposit: 500_000_000, GovActionDeposit: 1_000_000_000,
		PriceMem: chain.Rational{Num: 577, Den: 10000}, PriceStep: chain.Rational{Num: 721, Den: 10000000},
		MaxTxExMem: 17_500_000, MaxTxExSteps: 10_000_000_000, CollateralPercent: 150, MaxCollateralInputs: 3,
		MinFeeRefScriptByte: chain.Rational{Num: 15, Den: 1}, ProtocolMajor: 11,
	}
}

const ada = 1_000_000

func randomBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// randomAddress returns a preprod base or enterprise address of one of the
// given types (CIP-19).
func randomAddress(t testing.TB, r *rand.Rand, types ...byte) model.Address {
	t.Helper()
	typ := types[r.IntN(len(types))]
	size := 57
	if typ >= 6 {
		size = 29
	}
	raw := randomBytes(r, size)
	raw[0] = typ << 4 // network 0
	a, err := chain.AddressFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// randomMessage returns valid UTF-8 of up to 256 bytes, with characters of
// one to four bytes so that lines split between them.
func randomMessage(r *rand.Rand) string {
	alphabet := []rune("aZ09 ñé€😀​")
	var b strings.Builder
	for n := r.IntN(80); n > 0; n-- {
		c := string(alphabet[r.IntN(len(alphabet))])
		if b.Len()+len(c) > model.MaxMessageBytes {
			break
		}
		b.WriteString(c)
	}
	return b.String()
}

// draft builds a random draft with txbuild: a payment of one to four outputs,
// with tokens and a message at times, or a consolidation. It returns nil when
// the random wallet cannot pay.
func draft(t testing.TB, r *rand.Rand) *txbuild.Tx {
	t.Helper()
	// The MVP spends only from a key payment credential; destinations may
	// have any credentials.
	wallet := randomAddress(t, r, 0, 2, 6)
	var policies [][]byte
	for range 1 + r.IntN(3) {
		policies = append(policies, randomBytes(r, 28))
	}
	var pool []chain.UTxO
	held := map[model.AssetID]uint64{}
	for range 1 + r.IntN(8) {
		v := model.Value{Lovelace: uint64(2+r.IntN(500)) * ada}
		if r.IntN(2) == 0 {
			v.Assets = map[model.AssetID]uint64{}
			for range 1 + r.IntN(4) {
				a, err := model.NewAssetID(policies[r.IntN(len(policies))], randomBytes(r, r.IntN(33)))
				if err != nil {
					t.Fatal(err)
				}
				q := uint64(1 + r.IntN(1_000_000))
				v.Assets[a] += q
				held[a] += q
			}
		}
		in := chain.TxIn{TxID: [32]byte(randomBytes(r, 32)), Index: uint32(r.IntN(10))}
		pool = append(pool, chain.UTxO{In: in, Address: wallet, Value: v})
	}

	intent := model.Intent{Kind: model.IntentConsolidation}
	if r.IntN(5) > 0 {
		p := &model.Payment{}
		for range 1 + r.IntN(4) {
			o := model.PaymentOutput{Address: randomAddress(t, r, 0, 1, 2, 3, 6, 7), Value: model.Value{Lovelace: uint64(1+r.IntN(30)) * ada}}
			for a, q := range held {
				if r.IntN(3) == 0 {
					o.Value.Assets = map[model.AssetID]uint64{a: 1 + uint64(r.IntN(int(q)))}
					if r.IntN(2) == 0 {
						o.Value.Lovelace = 0 // txbuild adds the minimum ADA
					}
					break
				}
			}
			p.Outputs = append(p.Outputs, o)
		}
		if r.IntN(2) == 0 {
			p.Message = randomMessage(r)
		}
		intent = model.Intent{Kind: model.IntentPayment, Payment: p}
	}

	tx, err := txbuild.Build(txbuild.Input{
		Network: model.Preprod, Wallet: wallet, Intent: intent, Available: pool,
		Params: params(), MaxFee: 2 * ada, TipSlot: 136_515_214, TTLSeconds: uint32(60 + r.IntN(7200)),
		UTxO:     model.UTxOPolicy{TargetADAOnly: uint32(1 + r.IntN(4)), MinSplit: 5 * ada, DustThreshold: ada, MaxDustSweep: 2},
		Verified: func(model.AssetID) bool { return true },
	})
	if err != nil {
		var below *txbuild.BelowMinimumError
		if errors.Is(err, txbuild.ErrInsufficientFunds) || errors.As(err, &below) || errors.Is(err, txbuild.ErrTooLarge) {
			return nil
		}
		t.Fatalf("build: %v", err)
	}
	return tx
}

// TestBuiltDrafts runs the differential on drafts of every shape the server
// builds: what txbuild writes, txcheck must accept and read as the server
// does.
func TestBuiltDrafts(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	var built, messages, tokens, consolidations int
	for range 400 {
		tx := draft(t, r)
		if tx == nil {
			continue
		}
		got, err := txcheck.Decode(tx.Body, tx.AuxData)
		if err != nil {
			t.Fatalf("txcheck rejects a draft of txbuild: %v", err)
		}
		raw, err := tx.Unsigned()
		if err != nil {
			t.Fatal(err)
		}
		same(t, "draft", raw, got)

		built++
		if got.Message != nil {
			messages++
		}
		for _, o := range tx.Outputs {
			if !o.Own && o.Value.HasAssets() {
				tokens++
				break
			}
		}
		if len(tx.Outputs) > 0 && !slices.ContainsFunc(tx.Outputs, func(o model.Output) bool { return !o.Own }) {
			consolidations++
		}
	}
	t.Logf("%d drafts, %d with a message, %d paying tokens, %d consolidations", built, messages, tokens, consolidations)
	if built < 250 || messages < 50 || tokens < 50 || consolidations < 30 {
		t.Errorf("thin sample: %d drafts, %d with a message, %d paying tokens, %d consolidations",
			built, messages, tokens, consolidations)
	}
}

// FuzzDifferential looks for a body that txcheck accepts and the server reads
// differently, or cannot read at all.
func FuzzDifferential(f *testing.F) {
	for _, raw := range load(f) {
		d, err := chain.DecodeTransaction(raw)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(d.Body, d.AuxData)
		body, _ := reduce(f, d)
		f.Add(body, []byte(nil))
	}
	r := rand.New(rand.NewPCG(3, 4))
	for range 20 {
		if tx := draft(f, r); tx != nil {
			f.Add(tx.Body, tx.AuxData)
		}
	}
	f.Fuzz(func(t *testing.T, body, aux []byte) {
		got, err := txcheck.Decode(body, aux)
		if err != nil {
			return
		}
		same(t, "fuzz", assemble(t, body, aux), got)
	})
}
