// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package txcheck

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

var testCodec = func() *cborx.Codec {
	c, err := cborx.New(cborx.Limits{MaxDepth: 64, MaxArrayElements: 1 << 16, MaxMapPairs: 1 << 16, AllowTags: true})
	if err != nil {
		panic(err)
	}
	return c
}()

func enc(t testing.TB, v any) []byte {
	t.Helper()
	b, err := testCodec.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fill(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

// addr returns the bytes of a preprod address: header type, then the payment
// and, for a base address, the stake credential.
func addr(typ byte, pay, stake byte) []byte {
	raw := append([]byte{typ << 4}, fill(28, pay)...)
	if typ <= 3 {
		raw = append(raw, fill(28, stake)...)
	}
	return raw
}

var (
	wallet = addr(0, 0x11, 0x22)
	shop   = addr(6, 0x33, 0)
	policy = cborx.ByteString(fill(28, 0xa1))
)

func tagged(items ...any) cborx.Tag {
	if items == nil {
		items = []any{}
	}
	return cborx.Tag{Number: setTag, Content: items}
}

// draftBody is a payment as txbuild writes it: 5 ADA to a shop and the
// change, with a token, back to the wallet.
func draftBody() map[uint64]any {
	return map[uint64]any{
		0: tagged([]any{fill(32, 0xee), uint64(1)}, []any{fill(32, 0xef), uint64(0)}),
		1: []any{
			[]any{shop, uint64(5_000_000)},
			[]any{wallet, []any{uint64(94_830_000), map[cborx.ByteString]map[cborx.ByteString]uint64{policy: {"MC": 60}}}},
		},
		2: uint64(170_000),
		3: uint64(136_518_814),
	}
}

func withMessage(t testing.TB, m map[uint64]any, lines ...string) []byte {
	t.Helper()
	aux := enc(t, map[uint64]any{cip20Label: map[string]any{"msg": lines}})
	h := blake2b.Sum256(aux)
	m[keyAuxDataHash] = h[:]
	return aux
}

func walletAddress() model.Address {
	return model.Address{Raw: wallet, Type: 0, Payment: model.Credential{Hash: [28]byte(fill(28, 0x11))},
		Stake: &model.Credential{Hash: [28]byte(fill(28, 0x22))}}
}

func TestDraft(t *testing.T) {
	m := draftBody()
	aux := withMessage(t, m, "pago de la factura", "número 7")
	body := enc(t, m)
	tx, err := Decode(body, aux)
	if err != nil {
		t.Fatal(err)
	}
	if tx.ID != blake2b.Sum256(body) {
		t.Error("the id is not the hash of the body")
	}
	want := []Input{{TxID: [32]byte(fill(32, 0xee)), Index: 1}, {TxID: [32]byte(fill(32, 0xef)), Index: 0}}
	if !reflect.DeepEqual(tx.Inputs, want) {
		t.Errorf("inputs %+v", tx.Inputs)
	}
	if !reflect.DeepEqual(tx.Message, []string{"pago de la factura", "número 7"}) {
		t.Errorf("message %q", tx.Message)
	}

	w := walletAddress()
	v := tx.View(w)
	if v.Fee != 170_000 || v.TTL == nil || *v.TTL != 136_518_814 || v.ValidityStart != nil || v.NetworkID != nil {
		t.Errorf("fee %d, ttl %v, start %v, network %v", v.Fee, v.TTL, v.ValidityStart, v.NetworkID)
	}
	if len(v.Outputs) != 2 {
		t.Fatalf("%d outputs", len(v.Outputs))
	}
	pay, change := v.Outputs[0], v.Outputs[1]
	if pay.Own || pay.Value.Lovelace != 5_000_000 || pay.Value.Assets != nil || pay.Address.Type != 6 || pay.Address.Stake != nil {
		t.Errorf("payment %+v", pay)
	}
	if !change.Own || !reflect.DeepEqual(change.Address, w) {
		t.Errorf("change %+v", change)
	}
	tok, _ := model.NewAssetID([]byte(policy), []byte("MC"))
	if change.Value.Lovelace != 94_830_000 || !reflect.DeepEqual(change.Value.Assets, map[model.AssetID]uint64{tok: 60}) {
		t.Errorf("change value %+v", change.Value)
	}
	// The view of another wallet owns nothing, and the views do not share
	// their outputs.
	if other := tx.View(model.Address{Raw: shop}); other.Outputs[1].Own || !other.Outputs[0].Own || !v.Outputs[1].Own {
		t.Error("views share their outputs")
	}
}

func TestOwnOnlyOnCompleteMatch_M02(t *testing.T) {
	m := draftBody()
	// The wallet's payment credential with somebody else's stake credential.
	m[1] = []any{[]any{addr(0, 0x11, 0x99), uint64(5_000_000)}}
	tx, err := Decode(enc(t, m), nil)
	if err != nil {
		t.Fatal(err)
	}
	if tx.View(walletAddress()).Outputs[0].Own {
		t.Error("an output with another stake credential counts as own")
	}
}

func TestOptionalFields(t *testing.T) {
	m := draftBody()
	m[0] = []any{[]any{fill(32, 0xee), uint64(1)}} // a set without its tag
	m[1] = []any{map[uint64]any{0: shop, 1: uint64(2_000_000)}}
	m[keyValidityStart] = uint64(100)
	m[keyNetworkID] = uint64(0)
	m[keyRequiredSigners] = tagged(fill(28, 0x11))
	reward := append([]byte{0xe0}, fill(28, 0x22)...)
	m[keyWithdrawals] = map[cborx.ByteString]uint64{cborx.ByteString(reward): 1_234}
	// M-03: the mint reaches policy, which allows it only if the wallet's
	// policy does.
	m[keyMint] = map[cborx.ByteString]map[cborx.ByteString]int64{policy: {"A": 5, "B": -3}}
	tx, err := Decode(enc(t, m), nil)
	if err != nil {
		t.Fatal(err)
	}
	v := tx.View(model.Address{})
	a, _ := model.NewAssetID([]byte(policy), []byte("A"))
	b, _ := model.NewAssetID([]byte(policy), []byte("B"))
	switch {
	case len(tx.Inputs) != 1 || len(v.Outputs) != 1 || v.Outputs[0].Value.Lovelace != 2_000_000:
		t.Errorf("inputs %+v, outputs %+v", tx.Inputs, v.Outputs)
	case v.ValidityStart == nil || *v.ValidityStart != 100 || v.NetworkID == nil || *v.NetworkID != 0:
		t.Errorf("start %v, network %v", v.ValidityStart, v.NetworkID)
	case !reflect.DeepEqual(v.RequiredSigners, [][28]byte{[28]byte(fill(28, 0x11))}):
		t.Errorf("signers %x", v.RequiredSigners)
	case !reflect.DeepEqual(v.Withdrawals, []model.Withdrawal{{Account: reward, Amount: 1_234}}):
		t.Errorf("withdrawals %+v", v.Withdrawals)
	case !reflect.DeepEqual(v.Mint, map[model.AssetID]int64{a: 5, b: -3}):
		t.Errorf("mint %v", v.Mint)
	}
}

func TestUnsupportedFields_M07(t *testing.T) {
	voter := []any{uint64(0), fill(28, 1)}
	action := []any{fill(32, 2), uint64(0)}
	cases := []struct {
		key    uint64
		value  any
		detail string
	}{
		{4, []any{[]any{uint64(0), []any{uint64(0), fill(28, 1)}}}, "certificates"}, // decision 105
		{6, uint64(0), "unknown body field 6"},
		{10, uint64(0), "unknown body field 10"},
		{11, fill(32, 0), "script_data_hash"},
		{12, uint64(0), "unknown body field 12"},
		{13, tagged([]any{fill(32, 3), uint64(0)}), "collateral_inputs"},
		{16, []any{shop, uint64(1)}, "collateral_return"},
		{17, uint64(1), "total_collateral"},
		{18, tagged([]any{fill(32, 3), uint64(0)}), "reference_inputs"},
		// A map with arrays as keys, which a generic decoder cannot hold: the
		// closed list rejects it before anything reads it.
		{19, map[any]any{&voter: map[any]any{&action: []any{uint64(1), nil}}}, "voting_procedures"},
		{20, []any{}, "proposal_procedures"},
		{21, uint64(1), "current_treasury_value"},
		{22, uint64(1), "donation"},
		{23, uint64(0), "unknown body field 23"},
		{1 << 40, uint64(0), "unknown body field"},
	}
	for _, c := range cases {
		m := draftBody()
		m[c.key] = c.value
		if c.key == 19 {
			// Pointer keys keep the encoder from rejecting arrays as keys.
			m[c.key] = rawVotes(t)
		}
		_, err := Decode(enc(t, m), nil)
		if !errors.Is(err, ErrUnsupportedField) || !strings.Contains(err.Error(), c.detail) {
			t.Errorf("field %d: got %v", c.key, err)
		}
	}
}

// rawVotes is {[0, key hash]: {[tx id, 0]: [1, null]}}, encoded by hand: Go
// maps cannot have arrays as keys.
func rawVotes(t testing.TB) cborx.Raw {
	var b []byte
	b = append(b, 0xa1)
	b = append(b, enc(t, []any{uint64(0), fill(28, 1)})...)
	b = append(b, 0xa1)
	b = append(b, enc(t, []any{fill(32, 2), uint64(0)})...)
	b = append(b, enc(t, []any{uint64(1), nil})...)
	return b
}

func TestMissingFields(t *testing.T) {
	for _, k := range []uint64{keyInputs, keyOutputs, keyFee} {
		m := draftBody()
		delete(m, k)
		_, err := Decode(enc(t, m), nil)
		if !errors.Is(err, ErrUnsupportedField) || !strings.Contains(err.Error(), "the body has no "+bodyFields[k].name) {
			t.Errorf("without field %d: %v", k, err)
		}
	}
}

func TestRejectedForms(t *testing.T) {
	out := func(o any) func(map[uint64]any) {
		return func(m map[uint64]any) { m[keyOutputs] = []any{o} }
	}
	value := func(v any) func(map[uint64]any) { return out([]any{shop, v}) }
	tokens := func(ma any) func(map[uint64]any) { return value([]any{uint64(2_000_000), ma}) }
	in := func(items ...any) func(map[uint64]any) {
		return func(m map[uint64]any) { m[keyInputs] = tagged(items...) }
	}
	field := func(k uint64, v any) func(map[uint64]any) {
		return func(m map[uint64]any) { m[k] = v }
	}
	name33 := cborx.ByteString(fill(33, 'x'))
	cases := []struct {
		name   string
		mutate func(map[uint64]any)
		detail string
	}{
		// Outputs (decision 35 and decision 105).
		{"datum hash", out([]any{shop, uint64(2_000_000), fill(32, 0)}), "a datum hash"},
		{"datum", out(map[uint64]any{0: shop, 1: uint64(2_000_000), 2: []any{uint64(0), fill(32, 0)}}), "a datum"},
		{"reference script", out(map[uint64]any{0: shop, 1: uint64(2_000_000), 3: cborx.Tag{Number: 24, Content: []byte{0}}}), "a reference script"},
		{"unknown output field", out(map[uint64]any{0: shop, 1: uint64(2_000_000), 4: uint64(0)}), "unknown output field"},
		{"output without value", out(map[uint64]any{0: shop}), "no address or no value"},
		{"output of one element", out([]any{shop}), "not [address, value]"},
		{"Byron address", out([]any{append([]byte{0x82}, fill(40, 0)...), uint64(2_000_000)}), "address type 8"},
		{"pointer address", out([]any{append([]byte{0x40}, fill(31, 1)...), uint64(2_000_000)}), "address type 4"},
		{"reward address", out([]any{append([]byte{0xe0}, fill(28, 1)...), uint64(2_000_000)}), "address type 14"},
		{"short base address", out([]any{wallet[:56], uint64(2_000_000)}), "has 56 bytes, not 57"},
		{"long enterprise address", out([]any{append(shop, 0), uint64(2_000_000)}), "has 30 bytes, not 29"},
		{"address of network 2", out([]any{append([]byte{0x62}, fill(28, 1)...), uint64(2_000_000)}), "network 2"},
		{"address as text", out([]any{"addr_test1", uint64(2_000_000)}), "not a byte string"},
		// Values.
		{"negative coin", value(int64(-1)), "not a value"},
		{"value of one element", value([]any{uint64(1)}), "not [coin, multiasset]"},
		{"zero token", tokens(map[cborx.ByteString]map[cborx.ByteString]uint64{policy: {"A": 0}}), "not a positive quantity"},
		{"empty multiasset", tokens(map[cborx.ByteString]any{}), "not a non-empty map"},
		{"policy without tokens", tokens(map[cborx.ByteString]map[cborx.ByteString]uint64{policy: {}}), "a policy without tokens"},
		{"long asset name", tokens(map[cborx.ByteString]map[cborx.ByteString]uint64{policy: {name33: 1}}), "invalid asset id"},
		{"short policy id", tokens(map[cborx.ByteString]map[cborx.ByteString]uint64{policy[:27]: {"A": 1}}), "invalid asset id"},
		{"text asset name", tokens(map[cborx.ByteString]map[string]uint64{policy: {"A": 1}}), "not a byte string"},
		// Inputs.
		{"no inputs", in(), "no inputs"},
		{"duplicate input", in([]any{fill(32, 1), uint64(0)}, []any{fill(32, 1), uint64(0)}), "appears twice"},
		{"index of 3 bytes", in([]any{fill(32, 1), uint64(65_536)}), "integer of 2 bytes"},
		{"short transaction id", in([]any{fill(31, 1), uint64(0)}), "hash of 32 bytes"},
		{"set with another tag", field(keyInputs, cborx.Tag{Number: 259, Content: []any{}}), "tag 259"},
		// Single values.
		{"negative fee", field(keyFee, int64(-1)), "not an unsigned integer"},
		{"TTL as bytes", field(keyTTL, []byte{1}), "not an unsigned integer"},
		{"float fee", field(keyFee, 170_000.0), "not an unsigned integer"},
		{"network 2", field(keyNetworkID, uint64(2)), "not 0 or 1"},
		{"auxiliary data hash of 31 bytes", field(keyAuxDataHash, fill(31, 0)), "hash of 32 bytes"},
		// Required signers.
		{"no required signers", field(keyRequiredSigners, tagged()), "an empty set"},
		{"duplicate signer", field(keyRequiredSigners, tagged(fill(28, 1), fill(28, 1))), "appears twice"},
		{"short signer", field(keyRequiredSigners, tagged(fill(27, 1))), "hash of 28 bytes"},
		// Withdrawals.
		{"no withdrawals", field(keyWithdrawals, map[cborx.ByteString]uint64{}), "not a non-empty map"},
		{"withdrawal from a payment address", field(keyWithdrawals, map[cborx.ByteString]uint64{cborx.ByteString(shop): 1}), "not a reward account"},
		{"withdrawal of network 2", field(keyWithdrawals, map[cborx.ByteString]uint64{cborx.ByteString(append([]byte{0xe2}, fill(28, 1)...)): 1}), "not a reward account"},
		// Mint.
		{"zero mint", field(keyMint, map[cborx.ByteString]map[cborx.ByteString]int64{policy: {"A": 0}}), "non-zero quantity"},
		{"mint beyond 8 bytes", field(keyMint, map[cborx.ByteString]map[cborx.ByteString]uint64{policy: {"A": math.MaxInt64 + 1}}), "non-zero quantity"},
	}
	for _, c := range cases {
		m := draftBody()
		c.mutate(m)
		_, err := Decode(enc(t, m), nil)
		if !errors.Is(err, ErrUnsupportedField) || !strings.Contains(err.Error(), c.detail) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
}

func TestNotCanonical_M08(t *testing.T) {
	m := draftBody()
	good := enc(t, m)
	in, outs, fee := enc(t, m[keyInputs]), enc(t, m[keyOutputs]), enc(t, m[keyFee])
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	cases := []struct {
		name string
		body []byte
	}{
		{"unsorted keys", cat([]byte{0xa3}, enc(t, uint64(2)), fee, enc(t, uint64(0)), in, enc(t, uint64(1)), outs)},
		{"fee with a long integer", cat([]byte{0xa3, 0x00}, in, []byte{0x01}, outs, []byte{0x02, 0x1b, 0, 0, 0, 0, 0, 2, 0x98, 0x10})},
		{"indefinite outputs", cat([]byte{0xa3, 0x00}, in, []byte{0x01, 0x9f}, outs[1:], []byte{0xff, 0x02}, fee)},
		{"duplicate key", cat([]byte{0xa4, 0x00}, in, []byte{0x01}, outs, []byte{0x02}, fee, []byte{0x02}, fee)},
		{"trailing bytes", cat(good, []byte{0x00})},
		{"tag around the body", cat([]byte{0xcf}, good)},
		{"tag around a key", cat([]byte{0xa3, 0xc5, 0x00}, in, []byte{0x01}, outs, []byte{0x02}, fee)},
		{"bignum fee", cat([]byte{0xa3, 0x00}, in, []byte{0x01}, outs, []byte{0x02, 0xc2, 0x43, 0x02, 0x98, 0x10})},
		{"an array", enc(t, []any{uint64(0)})},
		{"truncated", good[:len(good)-1]},
		{"empty", nil},
	}
	for _, c := range cases {
		_, err := Decode(c.body, nil)
		if !errors.Is(err, ErrNotCanonical) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
}

// TestDepthLimit puts arrays inside the outputs, which sit two levels deep:
// 16 levels decode, and then fail as outputs; 17 do not decode (decision 97).
func TestDepthLimit(t *testing.T) {
	nested := func(levels int) []byte {
		deep := any(uint64(0))
		for range levels - 2 {
			deep = []any{deep}
		}
		m := draftBody()
		m[keyOutputs] = []any{deep}
		return enc(t, m)
	}
	if _, err := Decode(nested(16), nil); !errors.Is(err, ErrUnsupportedField) {
		t.Errorf("16 levels: %v", err)
	}
	if _, err := Decode(nested(17), nil); !errors.Is(err, ErrNotCanonical) {
		t.Errorf("17 levels: %v", err)
	}
}

func TestAuxiliaryData_M12(t *testing.T) {
	hashed := func(m map[uint64]any, aux []byte) []byte {
		h := blake2b.Sum256(aux)
		m[keyAuxDataHash] = h[:]
		return enc(t, m)
	}
	cip20 := func(lines any) []byte { return enc(t, map[uint64]any{cip20Label: map[string]any{"msg": lines}}) }
	long := strings.Repeat("é", 33) // 66 bytes
	cases := []struct {
		name string
		body func(map[uint64]any) []byte
		aux  []byte
		want error
	}{
		{"hash without auxiliary data", func(m map[uint64]any) []byte { m[keyAuxDataHash] = fill(32, 1); return enc(t, m) }, nil, ErrUnsupportedField},
		{"auxiliary data without hash", func(m map[uint64]any) []byte { return enc(t, m) }, cip20([]string{"a"}), ErrUnsupportedField},
		{"another hash", func(m map[uint64]any) []byte { m[keyAuxDataHash] = fill(32, 1); return enc(t, m) }, cip20([]string{"a"}), ErrUnsupportedField},
		{"another label", nil, enc(t, map[uint64]any{721: map[string]any{"msg": []string{"a"}}}), ErrUnsupportedField},
		{"two labels", nil, enc(t, map[uint64]any{cip20Label: map[string]any{"msg": []string{"a"}}, 1: uint64(0)}), ErrUnsupportedField},
		{"another key next to msg", nil, enc(t, map[uint64]any{cip20Label: map[string]any{"msg": []string{"a"}, "x": uint64(0)}}), ErrUnsupportedField},
		{"msg is text", nil, cip20("a"), ErrUnsupportedField},
		{"empty message", nil, cip20([]string{}), ErrUnsupportedField},
		{"line of 66 bytes", nil, cip20([]string{long}), ErrUnsupportedField},
		{"line of bytes", nil, cip20([]any{[]byte("a")}), ErrUnsupportedField},
		{"tagged line", nil, cip20([]any{cborx.Tag{Number: 24, Content: "a"}}), ErrUnsupportedField},
		{"Alonzo form", nil, enc(t, cborx.Tag{Number: 259, Content: map[uint64]any{0: map[uint64]any{cip20Label: map[string]any{"msg": []string{"a"}}}}}), ErrUnsupportedField},
		{"not canonical", nil, []byte{0xa1, 0x19, 0x02, 0xa2, 0xa1, 0x63, 'm', 's', 'g', 0x81, 0x78, 0x01, 'a'}, ErrNotCanonical},
	}
	for _, c := range cases {
		m := draftBody()
		var body []byte
		if c.body != nil {
			body = c.body(m)
		} else {
			body = hashed(m, c.aux)
		}
		_, err := Decode(body, c.aux)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}

	// The longest lines pass, in characters of any size.
	m := draftBody()
	lines := []string{strings.Repeat("a", 64), strings.Repeat("€", 21) + "a"}
	aux := cip20(lines)
	tx, err := Decode(hashed(m, aux), aux)
	if err != nil || !reflect.DeepEqual(tx.Message, lines) {
		t.Errorf("got %q, %v", tx.Message, err)
	}
}

func TestTooLarge(t *testing.T) {
	m := draftBody()
	aux := withMessage(t, m, "a")
	body := enc(t, m)
	if _, err := Decode(body, append(aux, make([]byte, 16384-len(body)-len(aux)+1)...)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("got %v", err)
	}
	if _, err := Decode(make([]byte, 16385), nil); !errors.Is(err, ErrTooLarge) {
		t.Errorf("got %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	m := draftBody()
	aux := withMessage(f, m, "hola")
	f.Add(enc(f, m), aux)
	f.Add(enc(f, draftBody()), []byte(nil))
	m = draftBody()
	m[keyMint] = map[cborx.ByteString]map[cborx.ByteString]int64{policy: {"A": 5, "B": -3}}
	m[keyRequiredSigners] = tagged(fill(28, 0x11))
	f.Add(enc(f, m), []byte(nil))
	f.Fuzz(func(t *testing.T, body, aux []byte) {
		tx, err := Decode(body, aux)
		if err != nil {
			if !errors.Is(err, ErrNotCanonical) && !errors.Is(err, ErrUnsupportedField) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("an error without its class: %v", err)
			}
			return
		}
		again, err := Decode(body, aux)
		if err != nil || !reflect.DeepEqual(tx, again) {
			t.Fatalf("two readings differ: %v", err)
		}
		if tx.ID != blake2b.Sum256(body) {
			t.Fatal("the id is not the hash of the body")
		}
	})
}
