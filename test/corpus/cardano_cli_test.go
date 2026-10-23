// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package corpus

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/big"
	"math/rand/v2"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/txcheck"
)

// The cross check of txcheck with cardano-cli (decision 131). The
// differential test compares txcheck with gouroboros, the server's reading;
// cardano-cli reads a transaction with the decoders of cardano-ledger, in
// Haskell, which is what runs it on the network. testdata/cli/cardano_cli.json
// holds transactions of every shape txcheck accepts and what cardano-cli read
// in each, with `debug transaction view` and `transaction txid`.
// make cli-txviews records it again.

const cliFixture = "testdata/cli/cardano_cli.json"

var cliBodies = flag.String("cli-bodies", "", "write the transactions of the cross check with cardano-cli to this file, for test/cardano-cli/txviews.go, and stop")

// CLITx is a transaction of the cross check: what txcheck reads, and what
// cardano-cli read.
type CLITx struct {
	Name string `json:"name"`
	Body string `json:"body"`
	Aux  string `json:"aux,omitempty"`
	// Tx is [body, {}, true, aux or null], the transaction cardano-cli reads.
	Tx    string          `json:"tx"`
	TxID  string          `json:"txid,omitempty"`
	View  json.RawMessage `json:"view,omitempty"`
	Error string          `json:"error,omitempty"`
}

// CLIFile is the fixture.
type CLIFile struct {
	Tool     string  `json:"tool"`
	Recorded string  `json:"recorded"`
	Txs      []CLITx `json:"txs"`
}

// crossCheckTxs returns the transactions of the cross check: the real ones
// txcheck accepts, every real one reduced to what txcheck accepts, drafts of
// txbuild and edge cases.
func crossCheckTxs(t testing.TB) []CLITx {
	t.Helper()
	var txs []CLITx
	add := func(name string, body, aux []byte) {
		if _, err := txcheck.Decode(body, aux); err != nil {
			t.Fatalf("%s: txcheck rejects it: %v", name, err)
		}
		txs = append(txs, CLITx{Name: name, Body: hex.EncodeToString(body), Aux: hex.EncodeToString(aux),
			Tx: hex.EncodeToString(assemble(t, body, aux))})
	}
	byName := load(t)
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		d, err := chain.DecodeTransaction(byName[name])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := txcheck.Decode(d.Body, d.AuxData); err == nil {
			add("real "+name, d.Body, d.AuxData)
		}
		body, _ := reduce(t, d)
		add("reduced "+name, body, nil)
	}
	r := rand.New(rand.NewPCG(5, 6))
	for n := 0; n < 60; {
		if tx := draft(t, r); tx != nil {
			n++
			add(fmt.Sprintf("draft %d", n), tx.Body, tx.AuxData)
		}
	}
	for _, e := range edgeCases(t) {
		add(e.name, e.body, e.aux)
	}
	return txs
}

type edgeCase struct {
	name      string
	body, aux []byte
}

// edgeCases are forms that neither the corpus nor txbuild writes and txcheck
// accepts: outputs as maps, sets without their tag, script credentials,
// mainnet, the largest amounts, and the edges of asset names, mints,
// withdrawals, validity and messages.
func edgeCases(t testing.TB) []edgeCase {
	t.Helper()
	fill := func(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }
	input := func(b byte, ix uint64) []any { return []any{fill(32, b), ix} }
	inputs := cborx.Tag{Number: 258, Content: []any{input(0xa1, 0), input(0xa2, 7)}}
	// addr is an address of CIP-19 type typ on network n.
	addr := func(typ, n, b byte) []byte {
		size := 57
		if typ >= 6 {
			size = 29
		}
		raw := fill(size, b)
		raw[0] = typ<<4 | n
		return raw
	}
	type assets = map[cborx.ByteString]map[cborx.ByteString]uint64
	p1, p2 := cborx.ByteString(fill(28, 0x11)), cborx.ByteString(fill(28, 0x22))
	enc := func(v any) []byte {
		b, err := codec.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	body := func(extra map[uint64]any) []byte {
		m := map[uint64]any{0: inputs, 1: []any{[]any{addr(0, 0, 0x31), uint64(2_000_000)}}, 2: uint64(170_000), 3: uint64(136_518_814)}
		for k, v := range extra {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return enc(m)
	}
	message := func(lines ...string) (map[uint64]any, []byte) {
		ls := make([]any, len(lines))
		for i, l := range lines {
			ls[i] = l
		}
		aux := enc(map[uint64]any{674: map[string]any{"msg": ls}})
		h := blake2b.Sum256(aux)
		return map[uint64]any{7: h[:]}, aux
	}
	msg, aux := message("hola", strings.Repeat("x", 64), "ñé€😀", "a\u200bb")

	return []edgeCase{
		{"outputs as maps and arrays", body(map[uint64]any{1: []any{
			map[uint64]any{0: addr(0, 0, 0x31), 1: uint64(2_000_000)},
			[]any{addr(6, 0, 0x32), uint64(3_000_000)},
			map[uint64]any{0: addr(0, 0, 0x33), 1: []any{uint64(1_500_000), assets{p1: {"a": 5}}}},
		}}), nil},
		{"sets without their tag", body(map[uint64]any{
			0:  []any{input(0xa1, 0), input(0xa2, 7)},
			14: []any{fill(28, 0x41), fill(28, 0x42)},
		}), nil},
		{"sets with their tag", body(map[uint64]any{14: cborx.Tag{Number: 258, Content: []any{fill(28, 0x42), fill(28, 0x41)}}}), nil},
		{"script credentials", body(map[uint64]any{1: []any{
			[]any{addr(1, 0, 0x51), uint64(1_000_000)},
			[]any{addr(2, 0, 0x52), uint64(1_000_000)},
			[]any{addr(3, 0, 0x53), uint64(1_000_000)},
			[]any{addr(7, 0, 0x54), uint64(1_000_000)},
		}}), nil},
		{"mainnet", body(map[uint64]any{
			1:  []any{[]any{addr(0, 1, 0x61), uint64(1_000_000)}, []any{addr(6, 1, 0x62), uint64(1_000_000)}},
			5:  map[cborx.ByteString]uint64{cborx.ByteString(addr(14, 1, 0x63)): 1_234},
			15: uint64(1),
		}), nil},
		{"network id 0", body(map[uint64]any{15: uint64(0)}), nil},
		{"the largest amounts", body(map[uint64]any{
			1: []any{
				[]any{addr(0, 0, 0x71), uint64(math.MaxUint64)},
				[]any{addr(0, 0, 0x72), []any{uint64(1_000_000), assets{p1: {"max": math.MaxUint64}}}},
			},
			2: uint64(math.MaxUint64),
			3: uint64(math.MaxUint64),
			8: uint64(0),
		}), nil},
		{"asset names", body(map[uint64]any{1: []any{[]any{addr(0, 0, 0x81), []any{uint64(1_500_000), assets{
			p1: {"": 1, cborx.ByteString(fill(32, 0xff)): 2, "\x00": 3},
			p2: {cborx.ByteString(fill(32, 0x00)): 4, "token": 5},
		}}}}}), nil},
		{"mint at its edges", body(map[uint64]any{9: map[cborx.ByteString]map[cborx.ByteString]int64{
			p1: {"": math.MaxInt64, "burn": math.MinInt64},
			p2: {cborx.ByteString(fill(32, 0xee)): -1, "one": 1},
		}}), nil},
		{"withdrawals", body(map[uint64]any{5: map[cborx.ByteString]uint64{
			cborx.ByteString(addr(14, 0, 0x91)): 0,
			cborx.ByteString(addr(15, 0, 0x92)): 45_000_000_000_000_000,
		}}), nil},
		{"validity start without a TTL", body(map[uint64]any{3: nil, 8: uint64(136_518_000)}), nil},
		{"no validity", body(map[uint64]any{3: nil}), nil},
		{"a message", body(msg), aux},
	}
}

func TestCardanoCLI(t *testing.T) {
	if *cliBodies != "" {
		b, err := json.MarshalIndent(CLIFile{Txs: crossCheckTxs(t)}, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(*cliBodies, b, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skipf("wrote %s", *cliBodies)
	}
	b, err := os.ReadFile(cliFixture)
	if err != nil {
		t.Fatal(err)
	}
	var f CLIFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	t.Logf("recorded with %s on %s", f.Tool, f.Recorded)
	recorded := map[string]CLITx{}
	for _, x := range f.Txs {
		recorded[x.Name] = x
	}
	// The edge cases are written here, so the fixture must hold them as they
	// are. The drafts change from run to run, and those recorded stay valid.
	for _, e := range edgeCases(t) {
		if x, ok := recorded[e.name]; !ok || x.Body != hex.EncodeToString(e.body) || x.Aux != hex.EncodeToString(e.aux) {
			t.Errorf("%s: not in the fixture as written here; run make cli-txviews", e.name)
		}
	}

	var n counts
	for _, x := range f.Txs {
		body, _ := hex.DecodeString(x.Body)
		aux, _ := hex.DecodeString(x.Aux)
		got, err := txcheck.Decode(body, aux)
		switch {
		case err != nil:
			t.Errorf("%s: txcheck rejects it: %v", x.Name, err)
			continue
		case x.Error != "":
			t.Errorf("%s: txcheck accepts what cardano-cli cannot read: %s", x.Name, x.Error)
			continue
		case x.TxID != hex.EncodeToString(got.ID[:]):
			t.Errorf("%s: id %x, cardano-cli's %s", x.Name, got.ID, x.TxID)
		}
		want, err := cliRead(x.View)
		if err != nil {
			t.Errorf("%s: %v", x.Name, err)
			continue
		}
		if have := txcheckRead(got); !reflect.DeepEqual(have, want) {
			t.Errorf("%s: txcheck reads\n%+v\nand cardano-cli\n%+v", x.Name, have, want)
		}
		n.add(want)
	}
	// The fixture must keep exercising each part of the decoder.
	if len(f.Txs) < 100 || n.outputs < 300 || n.tokens < 1200 || n.mints < 15 || n.burns < 4 ||
		n.withdrawals < 6 || n.signers < 6 || n.messages < 20 || n.ttls < 80 || n.starts < 5 {
		t.Errorf("thin fixture: %d transactions, %+v", len(f.Txs), n)
	}
}

// read is a transaction as the cross check compares it, in the terms of
// cardano-cli's view: sets sorted, addresses in bech32, amounts as text.
type read struct {
	Inputs      []string // tx#index
	Outputs     []string // address, lovelace and each token
	Fee         string
	Lower       string // validity start
	Upper       string // TTL
	Mint        []string
	Withdrawals []string
	Signers     []string
	Message     []string
}

func asset(policy, name []byte) string {
	return hex.EncodeToString(policy) + "." + hex.EncodeToString(name)
}

func txcheckRead(tx *txcheck.Tx) read {
	v := tx.View(model.Address{})
	var r read
	for _, in := range tx.Inputs {
		r.Inputs = append(r.Inputs, fmt.Sprintf("%x#%d", in.TxID, in.Index))
	}
	for _, o := range v.Outputs {
		s := []string{o.Address.Bech32(), strconv.FormatUint(o.Value.Lovelace, 10)}
		var ts []string
		for a, q := range o.Value.Assets {
			ts = append(ts, asset(a.Policy[:], []byte(a.Name))+"="+strconv.FormatUint(q, 10))
		}
		slices.Sort(ts)
		r.Outputs = append(r.Outputs, strings.Join(append(s, ts...), " "))
	}
	r.Fee = strconv.FormatUint(v.Fee, 10)
	if v.ValidityStart != nil {
		r.Lower = strconv.FormatUint(*v.ValidityStart, 10)
	}
	if v.TTL != nil {
		r.Upper = strconv.FormatUint(*v.TTL, 10)
	}
	for a, q := range v.Mint {
		r.Mint = append(r.Mint, asset(a.Policy[:], []byte(a.Name))+"="+strconv.FormatInt(q, 10))
	}
	for _, w := range v.Withdrawals {
		r.Withdrawals = append(r.Withdrawals, model.Address{Raw: w.Account}.Bech32()+"="+strconv.FormatUint(w.Amount, 10))
	}
	for _, h := range v.RequiredSigners {
		r.Signers = append(r.Signers, hex.EncodeToString(h[:]))
	}
	r.Message = tx.Message
	r.sort()
	return r
}

func (r *read) sort() {
	slices.Sort(r.Inputs)
	slices.Sort(r.Mint)
	slices.Sort(r.Withdrawals)
	slices.Sort(r.Signers)
}

// cliRead reads cardano-cli's view, refusing anything txcheck never accepts.
func cliRead(raw json.RawMessage) (read, error) {
	var v map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return read{}, err
	}
	// What txcheck never accepts must be absent.
	for _, k := range []string{"auxiliary scripts", "certificates", "collateral inputs", "currentTreasuryValue", "datums",
		"governance actions", "redeemers", "reference inputs", "return collateral", "scripts", "total collateral",
		"treasuryDonation", "update proposal", "voters"} {
		switch string(v[k]) {
		case "", "null", "[]", "{}", "0": // "" when the version has no such field
		default:
			return read{}, fmt.Errorf("cardano-cli reads %s: %s", k, v[k])
		}
	}
	if e := string(v["era"]); e != `"Conway"` {
		return read{}, fmt.Errorf("era %s", e)
	}
	var r read
	var fee string
	var outs []struct {
		Address string                     `json:"address"`
		Amount  map[string]json.RawMessage `json:"amount"`
		Script  json.RawMessage            `json:"reference script"`
		Datum   json.RawMessage            `json:"datum"`
	}
	var validity struct {
		Lower json.Number `json:"lower bound"`
		Upper json.Number `json:"upper bound"`
	}
	var mint map[string]map[string]json.Number
	var withdrawals []struct{ Address, Amount string }
	var meta map[string][][]json.RawMessage
	for k, dst := range map[string]any{"inputs": &r.Inputs, "fee": &fee, "outputs": &outs, "validity range": &validity,
		"mint": &mint, "withdrawals": &withdrawals, "required signers (payment key hashes needed for scripts)": &r.Signers,
		"metadata": &meta} {
		d := json.NewDecoder(bytes.NewReader(v[k]))
		d.UseNumber()
		if err := d.Decode(dst); err != nil {
			return read{}, fmt.Errorf("%s: %v", k, err)
		}
	}
	lovelace := func(s string) (string, error) {
		n, ok := strings.CutSuffix(s, " Lovelace")
		if !ok {
			return "", fmt.Errorf("amount %q", s)
		}
		return n, nil
	}
	var err error
	if r.Fee, err = lovelace(fee); err != nil {
		return read{}, err
	}
	for _, o := range outs {
		if s := string(o.Script); s != "null" || len(o.Datum) > 0 && string(o.Datum) != "null" {
			return read{}, fmt.Errorf("output with a script %s or a datum %s", o.Script, o.Datum)
		}
		l, err := integer(string(o.Amount["lovelace"]))
		if err != nil {
			return read{}, err
		}
		s := []string{o.Address, l}
		var ts []string
		for k, x := range o.Amount {
			p, ok := strings.CutPrefix(k, "policy ")
			if !ok {
				if k != "lovelace" {
					return read{}, fmt.Errorf("amount %s", k)
				}
				continue
			}
			var as map[string]json.Number
			if err := json.Unmarshal(x, &as); err != nil {
				return read{}, err
			}
			for name, q := range as {
				n, err := cliAssetName(name)
				if err != nil {
					return read{}, err
				}
				q, err := integer(q.String())
				if err != nil {
					return read{}, err
				}
				ts = append(ts, p+"."+n+"="+q)
			}
		}
		slices.Sort(ts)
		r.Outputs = append(r.Outputs, strings.Join(append(s, ts...), " "))
	}
	if r.Lower, err = integer(validity.Lower.String()); err != nil {
		return read{}, err
	}
	if r.Upper, err = integer(validity.Upper.String()); err != nil {
		return read{}, err
	}
	for p, as := range mint {
		for name, q := range as {
			n, err := cliAssetName(name)
			if err != nil {
				return read{}, err
			}
			q, err := integer(q.String())
			if err != nil {
				return read{}, err
			}
			r.Mint = append(r.Mint, strings.TrimPrefix(p, "policy ")+"."+n+"="+q)
		}
	}
	for _, w := range withdrawals {
		n, err := lovelace(w.Amount)
		if err != nil {
			return read{}, err
		}
		r.Withdrawals = append(r.Withdrawals, w.Address+"="+n)
	}
	if len(r.Signers) == 0 {
		r.Signers = nil
	}
	if meta != nil {
		// CIP-20: {674: {"msg": [lines]}}, which the view prints as pairs.
		pairs, ok := meta["674"]
		if len(meta) != 1 || !ok || len(pairs) != 1 || len(pairs[0]) != 2 || string(pairs[0][0]) != `"msg"` {
			return read{}, fmt.Errorf("metadata %v", meta)
		}
		if err := json.Unmarshal(pairs[0][1], &r.Message); err != nil {
			return read{}, err
		}
	}
	r.sort()
	return r, nil
}

// integer returns in decimal digits a JSON number, which the view prints in
// scientific notation from 2^64 or so; "" stays "".
func integer(n string) (string, error) {
	if n == "" {
		return "", nil
	}
	r, ok := new(big.Rat).SetString(n)
	if !ok || !r.IsInt() {
		return "", fmt.Errorf("not an integer: %s", n)
	}
	return r.Num().String(), nil
}

// cliAssetName returns in hex an asset name as the view prints it: "asset"
// and the name in hex, followed by the name in parentheses if it is text, or
// "default asset" for the empty name.
func cliAssetName(s string) (string, error) {
	if s == "default asset" {
		return "", nil
	}
	rest, ok := strings.CutPrefix(s, "asset ")
	name, _, _ := strings.Cut(rest, " ")
	if _, err := hex.DecodeString(name); !ok || err != nil || name == "" {
		return "", fmt.Errorf("asset name %q", s)
	}
	return name, nil
}

type counts struct {
	outputs, tokens, mints, burns, withdrawals, signers, messages, ttls, starts int
}

func (n *counts) add(r read) {
	n.outputs += len(r.Outputs)
	for _, o := range r.Outputs {
		n.tokens += strings.Count(o, "=")
	}
	n.mints += len(r.Mint)
	for _, m := range r.Mint {
		if strings.Contains(m, "=-") {
			n.burns++
		}
	}
	n.withdrawals += len(r.Withdrawals)
	n.signers += len(r.Signers)
	if r.Message != nil {
		n.messages++
	}
	if r.Upper != "" {
		n.ttls++
	}
	if r.Lower != "" {
		n.starts++
	}
}
