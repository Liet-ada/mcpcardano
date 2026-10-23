// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package ipc

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

func filled(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

// manyAddresses returns n distinct enterprise addresses, in order.
func manyAddresses(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = append([]byte{0x60, byte(i)}, filled(27, 8)...)
	}
	return out
}

var (
	walletA   = mustID(model.NewWalletID(bytes.NewReader(filled(16, 1))))
	walletB   = mustID(model.NewWalletID(bytes.NewReader(filled(16, 2))))
	draft     = mustID(model.NewDraftID(bytes.NewReader(filled(16, 3))))
	approval  = mustID(model.NewApprovalID(bytes.NewReader(filled(16, 4))))
	addr      = append([]byte{0x00}, filled(56, 7)...) // a base address of preprod
	otherAddr = append([]byte{0x60}, filled(28, 8)...) // an enterprise address
	policyID  = filled(28, 9)
	reqID     = filled(IDSize, 5)
)

func mustID[T ~string](id T, err error) string {
	if err != nil {
		panic(err)
	}
	return string(id)
}

func samplePolicy() Policy {
	return Policy{
		SessionRequired: true,
		Networks:        []string{"preprod", "preview"},
		Limits:          Limits{PerTx: 20_000_000, PerHour: 50_000_000, PerDay: 100_000_000, Budget: 100_000_000, MaxFee: 2_000_000, NewDestinationsPerHour: 2, NewDestinationsPerDay: 5, MaxLiveDrafts: 10, MaxTTLSeconds: 7200},
		Destinations:    Destinations{Allowed: [][]byte{addr, otherAddr}},
		Assets:          []AssetCap{{Policy: policyID, Name: []byte("A"), Cap: 10}, {Policy: policyID, Name: []byte("B"), Cap: 0}},
		Structure:       Structure{InternalTransfers: true},
		UTxO:            UTxOPolicy{TargetADAOnly: 3, MinSplit: 5_000_000, DustThreshold: 1_000_000, MaxDustSweep: 2},
	}
}

func sampleWallet(id string) Wallet {
	return Wallet{ID: id, Label: "Agent wallet", Network: "preprod", Mode: "C", Address: addr, CreatedBy: "agent"}
}

func sampleSpend() Spend {
	return Spend{Lovelace: 5_176_589, Assets: []AssetAmount{{Policy: policyID, Name: []byte("A"), Quantity: 3}}}
}

func witness() []Witness { return []Witness{{VKey: filled(32, 1), Signature: filled(64, 2)}} }

func raw(t testing.TB, b Body) cborx.Raw {
	t.Helper()
	r, err := NewCodec().Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// samples gives a valid request and response for every message type.
func samples(t testing.TB) map[string][2]Body {
	p := samplePolicy()
	return map[string][2]Body{
		MsgHello: {&Hello{Software: "0.2.0", Network: "preprod"}, &Hello{Software: "0.2.0", Network: "preprod"}},
		MsgSignDraft: {
			&SignDraft{WalletID: walletA, DraftID: draft, Body: filled(300, 0xa5), AuxData: filled(40, 0xa1),
				Inputs: []ResolvedInput{{TxID: filled(32, 6), Index: 1, Output: filled(70, 0x82)}}},
			&SignDraftResult{Status: Signed, Witnesses: witness(), Spend: sampleSpend()},
		},
		MsgCreateWallet:      {&CreateWallet{Label: "Agent wallet", IdempotencyKey: "k1"}, &WalletCreated{Wallet: sampleWallet(walletA), Policy: p}},
		MsgGetApprovalStatus: {&GetApprovalStatus{ApprovalID: approval}, &ApprovalStatus{Status: ApprovalApproved, Witnesses: witness(), ExpiresAt: 1_792_000_000}},
		MsgGetPolicyStatus: {&GetPolicyStatus{WalletID: walletA, Destinations: [][]byte{filled(29, 0x60), filled(29, 0x61)}}, &PolicyStatus{
			Mode: "B", Policy: p, Session: &Session{ExpiresAt: 1_792_000_000, Remaining: 10_000_000},
			SpentHour: 1, SpentDay: 2, TxHour: 4, NewDestinationsHour: 5, NewDestinationsDay: 6, Known: [][]byte{filled(29, 0x61)},
			BudgetRemaining: 3, Pending: []PendingTx{{TxID: filled(32, 6), TTL: 81_234_567}},
		}},
		MsgPing:        {&Empty{}, &PingResult{AnyFrozen: true, Slot: 81_234_000}},
		MsgListWallets: {&Empty{}, &WalletList{Wallets: []Wallet{sampleWallet(walletA), sampleWallet(walletB)}}},

		MsgStatus: {&Empty{}, &StatusReport{
			Unlocked:        true,
			Wallets:         []WalletStatus{{Wallet: sampleWallet(walletA), Session: &Session{ExpiresAt: 1, Remaining: 2}, OpenDestinations: true}},
			Approvals:       []Approval{{ID: approval, WalletID: walletA, Spend: sampleSpend(), ExpiresAt: 1_792_000_000}},
			LastLedgerEntry: 1_791_000_000,
			Keys:            []KeyInfo{{Name: "YubiKey", CredentialID: filled(64, 9), Alg: AlgEdDSA, Added: 1_790_000_000}},
			Recovery:        &Recovery{StartedAt: 1_791_000_000, EndsAt: 1_791_259_200},
		}},
		MsgUnlock: {&Unlock{Password: model.Secret("correct horse")}, &Empty{}},
		MsgBeginAuthorization: {
			&BeginAuthorization{Action: ActOpenSession, Params: raw(t, &OpenSession{WalletID: walletA, Seconds: 3600, MaxLovelace: 50_000_000})},
			&Challenge{AuthID: filled(16, 3), Summary: []string{"Open a session on Agent wallet", "for 1 hour, up to 50 ADA"}, Methods: []string{MethodKey},
				ExpiresAt: 1, RPID: "mcpcardano", Credentials: [][]byte{filled(64, 9), filled(48, 8)}, PIN: true, ClientDataHash: filled(32, 7)},
		},
		MsgCompleteAuthorization: {
			&CompleteAuthorization{AuthID: filled(16, 3), Assertion: &Assertion{CredentialID: filled(64, 9), AuthenticatorData: filled(37, 1), Signature: filled(70, 2)}},
			&Completed{Result: raw(t, &Empty{})},
		},
		MsgReject:       {&ApprovalRef{ApprovalID: approval}, &Empty{}},
		MsgFreeze:       {&Freeze{}, &Empty{}},
		MsgCloseSession: {&WalletRef{WalletID: walletA}, &Empty{}},
		MsgListExpired: {&ListExpired{WalletID: walletA}, &ExpiredList{Entries: []Expired{
			{WalletID: walletA, BodyHash: filled(32, 4), Spend: Spend{Lovelace: 1}, TTL: 9, Time: 8},
		}}},
		MsgShowPolicy:   {&WalletRef{WalletID: walletA}, &WalletPolicy{WalletID: walletA, Mode: "B", Policy: p}},
		MsgShowTemplate: {&Empty{}, &Template{Mode: "C", Policy: p}},
		MsgShowAudit:    {&ShowAudit{From: 1, Limit: 50}, &AuditPage{Entries: []cborx.Raw{{0xa0}}, Next: 51}},
		MsgVerifyAudit:  {&Empty{}, &AuditCheck{AuditEntries: 10, LedgerEntries: 4}},
	}
}

func socketOf(t string) Socket {
	if messages[t].service {
		return Service
	}
	return Admin
}

func TestEveryMessageRoundTrips(t *testing.T) {
	c := NewCodec()
	s := samples(t)
	for name := range messages {
		pair, ok := s[name]
		if !ok {
			t.Errorf("no sample for %s", name)
			continue
		}
		frame, err := c.EncodeRequest(name, reqID, pair[0])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		r, err := c.DecodeRequest(socketOf(name), frame)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := NewRequest(name)
		if err := c.DecodeBody(r.B, got); err != nil {
			t.Fatalf("%s request: %v", name, err)
		}
		if !reflect.DeepEqual(got, pair[0]) {
			t.Errorf("%s request: got %+v, want %+v", name, got, pair[0])
		}

		frame, err = c.EncodeResponse(reqID, pair[1])
		if err != nil {
			t.Fatal(err)
		}
		gotResp := NewResponse(name)
		if err := c.DecodeResponse(frame, reqID, gotResp); err != nil {
			t.Fatalf("%s response: %v", name, err)
		}
		if !reflect.DeepEqual(gotResp, pair[1]) {
			t.Errorf("%s response: got %+v, want %+v", name, gotResp, pair[1])
		}
	}
}

func TestEveryActionHasBodies(t *testing.T) {
	c := NewCodec()
	params := map[string]Body{
		ActApproveDraft:       &ApproveDraft{ApprovalID: approval},
		ActOpenSession:        &OpenSession{WalletID: walletA, Seconds: 60, MaxLovelace: 1},
		ActChangePolicy:       &WalletPolicy{WalletID: walletA, Mode: "C", Policy: samplePolicy()},
		ActSetTemplate:        &Template{Mode: "C", Policy: samplePolicy()},
		ActUnfreeze:           &WalletRef{WalletID: walletA},
		ActReleaseBudget:      &ReleaseBudget{WalletID: walletA, Entries: [][]byte{filled(32, 1), filled(32, 2)}},
		ActCreateWallet:       &CreateWallet{Label: "Savings"},
		ActRestoreWallet:      &RestoreWallet{Label: "Savings", Phrase: model.Secret("abandon abandon about")},
		ActShowRecoveryPhrase: &WalletRef{WalletID: walletA},
		ActAddKey:             &AddKey{Name: "YubiKey", AuthenticatorData: filled(200, 1)},
		ActRemoveKey:          &KeyRef{CredentialID: filled(64, 9)},
		ActStartRecovery:      &Empty{},
		ActCancelRecovery:     &Empty{},
	}
	for action := range actions {
		p, ok := params[action]
		if !ok {
			t.Errorf("no sample for %s", action)
			continue
		}
		b := &BeginAuthorization{Action: action, Params: raw(t, p)}
		got, err := c.DecodeParams(b)
		if err != nil || !reflect.DeepEqual(got, p) {
			t.Errorf("%s: %+v, %v", action, got, err)
		}
		if NewResult(action) == nil {
			t.Errorf("%s has no result type", action)
		}
	}
	if _, err := c.DecodeParams(&BeginAuthorization{Action: "add_key", Params: raw(t, &Empty{})}); !isCode(err, Malformed) {
		t.Errorf("add_key arrives in H-3: %v", err)
	}
}

func isCode(err error, code Code) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// enc encodes a generic value with the canonical encoder, for building
// messages the typed encoder would never produce.
func enc(t testing.TB, v any) []byte {
	t.Helper()
	c, _ := cborx.New(cborx.Limits{MaxDepth: 64, MaxArrayElements: 1 << 16, MaxMapPairs: 1 << 16, AllowTags: true})
	b, err := c.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func envelope(t testing.TB, fields map[string]any) []byte {
	m := map[string]any{"v": uint64(Version), "id": reqID, "t": MsgPing, "b": cborx.Raw{0xa0}}
	for k, v := range fields {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return enc(t, m)
}

func TestEnvelopeRejections(t *testing.T) {
	c := NewCodec()
	ping := envelope(t, nil)
	if _, err := c.DecodeRequest(Service, ping); err != nil {
		t.Fatalf("a valid Ping: %v", err)
	}
	unsorted, _ := hex.DecodeString("a4" + "61" + hex.EncodeToString([]byte("t")) + "6450696e67" +
		"61" + hex.EncodeToString([]byte("v")) + hex.EncodeToString([]byte{Version}) + "6162a0" + "626964" + "50" + hex.EncodeToString(reqID))
	nonMinimal := bytes.Replace(ping, []byte{0x61, 'v', Version}, []byte{0x61, 'v', 0x18, Version}, 1)
	indefinite := append([]byte{0xbf}, ping[1:]...)
	indefinite = append(indefinite, 0xff)
	deep := enc(t, map[string]any{"v": uint64(Version), "id": reqID, "t": MsgPing,
		"b": cborx.Raw(append(bytes.Repeat([]byte{0x81}, 40), 0x00))})
	for _, tc := range []struct {
		name   string
		socket Socket
		frame  []byte
		code   Code
	}{
		{"an unknown envelope field", Service, envelope(t, map[string]any{"x": 1}), Malformed},
		{"no body", Service, envelope(t, map[string]any{"b": nil}), Malformed},
		{"no id", Service, envelope(t, map[string]any{"id": nil}), Malformed},
		{"a short id", Service, envelope(t, map[string]any{"id": filled(15, 1)}), Malformed},
		{"the id as text", Service, envelope(t, map[string]any{"id": "0123456789abcdef"}), Malformed},
		{"another version", Service, envelope(t, map[string]any{"v": uint64(Version + 1)}), ProtocolMismatch},
		{"an unknown type", Service, envelope(t, map[string]any{"t": "Sign"}), Malformed},
		{"an admin message on the service socket", Service, envelope(t, map[string]any{"t": MsgUnlock}), Malformed},
		{"a service message on the admin socket", Admin, envelope(t, map[string]any{"t": MsgSignDraft}), Malformed},
		{"unsorted keys", Service, unsorted, Malformed},
		{"a non-minimal integer", Service, nonMinimal, Malformed},
		{"an indefinite-length map", Service, indefinite, Malformed},
		{"trailing bytes", Service, append(slices.Clone(ping), 0x00), Malformed},
		{"a tag", Service, append([]byte{0xd8, 0x18}, ping...), Malformed},
		{"too deep", Service, deep, Malformed},
		{"not a map", Service, enc(t, []any{1, 2}), Malformed},
		{"garbage", Service, []byte{0xff, 0x00}, Malformed},
	} {
		if _, err := c.DecodeRequest(tc.socket, tc.frame); !isCode(err, tc.code) {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}

	dup, _ := hex.DecodeString("a5" + "6162a0" + "626964" + "50" + hex.EncodeToString(reqID) + "6174" + "6450696e67" + "6176" + "01" + "6176" + "01")
	if _, err := c.DecodeRequest(Service, dup); !isCode(err, Malformed) {
		t.Errorf("a repeated key: %v", err)
	}
}

func TestBodyRejections(t *testing.T) {
	c := NewCodec()
	good := samples(t)
	sd := func(f func(*SignDraft)) Body {
		s := *good[MsgSignDraft][0].(*SignDraft)
		f(&s)
		return &s
	}
	pol := func(f func(*Policy)) Body {
		p := samplePolicy()
		f(&p)
		return &WalletPolicy{WalletID: walletA, Mode: "B", Policy: p}
	}
	for _, tc := range []struct {
		name string
		body Body
	}{
		{"a bad wallet id", sd(func(s *SignDraft) { s.WalletID = "w_short" })},
		{"a draft id as wallet id", sd(func(s *SignDraft) { s.WalletID = draft })},
		{"an empty transaction", sd(func(s *SignDraft) { s.Body = nil })},
		{"a transaction too large", sd(func(s *SignDraft) { s.Body = filled(MaxTxSize+1, 1) })},
		{"auxiliary data too large", sd(func(s *SignDraft) { s.AuxData = filled(MaxTxSize+1, 1) })},
		{"a short input id", sd(func(s *SignDraft) { s.Inputs[0].TxID = filled(31, 1) })},
		{"an input index over 16 bits", sd(func(s *SignDraft) {
			s.Inputs = []ResolvedInput{{TxID: filled(32, 1), Index: 1 << 16, Output: []byte{0x80}}}
		})},
		{"a label with a newline", &CreateWallet{Label: "a\nb"}},
		{"a label with a zero-width space", &CreateWallet{Label: "a\u200bb"}},
		{"a label too long", &CreateWallet{Label: strings.Repeat("a", MaxLabel+1)}},
		{"an empty label", &CreateWallet{}},
		{"signed without witnesses", &SignDraftResult{Status: Signed}},
		{"signed with an approval", &SignDraftResult{Status: Signed, Witnesses: witness(), ApprovalID: approval}},
		{"pending without approval", &SignDraftResult{Status: PendingApproval}},
		{"rejected with a request error", &SignDraftResult{Status: Rejected, Rejection: &Error{Code: Malformed}}},
		{"rejected with an unknown code", &SignDraftResult{Status: Rejected, Rejection: &Error{Code: "NOPE"}}},
		{"an unknown status", &SignDraftResult{Status: "maybe"}},
		{"a short signature", &SignDraftResult{Status: Signed, Witnesses: []Witness{{VKey: filled(32, 1), Signature: filled(63, 1)}}}},
		{"a zero spend", &SignDraftResult{Status: Signed, Witnesses: witness(), Spend: Spend{Assets: []AssetAmount{{Policy: policyID, Quantity: 0}}}}},
		{"spend assets out of order", &SignDraftResult{Status: Signed, Witnesses: witness(), Spend: Spend{Assets: []AssetAmount{
			{Policy: policyID, Name: []byte("B"), Quantity: 1}, {Policy: policyID, Name: []byte("A"), Quantity: 1}}}}},
		{"witnesses on a pending approval", &ApprovalStatus{Status: ApprovalPending, Witnesses: witness()}},
		{"an approved approval without witnesses", &ApprovalStatus{Status: ApprovalApproved}},
		{"mode A in the wallet", &WalletPolicy{WalletID: walletA, Mode: "A", Policy: samplePolicy()}},
		{"networks out of order", pol(func(p *Policy) { p.Networks = []string{"preview", "preprod"} })},
		{"an unknown network", pol(func(p *Policy) { p.Networks = []string{"testnet"} })},
		{"any destination with a list", pol(func(p *Policy) { p.Destinations.Any = true })},
		{"destinations repeated", pol(func(p *Policy) { p.Destinations.Allowed = [][]byte{addr, addr} })},
		{"draft destinations out of order", &GetPolicyStatus{WalletID: walletA, Destinations: [][]byte{filled(29, 2), filled(29, 1)}}},
		{"an empty draft destination", &GetPolicyStatus{WalletID: walletA, Destinations: [][]byte{{}}}},
		{"more draft destinations than a payment has outputs", &GetPolicyStatus{WalletID: walletA, Destinations: manyAddresses(model.MaxPaymentOutputs + 1)}},
		{"known destinations repeated", &PolicyStatus{Mode: "B", Policy: samplePolicy(), Known: [][]byte{addr, addr}, Pending: []PendingTx{}}},
		{"an asset name too long", pol(func(p *Policy) { p.Assets = []AssetCap{{Policy: policyID, Name: filled(33, 1)}} })},
		{"a short policy id", pol(func(p *Policy) { p.Assets = []AssetCap{{Policy: filled(27, 1)}} })},
		{"two methods", &Challenge{AuthID: filled(16, 1), Summary: []string{"x"}, Methods: []string{"password", "fido2"}}},
		{"an unknown method", &Challenge{AuthID: filled(16, 1), Summary: []string{"x"}, Methods: []string{"face"}}},
		{"a password challenge with a key's fields", &Challenge{AuthID: filled(16, 1), Summary: []string{"x"}, Methods: []string{MethodPassword}, PIN: true}},
		{"a key challenge without credentials", &Challenge{AuthID: filled(16, 1), Summary: []string{"x"}, Methods: []string{MethodKey},
			RPID: "mcpcardano", ClientDataHash: filled(32, 1)}},
		{"a key challenge with a short hash", &Challenge{AuthID: filled(16, 1), Summary: []string{"x"}, Methods: []string{MethodKey},
			RPID: "mcpcardano", Credentials: [][]byte{filled(64, 9)}, ClientDataHash: filled(31, 1)}},
		{"a password and an assertion", &CompleteAuthorization{AuthID: filled(16, 1), Password: model.Secret("x"),
			Assertion: &Assertion{CredentialID: filled(64, 9), AuthenticatorData: filled(37, 1), Signature: filled(70, 2)}}},
		{"neither a password nor an assertion", &CompleteAuthorization{AuthID: filled(16, 1)}},
		{"an assertion without signature", &CompleteAuthorization{AuthID: filled(16, 1),
			Assertion: &Assertion{CredentialID: filled(64, 9), AuthenticatorData: filled(37, 1)}}},
		{"a credential id too long", &KeyRef{CredentialID: filled(MaxCredentialID+1, 9)}},
		{"a key without a name", &AddKey{AuthenticatorData: filled(200, 1)}},
		{"a key of another algorithm", &StatusReport{Wallets: []WalletStatus{}, Approvals: []Approval{},
			Keys: []KeyInfo{{Name: "RSA", CredentialID: filled(64, 9), Alg: -257}}}},
		{"a recovery that ends before it starts", &Recovery{StartedAt: 2, EndsAt: 1}},
		{"an empty summary", &Challenge{AuthID: filled(16, 1), Methods: []string{"password"}}},
		{"an empty password", &Unlock{}},
		{"a password too long", &Unlock{Password: model.Secret(filled(MaxSecret+1, 'a'))}},
		{"entries out of order", &ReleaseBudget{WalletID: walletA, Entries: [][]byte{filled(32, 2), filled(32, 1)}}},
		{"a session without amount", &OpenSession{WalletID: walletA, Seconds: 60}},
		{"an audit page of zero", &ShowAudit{From: 1}},
		{"a repeated wallet", &WalletList{Wallets: []Wallet{sampleWallet(walletA), sampleWallet(walletA)}}},
		{"an unknown created_by", &WalletList{Wallets: []Wallet{{ID: walletA, Label: "x", Network: "preprod", Mode: "B", Address: addr, CreatedBy: "robot"}}}},
	} {
		got := reflect.New(reflect.TypeOf(tc.body).Elem()).Interface().(Body)
		if err := c.DecodeBody(raw(t, tc.body), got); !isCode(err, Malformed) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}

	// Encodings the typed encoder never produces.
	for _, tc := range []struct {
		name string
		body []byte
		into Body
	}{
		{"a missing field", enc(t, map[string]any{"wallet_id": walletA}), new(SignDraft)},
		{"an unknown field", enc(t, map[string]any{"wallet_id": walletA, "extra": 1}), new(GetPolicyStatus)},
		{"an optional field sent empty", enc(t, map[string]any{"label": "x", "idempotency_key": ""}), new(CreateWallet)},
		{"no draft destinations sent empty", enc(t, map[string]any{"wallet_id": walletA, "destinations": []any{}}), new(GetPolicyStatus)},
		{"a negative amount", enc(t, map[string]any{"lovelace": -1}), new(Released)},
		{"a string as bytes", enc(t, map[string]any{"password": "secret"}), new(Unlock)},
		{"null", []byte{0xf6}, new(Empty)},
	} {
		if err := c.DecodeBody(tc.body, tc.into); !isCode(err, Malformed) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestResponses(t *testing.T) {
	c := NewCodec()
	ok, _ := c.EncodeResponse(reqID, &PingResult{Slot: 1})
	if err := c.DecodeResponse(ok, filled(IDSize, 9), new(PingResult)); !isCode(err, Malformed) {
		t.Errorf("a response to another request: %v", err)
	}
	failed, _ := c.EncodeError(reqID, &Error{Code: TooLarge, Detail: "message of 300000 bytes"})
	err := c.DecodeResponse(failed, reqID, new(PingResult))
	if !errors.Is(err, &Error{Code: TooLarge}) || errors.Is(err, &Error{Code: Malformed}) {
		t.Errorf("a failed response: %v", err)
	}
	// A request the wallet could not read has no id to echo.
	if err := c.DecodeResponse(must(c.EncodeError(nil, &Error{Code: Malformed})), reqID, new(PingResult)); !isCode(err, Malformed) {
		t.Errorf("a failed response without id: %v", err)
	}
	for _, tc := range []struct {
		name  string
		frame []byte
		code  Code
	}{
		{"ok with an error", enc(t, map[string]any{"v": Version, "id": reqID, "ok": true, "b": cborx.Raw{0xa0}, "err": map[string]any{"code": "INTERNAL", "detail": ""}}), Malformed},
		{"ok without a body", enc(t, map[string]any{"v": Version, "id": reqID, "ok": true}), Malformed},
		{"failed without an error", enc(t, map[string]any{"v": Version, "id": reqID, "ok": false}), Malformed},
		{"failed with a body", enc(t, map[string]any{"v": Version, "id": reqID, "ok": false, "b": cborx.Raw{0xa0}, "err": map[string]any{"code": "INTERNAL", "detail": ""}}), Malformed},
		{"an unknown code", enc(t, map[string]any{"v": Version, "id": reqID, "ok": false, "err": map[string]any{"code": "OOPS", "detail": ""}}), Malformed},
		{"a detail with a newline", enc(t, map[string]any{"v": Version, "id": reqID, "ok": false, "err": map[string]any{"code": "INTERNAL", "detail": "a\nb"}}), Malformed},
		{"another version", enc(t, map[string]any{"v": Version + 1, "id": reqID, "ok": true, "b": cborx.Raw{0xa0}}), ProtocolMismatch},
	} {
		if err := c.DecodeResponse(tc.frame, reqID, new(PingResult)); !isCode(err, tc.code) {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestDetail(t *testing.T) {
	if got := Detail("bad\x00field\u202e\nname"); got != "bad?field??name" {
		t.Errorf("Detail = %q", got)
	}
	long := Detail(strings.Repeat("\u00e9", 200))
	if len(long) > MaxDetail || !text(long, MaxDetail) {
		t.Errorf("a long detail: %d bytes", len(long))
	}
}

func testLimits() ConnLimits {
	return ConnLimits{MaxMessageSize: 1024, Receive: 100 * time.Millisecond, Idle: 300 * time.Millisecond}
}

func TestReadFrameLimits(t *testing.T) {
	l := testLimits()
	t.Run("too large before the payload", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		go b.Write([]byte{0, 0, 0x04, 0x01}) // 1025 bytes declared, none sent
		start := time.Now()
		_, err := ReadFrame(a, l)
		if !isCode(err, TooLarge) || time.Since(start) > l.Receive {
			t.Errorf("%v after %v", err, time.Since(start))
		}
	})
	t.Run("a slow sender", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		go b.Write([]byte{0, 0}) // and then nothing
		start := time.Now()
		_, err := ReadFrame(a, l)
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() || time.Since(start) > l.Idle {
			t.Errorf("%v after %v, want a timeout within Receive", err, time.Since(start))
		}
	})
	t.Run("an idle connection", func(t *testing.T) {
		a, _ := net.Pipe()
		defer a.Close()
		start := time.Now()
		_, err := ReadFrame(a, l)
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() || time.Since(start) < l.Idle {
			t.Errorf("%v after %v, want a timeout after Idle", err, time.Since(start))
		}
	})
	t.Run("an empty message", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		go b.Write([]byte{0, 0, 0, 0})
		if _, err := ReadFrame(a, l); !isCode(err, Malformed) {
			t.Error(err)
		}
	})
	t.Run("cut short", func(t *testing.T) {
		a, b := net.Pipe()
		go func() { b.Write([]byte{0, 0, 0, 8, 1, 2}); b.Close() }()
		if _, err := ReadFrame(a, l); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Error(err)
		}
	})
}

// fakeWallet answers on a real Unix socket, in the way of the wallet.
func fakeWallet(t *testing.T, network string, answer func(r Request) ([]byte, error)) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ipc") // t.TempDir can exceed the 104 bytes of a socket path on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "wallet.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c := NewCodec()
		for {
			conn, err := l.AcceptUnix()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if uid, err := PeerUID(conn); err != nil || uid != uint32(os.Getuid()) {
					t.Errorf("peer uid %d, %v; want %d", uid, err, os.Getuid())
					return
				}
				for {
					frame, err := ReadFrame(conn, testLimits())
					if err != nil {
						return
					}
					r, err := c.DecodeRequest(Service, frame)
					var out []byte
					switch {
					case err != nil:
						out, _ = c.EncodeError(r.ID, err.(*Error))
					case r.T == MsgHello:
						out, _ = c.EncodeResponse(r.ID, &Hello{Software: "0.2.0", Network: network})
					default:
						out, err = answer(r)
						if err != nil {
							out, _ = c.EncodeError(r.ID, err.(*Error))
						}
					}
					if WriteFrame(conn, out, testLimits()) != nil {
						return
					}
				}
			}()
		}
	}()
	return path
}

func TestClient(t *testing.T) {
	ctx := context.Background()
	hello := Hello{Software: "0.2.0", Network: "preprod"}
	path := fakeWallet(t, "preprod", func(r Request) ([]byte, error) {
		c := NewCodec()
		switch r.T {
		case MsgPing:
			return c.EncodeResponse(r.ID, &PingResult{Slot: 42})
		case MsgSignDraft:
			var s SignDraft
			if err := c.DecodeBody(r.B, &s); err != nil {
				return nil, err
			}
			return c.EncodeResponse(r.ID, &SignDraftResult{Status: Rejected, Rejection: &Error{Code: BudgetExceeded, Detail: "limits.per_day"}, Spend: Spend{Lovelace: 9}})
		}
		return nil, &Error{Code: Internal}
	})
	cl, err := Dial(ctx, path, hello)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if cl.Peer.Software != "0.2.0" {
		t.Errorf("peer %+v", cl.Peer)
	}
	var p PingResult
	if err := cl.Call(ctx, MsgPing, &Empty{}, &p); err != nil || p.Slot != 42 {
		t.Errorf("ping: %+v, %v", p, err)
	}
	var res SignDraftResult
	if err := cl.Call(ctx, MsgSignDraft, samples(t)[MsgSignDraft][0], &res); err != nil || res.Rejection.Code != BudgetExceeded {
		t.Errorf("sign: %+v, %v", res, err)
	}
	if err := cl.Call(ctx, MsgGetPolicyStatus, &GetPolicyStatus{WalletID: walletA}, new(PolicyStatus)); !isCode(err, Internal) {
		t.Errorf("a failed call: %v", err)
	}
	if err := cl.Call(ctx, MsgGetPolicyStatus, &GetPolicyStatus{WalletID: "w_x"}, new(PolicyStatus)); !isCode(err, Malformed) {
		t.Errorf("an invalid request is not sent: %v", err)
	}
	// The connection still works after both.
	if err := cl.Call(ctx, MsgPing, &Empty{}, &p); err != nil {
		t.Errorf("ping after errors: %v", err)
	}

	if _, err := Dial(ctx, fakeWallet(t, "preview", nil), hello); !isCode(err, NetworkMismatch) {
		t.Errorf("another network: %v", err)
	}
}

func TestClientCancel(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	path := fakeWallet(t, "preprod", func(r Request) ([]byte, error) {
		<-block
		return nil, &Error{Code: Internal}
	})
	cl, err := Dial(context.Background(), path, Hello{Software: "0.2.0", Network: "preprod"})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := cl.Call(ctx, MsgPing, &Empty{}, new(PingResult)); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a cancelled call: %v", err)
	}
	if err := cl.Call(context.Background(), MsgPing, &Empty{}, new(PingResult)); err == nil {
		t.Error("a broken connection accepted another call")
	}
}

func TestPolicyConversion(t *testing.T) {
	m := samplePolicy().Model()
	if got := PolicyFrom(m); !reflect.DeepEqual(got, samplePolicy()) {
		t.Errorf("round trip: %+v", got)
	}
	a, _ := model.NewAssetID(policyID, []byte("A"))
	if m.Assets[a] != 10 || !m.Destinations.Permits(model.Address{Raw: otherAddr}) {
		t.Errorf("model: %+v", m)
	}
	v := sampleSpend().Value()
	if got := SpendFrom(v); !reflect.DeepEqual(got, sampleSpend()) {
		t.Errorf("spend round trip: %+v", got)
	}
}

// TestWipe: the bodies that carry a secret wipe it through model.Wipe.
func TestWipe(t *testing.T) {
	restore := &RestoreWallet{Label: "Savings", Phrase: model.Secret("abandon abandon about")}
	shown := &RecoveryPhrase{Phrase: model.Secret("abandon abandon about")}
	completed := &Completed{Result: cborx.Raw("abandon abandon about")}
	for _, b := range []Body{restore, shown, completed} {
		model.Wipe(b)
	}
	for _, secret := range [][]byte{restore.Phrase, shown.Phrase, completed.Result} {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Errorf("not wiped: %q", secret)
		}
	}
}
