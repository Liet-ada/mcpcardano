// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/walletd"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

var ctx = context.Background()

// signed fails unless the result is a signature of body by the wallet's
// payment key: Ed25519 over the hash of the body, with a key whose hash is the
// payment credential of the wallet's address.
func signed(t *testing.T, res *ipc.SignDraftResult, err error, w ipc.Wallet, body []byte) ipc.Witness {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != ipc.Signed || len(res.Witnesses) != 1 {
		t.Fatalf("got %+v", res)
	}
	wit := res.Witnesses[0]
	id := blake2b.Sum256(body)
	if !ed25519.Verify(wit.VKey, id[:], wit.Signature) {
		t.Fatal("the signature does not verify")
	}
	h, _ := blake2b.New(28, nil)
	h.Write(wit.VKey)
	if !bytes.Equal(h.Sum(nil), w.Address[1:29]) {
		t.Fatal("the key is not the wallet's payment key")
	}
	return wit
}

func TestSignInModeC(t *testing.T) {
	w := walletkit.Start(t)
	admin, service := w.Admin(t), w.Service(t)
	walletkit.Unlock(t, admin)
	wallet := walletkit.CreateWallet(t, service, "agent")
	if wallet.Mode != "C" || wallet.CreatedBy != "agent" || wallet.Network != "preprod" {
		t.Fatalf("wallet %+v", wallet)
	}

	body := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 7, 0), 5_000_000, w.Clock))
	res, err := walletkit.Sign(service, wallet.ID, body, nil)
	wit := signed(t, res, err, wallet, body)
	if res.Spend.Lovelace != 5_170_000 {
		t.Errorf("spend %+v", res.Spend)
	}

	// The counts of the windows, and which destinations of a next draft the
	// record knows: the one just paid, not another.
	paid, other := walletkit.Address(6, 7, 0), walletkit.Address(6, 8, 0)
	var ps ipc.PolicyStatus
	req := &ipc.GetPolicyStatus{WalletID: wallet.ID, Destinations: [][]byte{paid, other}}
	if err := service.Call(ctx, ipc.MsgGetPolicyStatus, req, &ps); err != nil {
		t.Fatal(err)
	}
	if ps.SpentHour != 5_170_000 || ps.BudgetRemaining != 100_000_000-5_170_000 || len(ps.Pending) != 1 {
		t.Errorf("policy status %+v", ps)
	}
	if ps.TxHour != 1 || ps.NewDestinationsHour != 1 || ps.NewDestinationsDay != 1 || !slices.EqualFunc(ps.Known, [][]byte{paid}, bytes.Equal) {
		t.Errorf("counts %d, %d and %d, known %x", ps.TxHour, ps.NewDestinationsHour, ps.NewDestinationsDay, ps.Known)
	}

	// The same body again: the same signature, counted once (M-13).
	res, err = walletkit.Sign(service, wallet.ID, body, nil)
	if again := signed(t, res, err, wallet, body); !bytes.Equal(again.Signature, wit.Signature) {
		t.Error("another signature for the same body")
	}
	ps = ipc.PolicyStatus{}
	service.Call(ctx, ipc.MsgGetPolicyStatus, &ipc.GetPolicyStatus{WalletID: wallet.ID}, &ps)
	if ps.SpentHour != 5_170_000 || ps.TxHour != 1 || ps.Known != nil {
		t.Errorf("counted twice: %d lovelace, %d transactions; known %x", ps.SpentHour, ps.TxHour, ps.Known)
	}
}

// setup starts a wallet, unlocks it and creates one wallet with the template.
func setup(t *testing.T) (*walletkit.Wallet, *ipc.Client, *ipc.Client, ipc.Wallet) {
	t.Helper()
	w := walletkit.Start(t)
	admin, service := w.Admin(t), w.Service(t)
	walletkit.Unlock(t, admin)
	return w, admin, service, walletkit.CreateWallet(t, service, "agent")
}

func TestOpen(t *testing.T) {
	cfg := walletkit.NewConfig(t)
	if _, err := walletd.Open(ctx, cfg, walletd.Options{}); err == nil {
		t.Error("a wallet without a key store started")
	}
	if err := walletd.Init(cfg, walletkit.Password); err != nil {
		t.Fatal(err)
	}
	if err := walletd.Init(cfg, walletkit.Password); err == nil {
		t.Error("init replaced a key store")
	}
	os.Chmod(cfg.DataDir, 0o755)
	if _, err := walletd.Open(ctx, cfg, walletd.Options{}); !errors.Is(err, walletd.ErrPermissions) {
		t.Errorf("an open data directory: %v", err)
	}
	os.Chmod(cfg.DataDir, 0o700)

	bad := []func(*walletd.Config){
		func(c *walletd.Config) { c.Network = "mainnet" },
		func(c *walletd.Config) { c.Network = "testnet" },
		func(c *walletd.Config) { c.DataDir = "data" },
		func(c *walletd.Config) { c.AdminSocket = c.ServiceSocket },
		func(c *walletd.Config) { c.ServiceUID = nil },
		func(c *walletd.Config) { c.Argon2MemoryMiB = 32 },
	}
	for i, change := range bad {
		c := cfg
		change(&c)
		if err := c.Check(); !errors.Is(err, walletd.ErrConfig) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	write := func(s string) {
		os.WriteFile(path, []byte(s), 0o600)
	}
	write(`{"network": "preprod", "data_dir": "/var/lib/w", "service_socket": "/run/m/s.sock",
		"admin_socket": "/run/m/a.sock", "service_uid": 990, "admin_uid": 1000}`)
	c, err := walletd.LoadConfig(path)
	if err != nil || *c.ServiceUID != 990 || c.KeystoreParams().MemoryKiB != 256<<10 {
		t.Fatalf("got %+v, %v", c, err)
	}
	write(`{"network": "preprod", "unknown": 1}`)
	if _, err := walletd.LoadConfig(path); !errors.Is(err, walletd.ErrConfig) {
		t.Errorf("an unknown field: %v", err)
	}
	write(`{"network": "preprod", "data_dir": "/var/lib/w", "service_socket": "/run/m/s.sock",
		"admin_socket": "/run/m/a.sock", "service_uid": 990, "admin_uid": 1000} {}`)
	if _, err := walletd.LoadConfig(path); !errors.Is(err, walletd.ErrConfig) {
		t.Errorf("data after the configuration: %v", err)
	}
}

// raw sends one request on a new connection and returns the wallet's answer
// as it comes, without the checks of ipc.Client, and whether the wallet then
// closed the connection.
func raw(t *testing.T, path, typ string, req, resp ipc.Body) (closed bool, err error) {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := ipc.NewCodec()
	id := bytes.Repeat([]byte{1}, ipc.IDSize)
	frame, _ := c.EncodeRequest(typ, id, req)
	ipc.WriteFrame(conn, frame, ipc.DefaultConnLimits())
	reply, err := ipc.ReadFrame(conn, ipc.DefaultConnLimits())
	if err != nil {
		t.Fatal(err)
	}
	_, again := ipc.ReadFrame(conn, ipc.ConnLimits{MaxMessageSize: 1 << 20, Receive: time.Second, Idle: time.Second})
	return again != nil, c.DecodeResponse(reply, id, resp)
}

func TestConnections(t *testing.T) {
	w := walletkit.Start(t)
	other := walletkit.Hello()
	other.Network = "preview"
	closed, err := raw(t, w.Config.ServiceSocket, ipc.MsgHello, &other, &ipc.Hello{})
	if walletkit.Code(err) != ipc.NetworkMismatch || !closed {
		t.Errorf("a Hello of another network: %v, closed %v", err, closed)
	}
	closed, err = raw(t, w.Config.ServiceSocket, ipc.MsgPing, &ipc.Empty{}, &ipc.PingResult{})
	if walletkit.Code(err) != ipc.Malformed || !closed {
		t.Errorf("a request before Hello: %v, closed %v", err, closed)
	}

	// A message of the other socket.
	admin := w.Admin(t)
	if _, err := walletkit.Sign(admin, "w_x", []byte{0}, nil); walletkit.Code(err) != ipc.Malformed {
		t.Errorf("SignDraft on the admin socket: %v", err)
	}

	// At most four connections on the service socket; a fifth is closed.
	for range ipc.MaxServiceConns {
		w.Service(t)
	}
	if c, err := ipc.Dial(ctx, w.Config.ServiceSocket, walletkit.Hello()); err == nil {
		c.Close()
		t.Error("a fifth connection was served")
	}
}

// TestPeerUser: the kernel certifies the user at the other end, and only the
// configured one stays (section 5.1).
func TestPeerUser(t *testing.T) {
	cfg := walletkit.NewConfig(t)
	someone := uint32(os.Getuid()) + 1
	cfg.AdminUID = &someone
	walletd.Init(cfg, walletkit.Password)
	w := &walletkit.Wallet{Config: cfg, Clock: walletkit.NewClock()}
	ctx, cancel := context.WithCancel(ctx)
	d, err := walletd.Open(ctx, cfg, walletd.Options{Now: w.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { d.Serve(ctx); d.Close(); close(done) }()
	defer func() { cancel(); <-done }()
	walletkit.WaitFor(t, cfg.ServiceSocket)
	if c, err := ipc.Dial(ctx, cfg.AdminSocket, walletkit.Hello()); err == nil {
		c.Close()
		t.Error("another user was served on the admin socket")
	}
}

func TestLockedAndUnlock(t *testing.T) {
	w := walletkit.Start(t)
	admin, service := w.Admin(t), w.Service(t)
	if err := service.Call(ctx, ipc.MsgCreateWallet, &ipc.CreateWallet{Label: "x"}, &ipc.WalletCreated{}); walletkit.Code(err) != ipc.Locked {
		t.Errorf("CreateWallet while locked: %v", err)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActCreateWallet, &ipc.CreateWallet{Label: "x"}, nil); walletkit.Code(err) != ipc.Locked {
		t.Errorf("an authorization while locked: %v", err)
	}
	var st ipc.StatusReport
	if admin.Call(ctx, ipc.MsgStatus, &ipc.Empty{}, &st); st.Unlocked {
		t.Error("unlocked before Unlock")
	}

	wrong := &ipc.Unlock{Password: []byte("wrong password")}
	if err := admin.Call(ctx, ipc.MsgUnlock, wrong, &ipc.Empty{}); walletkit.Code(err) != ipc.AuthFailed {
		t.Errorf("a wrong password: %v", err)
	}
	// The wait doubles after each wrong password, for Unlock too.
	if err := admin.Call(ctx, ipc.MsgUnlock, &ipc.Unlock{Password: walletkit.Password}, &ipc.Empty{}); walletkit.Code(err) != ipc.RateLimited {
		t.Errorf("within the wait: %v", err)
	}
	w.Clock.Advance(2 * time.Second)
	walletkit.Unlock(t, admin)
	if admin.Call(ctx, ipc.MsgStatus, &ipc.Empty{}, &st); !st.Unlocked {
		t.Error("still locked")
	}
	wallet := walletkit.CreateWallet(t, service, "agent")

	// A restart locks it again: SignDraft waits for the person (decision 110).
	w.Restart(t)
	service = w.Service(t)
	body := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 7, 0), 5_000_000, w.Clock))
	if _, err := walletkit.Sign(service, wallet.ID, body, nil); walletkit.Code(err) != ipc.Locked {
		t.Errorf("SignDraft after a restart: %v", err)
	}
}

func TestCreateWallet(t *testing.T) {
	w, admin, service, first := setup(t)
	var again ipc.WalletCreated
	key := &ipc.CreateWallet{Label: "with key", IdempotencyKey: "k1"}
	service.Call(ctx, ipc.MsgCreateWallet, key, &again)
	w.Restart(t)
	admin, service = w.Admin(t), w.Service(t)
	walletkit.Unlock(t, admin)
	var repeated ipc.WalletCreated
	if err := service.Call(ctx, ipc.MsgCreateWallet, key, &repeated); err != nil || repeated.Wallet.ID != again.Wallet.ID {
		t.Fatalf("the same key after a restart: %+v, %v", repeated, err)
	}
	var list ipc.WalletList
	service.Call(ctx, ipc.MsgListWallets, &ipc.Empty{}, &list)
	if len(list.Wallets) != 2 || list.Wallets[0].ID != first.ID || bytes.Equal(list.Wallets[0].Address, list.Wallets[1].Address) {
		t.Errorf("wallets %+v", list.Wallets)
	}
	// The person creates one too, with an authorization.
	var person ipc.Wallet
	if _, err := walletkit.Authorize(admin, ipc.ActCreateWallet, &ipc.CreateWallet{Label: "mine"}, &person); err != nil || person.CreatedBy != "person" {
		t.Fatalf("got %+v, %v", person, err)
	}
	// Status marks the open destinations of the template (section 3.7).
	var st ipc.StatusReport
	admin.Call(ctx, ipc.MsgStatus, &ipc.Empty{}, &st)
	if len(st.Wallets) != 3 || !st.Wallets[0].OpenDestinations || st.LastLedgerEntry == 0 {
		t.Errorf("status %+v", st)
	}
}

func TestRejections(t *testing.T) {
	w, admin, service, wallet := setup(t)
	shop := walletkit.Address(6, 7, 0)
	pay := func(lovelace uint64) map[uint64]any {
		return walletkit.Payment(wallet.Address, shop, lovelace, w.Clock)
	}
	rejectedWith := func(name string, body []byte, code ipc.Code) *ipc.SignDraftResult {
		t.Helper()
		res, err := walletkit.Sign(service, wallet.ID, body, nil)
		if err != nil || res.Status != ipc.Rejected || res.Rejection.Code != code {
			t.Errorf("%s: got %+v, %v", name, res, err)
		}
		return res
	}

	body := walletkit.Encode(t, pay(5_000_000))
	rejectedWith("not canonical", append([]byte{0xd8, 0x18}, body...), ipc.TxNotCanonical)
	certs := pay(5_000_000)
	certs[4] = []any{}
	rejectedWith("a certificate", walletkit.Encode(t, certs), ipc.TxUnsupportedField)
	res := rejectedWith("over the limit per transaction", walletkit.Encode(t, pay(30_000_000)), ipc.BudgetExceeded)
	if res.Spend.Lovelace != 30_170_000 || !strings.Contains(res.Rejection.Detail, "limits.per_tx") {
		t.Errorf("the rejection does not carry the spend and the rule: %+v", res)
	}
	long := pay(5_000_000)
	long[3] = w.Clock.Slot() + 3*3600
	rejectedWith("TTL beyond the maximum", walletkit.Encode(t, long), ipc.TTLTooLong)
	mainnet := walletkit.Payment(wallet.Address, append([]byte{0x61}, shop[1:]...), 5_000_000, w.Clock)
	res = rejectedWith("another network", walletkit.Encode(t, mainnet), ipc.PolicyBlocked)
	if !strings.HasPrefix(res.Rejection.Detail, "network") {
		t.Errorf("detail %q", res.Rejection.Detail)
	}
	if _, err := walletkit.Sign(service, "w_aaaaaaaaaaaaaaaaaaaaaaaaaa", body, nil); walletkit.Code(err) != ipc.UnknownWallet {
		t.Errorf("an unknown wallet: %v", err)
	}

	if err := admin.Call(ctx, ipc.MsgFreeze, &ipc.Freeze{}, &ipc.Empty{}); err != nil {
		t.Fatal(err)
	}
	var ping ipc.PingResult
	if service.Call(ctx, ipc.MsgPing, &ipc.Empty{}, &ping); !ping.AnyFrozen || ping.Slot != w.Clock.Slot() {
		t.Errorf("ping %+v", ping)
	}
	rejectedWith("frozen", body, ipc.Frozen)
	if _, err := walletkit.Authorize(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID}, nil); err != nil {
		t.Fatal(err)
	}
	res, err := walletkit.Sign(service, wallet.ID, body, nil)
	signed(t, res, err, wallet, body)
}

func TestModeBApproval(t *testing.T) {
	w, admin, service, wallet := setup(t)
	var tpl ipc.Template
	admin.Call(ctx, ipc.MsgShowTemplate, &ipc.Empty{}, &tpl)
	pol := tpl.Policy
	pol.Limits.ApprovalThreshold = 1_000_000
	summary, err := walletkit.Authorize(admin, ipc.ActChangePolicy, &ipc.WalletPolicy{WalletID: wallet.ID, Mode: "B", Policy: pol}, &ipc.PolicyHash{})
	if err != nil || !strings.Contains(strings.Join(summary, "\n"), "Mode B") {
		t.Fatalf("change_policy: %q, %v", summary, err)
	}

	body := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 7, 0), 5_000_000, w.Clock))
	res, err := walletkit.Sign(service, wallet.ID, body, nil)
	if err != nil || res.Status != ipc.PendingApproval {
		t.Fatalf("got %+v, %v", res, err)
	}
	if again, _ := walletkit.Sign(service, wallet.ID, body, nil); again.ApprovalID != res.ApprovalID {
		t.Errorf("the same body gave another approval: %s", again.ApprovalID)
	}
	var st ipc.StatusReport
	if admin.Call(ctx, ipc.MsgStatus, &ipc.Empty{}, &st); len(st.Approvals) != 1 || st.Approvals[0].ID != res.ApprovalID {
		t.Errorf("status approvals %+v", st.Approvals)
	}
	summary, err = walletkit.Authorize(admin, ipc.ActApproveDraft, &ipc.ApproveDraft{ApprovalID: res.ApprovalID}, nil)
	text := strings.Join(summary, "\n")
	if err != nil || !strings.Contains(text, "5.000000 ADA to addr_test1") || !strings.Contains(text, "Spend: 5.170000 ADA") {
		t.Fatalf("approve: %v\n%s", err, text)
	}
	var as ipc.ApprovalStatus
	service.Call(ctx, ipc.MsgGetApprovalStatus, &ipc.GetApprovalStatus{ApprovalID: res.ApprovalID}, &as)
	if as.Status != ipc.ApprovalApproved || len(as.Witnesses) != 1 {
		t.Fatalf("approval %+v", as)
	}
	res, err = walletkit.Sign(service, wallet.ID, body, nil)
	if wit := signed(t, res, err, wallet, body); !bytes.Equal(wit.Signature, as.Witnesses[0].Signature) {
		t.Error("another signature after the approval")
	}

	// A rejected approval cannot be approved.
	other := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 8, 0), 4_000_000, w.Clock))
	res, _ = walletkit.Sign(service, wallet.ID, other, nil)
	if err := admin.Call(ctx, ipc.MsgReject, &ipc.ApprovalRef{ApprovalID: res.ApprovalID}, &ipc.Empty{}); err != nil {
		t.Fatal(err)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActApproveDraft, &ipc.ApproveDraft{ApprovalID: res.ApprovalID}, nil); walletkit.Code(err) != ipc.NotFound {
		t.Errorf("approving a rejected approval: %v", err)
	}

	// The approval lifts only the threshold: a wallet frozen meanwhile ends
	// the approval rejected.
	third := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 9, 0), 3_000_000, w.Clock))
	res, _ = walletkit.Sign(service, wallet.ID, third, nil)
	admin.Call(ctx, ipc.MsgFreeze, &ipc.Freeze{WalletID: wallet.ID}, &ipc.Empty{})
	if _, err := walletkit.Authorize(admin, ipc.ActApproveDraft, &ipc.ApproveDraft{ApprovalID: res.ApprovalID}, nil); walletkit.Code(err) != ipc.Frozen {
		t.Errorf("approving for a frozen wallet: %v", err)
	}
	service.Call(ctx, ipc.MsgGetApprovalStatus, &ipc.GetApprovalStatus{ApprovalID: res.ApprovalID}, &as)
	if as.Status != ipc.ApprovalRejected {
		t.Errorf("status %s", as.Status)
	}

	// An approval expires with the TTL of its transaction.
	walletkit.Authorize(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: wallet.ID}, nil)
	fourth := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 10, 0), 2_000_000, w.Clock))
	res, _ = walletkit.Sign(service, wallet.ID, fourth, nil)
	w.Clock.Advance(11 * time.Minute)
	service.Call(ctx, ipc.MsgGetApprovalStatus, &ipc.GetApprovalStatus{ApprovalID: res.ApprovalID}, &as)
	if as.Status != ipc.ApprovalExpired {
		t.Errorf("status %s after the TTL", as.Status)
	}
}

func TestSession(t *testing.T) {
	w, admin, service, wallet := setup(t)
	var pol ipc.WalletPolicy
	admin.Call(ctx, ipc.MsgShowPolicy, &ipc.WalletRef{WalletID: wallet.ID}, &pol)
	pol.Policy.SessionRequired = true
	if _, err := walletkit.Authorize(admin, ipc.ActChangePolicy, &pol, &ipc.PolicyHash{}); err != nil {
		t.Fatal(err)
	}
	n := byte(10)
	pay := func(lovelace uint64) ([]byte, *ipc.SignDraftResult, error) {
		n++
		body := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, n, 0), lovelace, w.Clock))
		res, err := walletkit.Sign(service, wallet.ID, body, nil)
		return body, res, err
	}
	needsSession := func(name string, res *ipc.SignDraftResult, err error) {
		t.Helper()
		if err != nil || res.Status != ipc.Rejected || res.Rejection.Code != ipc.NeedsSession {
			t.Errorf("%s: %+v, %v", name, res, err)
		}
	}
	_, res, err := pay(1_000_000)
	needsSession("without a session", res, err)

	open := &ipc.OpenSession{WalletID: wallet.ID, Seconds: 3600, MaxLovelace: 10_000_000}
	if _, err := walletkit.Authorize(admin, ipc.ActOpenSession, open, nil); err != nil {
		t.Fatal(err)
	}
	body, res, err := pay(5_000_000)
	signed(t, res, err, wallet, body)
	var ps ipc.PolicyStatus
	if service.Call(ctx, ipc.MsgGetPolicyStatus, &ipc.GetPolicyStatus{WalletID: wallet.ID}, &ps); ps.Session == nil || ps.Session.Remaining != 10_000_000-5_170_000 {
		t.Errorf("session %+v", ps.Session)
	}
	_, res, err = pay(5_000_000)
	needsSession("beyond what the session allows", res, err)

	admin.Call(ctx, ipc.MsgCloseSession, &ipc.WalletRef{WalletID: wallet.ID}, &ipc.Empty{})
	_, res, err = pay(1_000_000)
	needsSession("after closing it", res, err)

	walletkit.Authorize(admin, ipc.ActOpenSession, open, nil)
	w.Clock.Advance(time.Hour)
	_, res, err = pay(1_000_000)
	needsSession("after it ended", res, err)
}

func TestReleaseAndBudget(t *testing.T) {
	w, admin, service, wallet := setup(t)
	body := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 7, 0), 5_000_000, w.Clock))
	res, err := walletkit.Sign(service, wallet.ID, body, nil)
	signed(t, res, err, wallet, body)
	id := blake2b.Sum256(body)
	release := &ipc.ReleaseBudget{WalletID: wallet.ID, Entries: [][]byte{id[:]}}
	if _, err := walletkit.Authorize(admin, ipc.ActReleaseBudget, release, &ipc.Released{}); walletkit.Code(err) != ipc.NotFound {
		t.Errorf("releasing before the TTL: %v", err)
	}

	w.Clock.Advance(11 * time.Minute)
	var exp ipc.ExpiredList
	if admin.Call(ctx, ipc.MsgListExpired, &ipc.ListExpired{}, &exp); len(exp.Entries) != 1 || exp.Entries[0].Spend.Lovelace != 5_170_000 {
		t.Fatalf("expired %+v", exp)
	}
	var rel ipc.Released
	summary, err := walletkit.Authorize(admin, ipc.ActReleaseBudget, release, &rel)
	if err != nil || rel.Lovelace != 5_170_000 || !strings.Contains(summary[0], "5.170000 ADA") {
		t.Fatalf("release: %+v, %q, %v", rel, summary, err)
	}
	var ps ipc.PolicyStatus
	service.Call(ctx, ipc.MsgGetPolicyStatus, &ipc.GetPolicyStatus{WalletID: wallet.ID}, &ps)
	if ps.BudgetRemaining != 100_000_000 || len(ps.Pending) != 0 {
		t.Errorf("after the release %+v", ps)
	}

	// A new budget counts from now (section 8.5).
	body = walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 8, 0), 5_000_000, w.Clock))
	walletkit.Sign(service, wallet.ID, body, nil)
	var pol ipc.WalletPolicy
	admin.Call(ctx, ipc.MsgShowPolicy, &ipc.WalletRef{WalletID: wallet.ID}, &pol)
	pol.Policy.Limits.Budget = 50_000_000
	walletkit.Authorize(admin, ipc.ActChangePolicy, &pol, &ipc.PolicyHash{})
	service.Call(ctx, ipc.MsgGetPolicyStatus, &ipc.GetPolicyStatus{WalletID: wallet.ID}, &ps)
	if ps.BudgetRemaining != 50_000_000 || ps.SpentHour != 5_170_000 {
		t.Errorf("after a new budget %+v", ps)
	}
}

func TestRecoveryPhrase(t *testing.T) {
	_, admin, _, wallet := setup(t)
	var rp ipc.RecoveryPhrase
	summary, err := walletkit.Authorize(admin, ipc.ActShowRecoveryPhrase, &ipc.WalletRef{WalletID: wallet.ID}, &rp)
	if err != nil || len(bytes.Fields(rp.Phrase)) != 24 || !strings.Contains(summary[0], "recovery phrase") {
		t.Fatalf("phrase: %d words, %q, %v", len(bytes.Fields(rp.Phrase)), summary, err)
	}
	restore := &ipc.RestoreWallet{Label: "restored", Phrase: rp.Phrase}
	if _, err := walletkit.Authorize(admin, ipc.ActRestoreWallet, restore, &ipc.Wallet{}); walletkit.Code(err) != ipc.Malformed {
		t.Errorf("restoring a wallet it has: %v", err)
	}

	// Another wallet process restores it with the same address.
	w2 := walletkit.Start(t)
	admin2 := w2.Admin(t)
	walletkit.Unlock(t, admin2)
	var restored ipc.Wallet
	summary, err = walletkit.Authorize(admin2, ipc.ActRestoreWallet, restore, &restored)
	if err != nil || !bytes.Equal(restored.Address, wallet.Address) || restored.CreatedBy != "person" {
		t.Fatalf("restored %+v, %v", restored, err)
	}
	if !strings.HasPrefix(summary[1], "Address: addr_test1q") {
		t.Errorf("summary %q", summary)
	}
	bad := &ipc.RestoreWallet{Label: "x", Phrase: []byte("not a phrase at all")}
	if _, err := walletkit.Authorize(admin2, ipc.ActRestoreWallet, bad, &ipc.Wallet{}); walletkit.Code(err) != ipc.Malformed {
		t.Errorf("an invalid phrase: %v", err)
	}
}

func TestAuthorizationErrors(t *testing.T) {
	w, admin, _, wallet := setup(t)
	raw, _ := ipc.NewCodec().Encode(&ipc.WalletRef{WalletID: wallet.ID})
	var ch ipc.Challenge
	if err := admin.Call(ctx, ipc.MsgBeginAuthorization, &ipc.BeginAuthorization{Action: ipc.ActUnfreeze, Params: raw}, &ch); err != nil {
		t.Fatal(err)
	}
	wrong := &ipc.CompleteAuthorization{AuthID: ch.AuthID, Password: []byte("wrong password")}
	if err := admin.Call(ctx, ipc.MsgCompleteAuthorization, wrong, &ipc.Completed{}); walletkit.Code(err) != ipc.AuthFailed {
		t.Errorf("a wrong password: %v", err)
	}
	w.Clock.Advance(6 * time.Minute) // past the wait and the authorization
	right := &ipc.CompleteAuthorization{AuthID: ch.AuthID, Password: walletkit.Password}
	if err := admin.Call(ctx, ipc.MsgCompleteAuthorization, right, &ipc.Completed{}); walletkit.Code(err) != ipc.AuthExpired {
		t.Errorf("an expired authorization: %v", err)
	}
	if _, err := walletkit.Authorize(admin, ipc.ActUnfreeze, &ipc.WalletRef{WalletID: "w_aaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil); walletkit.Code(err) != ipc.UnknownWallet {
		t.Errorf("an unknown wallet: %v", err)
	}
}

func TestAudit(t *testing.T) {
	_, admin, service, wallet := setup(t)
	walletkit.Sign(service, wallet.ID, []byte{0xa0}, nil)
	var check ipc.AuditCheck
	if err := admin.Call(ctx, ipc.MsgVerifyAudit, &ipc.Empty{}, &check); err != nil || check.AuditEntries < 4 || check.LedgerEntries != 1 {
		t.Fatalf("verify: %+v, %v", check, err)
	}
	var page ipc.AuditPage
	if err := admin.Call(ctx, ipc.MsgShowAudit, &ipc.ShowAudit{From: 1, Limit: 2}, &page); err != nil || len(page.Entries) != 2 || page.Next != 3 {
		t.Fatalf("page: %d entries, next %d, %v", len(page.Entries), page.Next, err)
	}
	records, _ := cborx.New(cborx.RecordLimits())
	var types []string
	for from := uint64(1); from != 0; {
		admin.Call(ctx, ipc.MsgShowAudit, &ipc.ShowAudit{From: from, Limit: 100}, &page)
		for _, raw := range page.Entries {
			var e audit.Entry
			if err := records.Unmarshal(raw, &e); err != nil {
				t.Fatal(err)
			}
			types = append(types, e.Type)
		}
		from = page.Next
	}
	for _, want := range []string{"start", "unlock", "wallet.created", "sign_draft"} {
		if !slices.Contains(types, want) {
			t.Errorf("no %s in the audit log: %v", want, types)
		}
	}
}

// TestIsolationCheck: outside development mode, a wallet with network does
// not serve (section 10.3). The machine that runs the tests has network.
func TestIsolationCheck(t *testing.T) {
	cfg := walletkit.NewConfig(t)
	cfg.Development = false
	if err := walletd.Init(cfg, walletkit.Password); err != nil {
		t.Fatal(err)
	}
	d, err := walletd.Open(ctx, cfg, walletd.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := d.Serve(ctx); !errors.Is(err, walletd.ErrNotIsolated) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(cfg.ServiceSocket); err == nil {
		t.Error("the socket was created")
	}
}

// TestTamperedAddress: a wallet signs only if the key of its seed gives the
// address its state names. Whoever swapped the address in state.cbor would
// have the policy count the wrong outputs as own.
func TestTamperedAddress(t *testing.T) {
	w, _, _, wallet := setup(t)
	w.Stop()
	path := filepath.Join(w.Config.DataDir, "state.cbor")
	data, _ := os.ReadFile(path)
	other := bytes.Clone(wallet.Address)
	other[1] ^= 0xff
	os.WriteFile(path, bytes.Replace(data, wallet.Address, other, 1), 0o600)
	w.Run(t)
	admin, service := w.Admin(t), w.Service(t)
	walletkit.Unlock(t, admin)
	body := walletkit.Encode(t, walletkit.Payment(other, walletkit.Address(6, 7, 0), 5_000_000, w.Clock))
	if _, err := walletkit.Sign(service, wallet.ID, body, nil); walletkit.Code(err) != ipc.Internal {
		t.Fatalf("got %v", err)
	}
}
