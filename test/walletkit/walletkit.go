// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Package walletkit starts a real wallet for tests and talks to it as the
// server does, on the service socket, and as the person does, on the admin
// socket. It also builds transaction bodies, canonical or not, for the tests
// that play a compromised server.
package walletkit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/walletd"
	"github.com/Liet-ada/mcpcardano/test/fidokit"
)

// Password is the password of every test wallet.
var Password = model.Secret("correct horse battery staple")

// Clock is the wallet's clock, under the test's control.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock starts at a fixed time.
func NewClock() *Clock { return &Clock{t: time.Unix(1_800_000_000, 0).UTC()} }

// RealClock starts at the real time, for a wallet that runs in its own
// process with the system's clock.
func RealClock() *Clock { return &Clock{t: time.Now()} }

// Now returns the time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// Slot is the clock's slot on preprod.
func (c *Clock) Slot() uint64 { return model.Preprod.Clock().Slot(c.Now()) }

// Wallet is a wallet process under test, in this process.
type Wallet struct {
	Config walletd.Config
	Clock  *Clock
	// Credentials stands for the directory of systemd's credentials, with
	// the key of the machine (decision 132); empty, as outside systemd.
	Credentials string

	cancel context.CancelFunc
	done   chan error
}

// NewConfig returns a development configuration in a fresh directory: the
// sockets go under /tmp, whose paths fit the 104 bytes of a Unix socket on
// macOS. Both sockets admit the test's own user.
func NewConfig(t testing.TB) walletd.Config {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "mcw-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	uid := uint32(os.Getuid())
	return walletd.Config{
		Network:         model.Preprod,
		DataDir:         filepath.Join(dir, "data"),
		ServiceSocket:   filepath.Join(dir, "run", "s.sock"),
		AdminSocket:     filepath.Join(dir, "run", "a.sock"),
		ServiceUID:      &uid,
		AdminUID:        &uid,
		Argon2MemoryMiB: 64, // the least allowed, to keep the tests quick
		Development:     true,
	}
}

// Start creates a key store and starts a wallet on it, with a clock the
// test moves.
func Start(t testing.TB) *Wallet { return StartAt(t, NewClock()) }

// StartAt is Start with the given clock: RealClock for a wallet that works
// with a server, which takes its time from the system.
func StartAt(t testing.TB, clock *Clock) *Wallet {
	t.Helper()
	cfg := NewConfig(t)
	if err := walletd.Init(cfg, Password); err != nil {
		t.Fatal(err)
	}
	w := &Wallet{Config: cfg, Clock: clock}
	w.Run(t)
	return w
}

// Run starts the wallet process on its files and waits for its sockets.
func (w *Wallet) Run(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	d, err := walletd.Open(ctx, w.Config, walletd.Options{Version: "test", Now: w.Clock.Now, Credentials: w.Credentials})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	w.cancel, w.done = cancel, make(chan error, 1)
	go func() {
		err := d.Serve(ctx)
		d.Close()
		w.done <- err
	}()
	WaitFor(t, w.Config.ServiceSocket, w.Config.AdminSocket)
	t.Cleanup(w.Stop)
}

// Stop stops the wallet process and waits for it.
func (w *Wallet) Stop() {
	if w.cancel == nil {
		return
	}
	w.cancel()
	<-w.done
	w.cancel = nil
}

// Restart stops the wallet and starts it again on the same files: what is
// in memory, the unlocked key store, sessions and approvals, is gone.
func (w *Wallet) Restart(t testing.TB) {
	t.Helper()
	w.Stop()
	w.Run(t)
}

// WaitFor waits until the sockets accept connections.
func WaitFor(t testing.TB, paths ...string) {
	t.Helper()
	for _, p := range paths {
		deadline := time.Now().Add(10 * time.Second)
		for {
			if c, err := ipc.Dial(context.Background(), p, Hello()); err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s does not answer", p)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// Hello is the test's greeting.
func Hello() ipc.Hello { return ipc.Hello{Software: "walletkit", Network: string(model.Preprod)} }

// Dial opens a connection to a socket and greets the wallet.
func Dial(t testing.TB, path string) *ipc.Client {
	t.Helper()
	c, err := ipc.Dial(context.Background(), path, Hello())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// Service connects as the server.
func (w *Wallet) Service(t testing.TB) *ipc.Client { return Dial(t, w.Config.ServiceSocket) }

// Admin connects as the person's CLI.
func (w *Wallet) Admin(t testing.TB) *ipc.Client { return Dial(t, w.Config.AdminSocket) }

// Unlock unlocks the key store.
func Unlock(t testing.TB, admin *ipc.Client) {
	t.Helper()
	if err := admin.Call(context.Background(), ipc.MsgUnlock, &ipc.Unlock{Password: Password}, &ipc.Empty{}); err != nil {
		t.Fatal(err)
	}
}

// Authorize runs an action as the person does: BeginAuthorization, then
// CompleteAuthorization with the password. It returns the summary the wallet
// showed, and decodes the action's result into result.
func Authorize(admin *ipc.Client, action string, params, result ipc.Body) ([]string, error) {
	return AuthorizeWith(admin, action, params, result, WithPassword)
}

// An Answer completes a challenge: with the password or a key's assertion.
type Answer func(*ipc.Challenge) *ipc.CompleteAuthorization

// WithPassword answers with the password.
func WithPassword(ch *ipc.Challenge) *ipc.CompleteAuthorization {
	return &ipc.CompleteAuthorization{AuthID: ch.AuthID, Password: Password}
}

// Touch answers with a touch of a software key, and its PIN if the challenge
// asks for it.
func Touch(k *fidokit.Key) Answer {
	return func(ch *ipc.Challenge) *ipc.CompleteAuthorization {
		return WithKey(k, fidokit.Options{PIN: ch.PIN})(ch)
	}
}

// WithKey answers with an assertion of a software key under exactly the
// options o, which may make it misbehave.
func WithKey(k *fidokit.Key, o fidokit.Options) Answer {
	return func(ch *ipc.Challenge) *ipc.CompleteAuthorization {
		a := k.GetAssertion(ch.ClientDataHash, o)
		return &ipc.CompleteAuthorization{AuthID: ch.AuthID,
			Assertion: &ipc.Assertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, Signature: a.Signature}}
	}
}

// AuthorizeWith runs an action and answers its challenge with answer. It
// returns the challenge, and decodes the action's result into result.
func AuthorizeWith(admin *ipc.Client, action string, params, result ipc.Body, answer Answer) ([]string, error) {
	ch, err := Begin(admin, action, params)
	if err != nil {
		return nil, err
	}
	return ch.Summary, Complete(admin, answer(ch), result)
}

// Begin opens an authorization of action.
func Begin(admin *ipc.Client, action string, params ipc.Body) (*ipc.Challenge, error) {
	raw, err := ipc.NewCodec().Encode(params)
	if err != nil {
		return nil, err
	}
	var ch ipc.Challenge
	if err := admin.Call(context.Background(), ipc.MsgBeginAuthorization, &ipc.BeginAuthorization{Action: action, Params: raw}, &ch); err != nil {
		return nil, err
	}
	return &ch, nil
}

// Complete completes an authorization and decodes the action's result into
// result.
func Complete(admin *ipc.Client, c *ipc.CompleteAuthorization, result ipc.Body) error {
	var done ipc.Completed
	if err := admin.Call(context.Background(), ipc.MsgCompleteAuthorization, c, &done); err != nil {
		return err
	}
	if result == nil {
		result = &ipc.Empty{}
	}
	return ipc.NewCodec().DecodeBody(done.Result, result)
}

// AddKey registers a software key named name, authorized with answer.
func AddKey(admin *ipc.Client, k *fidokit.Key, name string, answer Answer) error {
	_, err := AuthorizeWith(admin, ipc.ActAddKey, &ipc.AddKey{Name: name, AuthenticatorData: k.MakeCredential(fidokit.Options{})}, nil, answer)
	return err
}

// CreateWallet creates a wallet with the template, as the server does for
// the agent.
func CreateWallet(t testing.TB, service *ipc.Client, label string) ipc.Wallet {
	t.Helper()
	var created ipc.WalletCreated
	if err := service.Call(context.Background(), ipc.MsgCreateWallet, &ipc.CreateWallet{Label: label}, &created); err != nil {
		t.Fatal(err)
	}
	return created.Wallet
}

// Sign sends a SignDraft for a body and its auxiliary data.
func Sign(service *ipc.Client, wallet string, body, aux []byte) (*ipc.SignDraftResult, error) {
	draft, _ := model.NewDraftID(nil)
	var res ipc.SignDraftResult
	err := service.Call(context.Background(), ipc.MsgSignDraft,
		&ipc.SignDraft{WalletID: wallet, DraftID: string(draft), Body: body, AuxData: aux, Inputs: []ipc.ResolvedInput{}}, &res)
	return &res, err
}

// Code returns the code of a failed response, or "" if err is not one.
func Code(err error) ipc.Code {
	var e *ipc.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// codec encodes bodies; tags allowed, for the sets of Conway.
var codec = func() *cborx.Codec {
	c, err := cborx.New(cborx.Limits{MaxDepth: 64, MaxArrayElements: 1 << 16, MaxMapPairs: 1 << 16, AllowTags: true})
	if err != nil {
		panic(err)
	}
	return c
}()

// Encode encodes v canonically.
func Encode(t testing.TB, v any) []byte {
	t.Helper()
	b, err := codec.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Set is a Conway set: an array with tag 258.
func Set(items ...any) cborx.Tag {
	if items == nil {
		items = []any{}
	}
	return cborx.Tag{Number: 258, Content: items}
}

// Address returns the bytes of a preprod address of type typ (CIP-19), with
// the given payment and, for a base address, stake credential bytes.
func Address(typ byte, pay, stake byte) []byte {
	raw := append([]byte{typ << 4}, bytes.Repeat([]byte{pay}, 28)...)
	if typ <= 3 {
		raw = append(raw, bytes.Repeat([]byte{stake}, 28)...)
	}
	return raw
}

// Payment is a body that pays lovelace to a destination, with change to the
// wallet, valid for ten minutes from the clock: what txbuild writes.
func Payment(wallet, to []byte, lovelace uint64, clock *Clock) map[uint64]any {
	return map[uint64]any{
		0: Set([]any{bytes.Repeat([]byte{0xee}, 32), uint64(0)}),
		1: []any{[]any{to, lovelace}, []any{wallet, uint64(50_000_000)}},
		2: uint64(170_000),
		3: clock.Slot() + 600,
	}
}

// Build compiles the wallet binary with the given build tags into a
// temporary directory, for the tests that kill it.
func Build(t testing.TB, tags ...string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "mcpcardano-wallet")
	args := []string{"build", "-o", bin}
	if len(tags) > 0 {
		args = append(args, "-tags", joinTags(tags))
	}
	args = append(args, "github.com/Liet-ada/mcpcardano/cmd/mcpcardano-wallet")
	cmd := exec.Command("go", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func joinTags(tags []string) string {
	var b bytes.Buffer
	for i, t := range tags {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(t)
	}
	return b.String()
}
