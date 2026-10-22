// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package wallet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/ledger"
	"github.com/Liet-ada/mcpcardano/internal/walletd"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

// crashBinary is the wallet built with the crashtest tag, once per run.
var crashBinary = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "mcw-bin-")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "mcpcardano-wallet")
	out, err := exec.Command("go", "build", "-tags", "crashtest", "-o", bin,
		"github.com/Liet-ada/mcpcardano/cmd/mcpcardano-wallet").CombinedOutput()
	if err != nil {
		return "", errors.New(string(out))
	}
	return bin, nil
})

// process is the real wallet binary, run as its own process.
type process struct {
	bin, config string
	cfg         walletd.Config
	cmd         *exec.Cmd
	exited      chan error
}

func newProcess(t *testing.T) *process {
	t.Helper()
	bin, err := crashBinary()
	if err != nil {
		t.Fatalf("building the wallet: %v", err)
	}
	cfg := walletkit.NewConfig(t)
	data, _ := json.Marshal(cfg)
	p := &process{bin: bin, config: filepath.Join(filepath.Dir(cfg.DataDir), "config.json"), cfg: cfg}
	if err := os.WriteFile(p.config, data, 0o600); err != nil {
		t.Fatal(err)
	}
	init := exec.Command(bin, "-config", p.config, "init")
	init.Stdin = strings.NewReader(string(walletkit.Password) + "\n")
	if out, err := init.CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	return p
}

// start runs the wallet, killing itself at crashAt if not empty, and waits
// for its sockets.
func (p *process) start(t *testing.T, crashAt string) {
	t.Helper()
	cmd := exec.Command(p.bin, "-config", p.config)
	cmd.Env = append(os.Environ(), "MCPCARDANO_WALLET_CRASH="+crashAt)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		cmd.Process.Kill()
		select {
		case err := <-exited:
			exited <- err
		case <-time.After(10 * time.Second):
		}
	})
	p.cmd, p.exited = cmd, exited
	walletkit.WaitFor(t, p.cfg.ServiceSocket, p.cfg.AdminSocket)
}

// killed waits for the process to die by SIGKILL, as its crash point does.
func (p *process) killed(t *testing.T) {
	t.Helper()
	select {
	case err := <-p.exited:
		p.exited <- err // for the cleanup
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
			t.Fatalf("the wallet did not die by SIGKILL: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the wallet did not die")
	}
}

// entries reads the spending record's entry types, from outside.
func (p *process) entries(t *testing.T) []string {
	t.Helper()
	es, _, err := audit.Read(context.Background(), filepath.Join(p.cfg.DataDir, "ledger.log"), audit.Options{Kind: ledger.Kind})
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, e := range es[1:] {
		types = append(types, e.Type)
	}
	return types
}

// TestCrashWhileSigning kills the wallet at each point of section 9.1 and
// checks the table of that section after a restart. In every case the
// server never got a signature before the crash, the spend is on disk if and
// only if the reservation was written, and a repeated request gets the
// signature and counts the spend once: no signature leaves the wallet
// without its spend on disk.
func TestCrashWhileSigning(t *testing.T) {
	const spend = 5_170_000
	cases := []struct {
		point   string
		spent   uint64   // after the restart, before the request is repeated
		entries []string // written before the crash
	}{
		{"before-reserve", 0, nil},
		{"after-reserve", spend, []string{ledger.TypeReserved}},
		{"after-sign", spend, []string{ledger.TypeReserved, ledger.TypeSigned}},
	}
	for _, c := range cases {
		t.Run(c.point, func(t *testing.T) {
			p := newProcess(t)
			p.start(t, c.point)
			admin := walletkit.Dial(t, p.cfg.AdminSocket)
			walletkit.Unlock(t, admin)
			service := walletkit.Dial(t, p.cfg.ServiceSocket)
			wallet := walletkit.CreateWallet(t, service, "agent")
			body := walletkit.Encode(t, walletkit.Payment(wallet.Address, walletkit.Address(6, 7, 0), 5_000_000, walletkit.RealClock()))

			if res, err := walletkit.Sign(service, wallet.ID, body, nil); err == nil {
				t.Fatalf("the wallet answered before dying: %+v", res)
			}
			p.killed(t)
			if got := p.entries(t); !slices(got, c.entries) {
				t.Fatalf("record after the crash: %v, want %v", got, c.entries)
			}

			p.start(t, "")
			admin = walletkit.Dial(t, p.cfg.AdminSocket)
			walletkit.Unlock(t, admin)
			service = walletkit.Dial(t, p.cfg.ServiceSocket)
			if got := spentHour(t, service, wallet.ID); got != c.spent {
				t.Fatalf("spent after the restart: %d, want %d", got, c.spent)
			}
			res, err := walletkit.Sign(service, wallet.ID, body, nil)
			if err != nil || res.Status != ipc.Signed {
				t.Fatalf("the repeated request: %+v, %v", res, err)
			}
			id := blake2b.Sum256(body)
			if !ed25519.Verify(res.Witnesses[0].VKey, id[:], res.Witnesses[0].Signature) {
				t.Fatal("the signature does not verify")
			}
			if got := spentHour(t, service, wallet.ID); got != spend {
				t.Errorf("spent after the repeated request: %d, want %d once", got, spend)
			}
			if got := p.entries(t); !slices(got, []string{ledger.TypeReserved, ledger.TypeSigned}) {
				t.Errorf("record at the end: %v", got)
			}
			// The signature on disk is the one the server got.
			l, _, err := audit.Read(context.Background(), filepath.Join(p.cfg.DataDir, "ledger.log"), audit.Options{Kind: ledger.Kind})
			if err != nil || !bytes.Contains(l[len(l)-1].Body, res.Witnesses[0].Signature) {
				t.Errorf("the recorded signature is not the one returned: %v", err)
			}
		})
	}
}

func spentHour(t *testing.T, service *ipc.Client, wallet string) uint64 {
	t.Helper()
	var ps ipc.PolicyStatus
	if err := service.Call(context.Background(), ipc.MsgGetPolicyStatus, &ipc.GetPolicyStatus{WalletID: wallet}, &ps); err != nil {
		t.Fatal(err)
	}
	return ps.SpentHour
}

func slices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
