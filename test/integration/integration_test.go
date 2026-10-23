// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build integration

// Package integration runs mcpcardano as mcpcardano install installs it on
// Linux: the wallet and the server as services of systemd, each with its own
// user, and the person's CLI (section 11.1). run.sh installs it; these tests
// act as the person, a member of the group mcpcardano, as the server's user
// through sudo, and as root to break what doctor must find.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/mcpclient"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

const (
	walletRun = "/run/mcpcardano-wallet"
	serverRun = "/run/mcpcardano-server"
	service   = walletRun + "/service.sock"
	admin     = walletRun + "/admin.sock"
	mcpSocket = serverRun + "/mcp.sock"
	cli       = "/usr/local/bin/mcpcardano"
	load      = "/usr/local/bin/mcpcardano-it-load"
)

// shop is a destination of someone else's, on preprod.
var shop = model.Address{Raw: append([]byte{0x60}, bytes.Repeat([]byte{0x5a}, 28)...)}.Bech32()

var hello = ipc.Hello{Software: "integration", Network: string(model.Preprod)}

// phase skips a test unless run.sh runs it in its phase: the tests that
// break the installation, bind it to a TPM2 or remove it run after the
// others, one phase at a time (MCPCARDANO_IT_PHASE).
func phase(t *testing.T, name string) {
	t.Helper()
	if os.Getenv("MCPCARDANO_IT_PHASE") != name {
		t.Skipf("run.sh runs it in the phase %s", name)
	}
}

// work is run.sh's directory, with the binaries it built.
func work(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("MCPCARDANO_IT_WORK")
	if dir == "" {
		t.Fatal("MCPCARDANO_IT_WORK is not set")
	}
	return dir
}

// password is the key store's, which run.sh created.
func password(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(os.Getenv("MCPCARDANO_IT_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b)) + "\n"
}

// run runs a command, typing input, and returns its exit code and output.
func run(t *testing.T, input string, name string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatalf("%s: %v", name, err)
	}
	return cmd.ProcessState.ExitCode(), string(out)
}

// person runs the CLI as the person.
func person(t *testing.T, input string, args ...string) (int, string) {
	t.Helper()
	return run(t, input, cli, append(args, "-admin", admin)...)
}

// mustPerson runs a command of the person's that must succeed.
func mustPerson(t *testing.T, input string, args ...string) string {
	t.Helper()
	code, out := person(t, input, args...)
	if code != 0 {
		t.Fatalf("mcpcardano %s: exit %d\n%s", strings.Join(args, " "), code, out)
	}
	return out
}

// asServer runs a command as the server's user, as a compromised server
// would.
func asServer(t *testing.T, args ...string) (int, string) {
	t.Helper()
	return run(t, "", "sudo", append([]string{"-n", "-u", "mcpcardano-server"}, args...)...)
}

func sudo(t *testing.T, args ...string) string {
	t.Helper()
	code, out := run(t, "", "sudo", append([]string{"-n"}, args...)...)
	if code != 0 {
		t.Fatalf("sudo %s: exit %d\n%s", strings.Join(args, " "), code, out)
	}
	return out
}

func mainPID(t *testing.T, unit string) string {
	t.Helper()
	pid := strings.TrimSpace(sudo(t, "systemctl", "show", "-p", "MainPID", "--value", unit))
	if pid == "" || pid == "0" {
		t.Fatalf("%s is not running", unit)
	}
	return pid
}

func uid(t *testing.T, name string) string {
	t.Helper()
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	return u.Uid
}

func gid(t *testing.T, name string) uint32 {
	t.Helper()
	g, err := user.LookupGroup(name)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(g.Gid)
	return uint32(n)
}

// TestIsolation checks the frontiers of sections 5.1, 7.1 and 10.3 on the
// running services.
func TestIsolation(t *testing.T) {
	// Each service runs as its own user, and the wallet has no network.
	for unit, name := range map[string]string{"mcpcardano-wallet": "mcpcardano-wallet", "mcpcardano-server": "mcpcardano-server"} {
		status := sudo(t, "cat", "/proc/"+mainPID(t, unit)+"/status")
		if !regexp.MustCompile(`(?m)^Uid:\t` + uid(t, name) + `\t`).MatchString(status) {
			t.Errorf("%s does not run as %s:\n%s", unit, name, status)
		}
	}
	// The wallet's memory is locked out of swap: all of it, since it locks
	// what it maps later too. Each page is locked when first used, so what
	// nobody touches takes no RAM, and at rest the wallet holds a few MB.
	status := sudo(t, "cat", "/proc/"+mainPID(t, "mcpcardano-wallet")+"/status")
	locked := regexp.MustCompile(`(?m)^VmLck:\s+(\d+) kB`).FindStringSubmatch(status)
	rss := regexp.MustCompile(`(?m)^VmRSS:\s+(\d+) kB`).FindStringSubmatch(status)
	if locked == nil || rss == nil || locked[1] == "0" {
		t.Errorf("the wallet's memory is not locked:\n%s", status)
	} else if n, _ := strconv.Atoi(rss[1]); n > 64<<10 {
		t.Errorf("the wallet holds %s kB at rest, with %s kB locked", rss[1], locked[1])
	} else {
		t.Logf("the wallet has %s kB locked and %s kB resident", locked[1], rss[1])
	}
	var ifaces []string
	for _, line := range strings.Split(sudo(t, "cat", "/proc/"+mainPID(t, "mcpcardano-wallet")+"/net/dev"), "\n")[2:] {
		if name, _, ok := strings.Cut(line, ":"); ok {
			ifaces = append(ifaces, strings.TrimSpace(name))
		}
	}
	if !slices.Equal(ifaces, []string{"lo"}) {
		t.Errorf("the wallet sees the interfaces %v", ifaces)
	}

	// The directories of the sockets are 0750 with the group mcpcardano, the
	// sockets 0660; the data directories are their services' alone.
	group := gid(t, "mcpcardano")
	for path, mode := range map[string]os.FileMode{walletRun: 0o750, service: 0o660, admin: 0o660, serverRun: 0o750, mcpSocket: 0o660} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != mode || fi.Sys().(*syscall.Stat_t).Gid != group {
			t.Errorf("%s: %v, group %d", path, fi.Mode(), fi.Sys().(*syscall.Stat_t).Gid)
		}
	}
	for _, dir := range []string{"/var/lib/mcpcardano-wallet", "/var/lib/mcpcardano-server"} {
		if _, err := os.ReadDir(dir); !errors.Is(err, os.ErrPermission) {
			t.Errorf("the person reads %s: %v", dir, err)
		}
	}
	if code, _ := asServer(t, "ls", "/var/lib/mcpcardano-wallet"); code == 0 {
		t.Error("the server's user reads the wallet's data")
	}

	// The kernel certifies the user at the other end of each socket: the
	// person cannot speak as the server, nor the server as the person.
	if c, err := ipc.Dial(context.Background(), service, hello); err == nil {
		c.Close()
		t.Error("the person reached the service socket")
	}
	if code, out := asServer(t, cli, "status", "-admin", admin); code != 4 {
		t.Errorf("the server's user on the admin socket: exit %d\n%s", code, out)
	}
	if out := mustPerson(t, "", "audit", "show", "-limit", "100"); strings.Count(out, "peer.refused") < 2 {
		t.Errorf("the wallet did not record the refused peers:\n%s", out)
	}
}

// agent connects to the server's MCP socket, as the person's bridge does.
func agent(t *testing.T) *mcpclient.Client {
	t.Helper()
	var c *mcpclient.Client
	var err error
	for range 50 {
		if c, err = mcpclient.Dial(context.Background(), mcpSocket, "integration"); err == nil {
			t.Cleanup(func() { c.Close() })
			return c
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}

type draft struct {
	DraftID string `json:"draft_id"`
	State   string `json:"state"`
	Summary struct {
		TxID string `json:"tx_id"`
	} `json:"summary"`
}

func call(t *testing.T, a *mcpclient.Client, tool string, args map[string]any, out any) error {
	t.Helper()
	return a.Call(context.Background(), tool, args, out)
}

func code(err error) string {
	var te *mcpclient.ToolError
	if errors.As(err, &te) {
		return te.Code
	}
	return ""
}

func pay(t *testing.T, a *mcpclient.Client, wallet, lovelace string) draft {
	t.Helper()
	var d draft
	if err := call(t, a, "build_payment", map[string]any{"wallet_id": wallet,
		"outputs": []any{map[string]any{"address": shop, "lovelace": lovelace}}}, &d); err != nil {
		t.Fatalf("build_payment: %v", err)
	}
	return d
}

// wait follows a draft until it reaches a state; the server's watcher looks
// every 20 seconds.
func wait(t *testing.T, a *mcpclient.Client, d *draft, want string) {
	t.Helper()
	for range 90 {
		if err := call(t, a, "get_draft", map[string]any{"draft_id": d.DraftID}, d); err != nil {
			t.Fatal(err)
		}
		if d.State == want {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("draft %s is %s, want %s", d.DraftID, d.State, want)
}

// agentWallet creates the agent's wallet, or finds it again: the key makes
// create_wallet idempotent.
func agentWallet(t *testing.T, a *mcpclient.Client) (string, string) {
	t.Helper()
	var w struct {
		WalletID string `json:"wallet_id"`
		Mode     string `json:"mode"`
		Address  string `json:"address"`
	}
	if err := call(t, a, "create_wallet", map[string]any{"label": "agent", "idempotency_key": "integration"}, &w); err != nil {
		t.Fatalf("create_wallet: %v", err)
	}
	return w.WalletID, w.Address
}

// setPolicy changes a wallet's policy through the CLI, with the password.
func setPolicy(t *testing.T, wallet string, change func(map[string]any)) {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal([]byte(mustPerson(t, "", "policy", "show", "-wallet", wallet)), &p); err != nil {
		t.Fatal(err)
	}
	change(p)
	file := filepath.Join(t.TempDir(), "policy.json")
	b, _ := json.Marshal(p)
	os.WriteFile(file, b, 0o600)
	mustPerson(t, password(t), "policy", "set", "-wallet", wallet, file)
}

// TestPayments runs the payments of milestone H-2 through the real services:
// mode C signs and the server sends at once; a locked wallet makes the draft
// wait; mode B waits for the person's approval; the server follows what the
// wallet signed across its own restart.
func TestPayments(t *testing.T) {
	mustPerson(t, password(t), "unlock")
	a := agent(t)
	wallet, _ := agentWallet(t, a)

	d := pay(t, a, wallet, "5000000")
	if err := call(t, a, "authorize_draft", map[string]any{"draft_id": d.DraftID}, &d); err != nil || d.State != "submitted" {
		t.Fatalf("mode C: %+v, %v", d, err)
	}
	wait(t, a, &d, "confirmed")

	// Locked after a restart of the wallet: the draft waits for the person.
	sudo(t, "systemctl", "restart", "mcpcardano-wallet")
	for range 50 {
		if code, out := person(t, "", "status"); code == 0 && strings.Contains(out, "locked;") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	locked := pay(t, a, wallet, "2000000")
	if err := call(t, a, "authorize_draft", map[string]any{"draft_id": locked.DraftID}, &locked); code(err) != "WALLET_UNAVAILABLE" {
		t.Fatalf("authorize while locked: %v", err)
	}
	mustPerson(t, password(t), "unlock")
	if err := call(t, a, "authorize_draft", map[string]any{"draft_id": locked.DraftID}, &locked); err != nil || locked.State != "submitted" {
		t.Fatalf("authorize after unlocking: %+v, %v", locked, err)
	}

	// Mode B: above the threshold the person approves with the CLI.
	setPolicy(t, wallet, func(p map[string]any) {
		p["mode"] = "B"
		p["limits"].(map[string]any)["approval_threshold"] = "1000000"
	})
	b := pay(t, a, wallet, "3000000")
	if err := call(t, a, "authorize_draft", map[string]any{"draft_id": b.DraftID}, &b); err != nil || b.State != "pending_approval" {
		t.Fatalf("mode B: %+v, %v", b, err)
	}
	approval := regexp.MustCompile(`a_[a-z2-7]{26}`).FindString(mustPerson(t, "", "status"))
	if approval == "" {
		t.Fatal("no approval in mcpcardano status")
	}
	if out := mustPerson(t, password(t), "approve", approval); !strings.Contains(out, "to "+shop) {
		t.Errorf("the summary does not show the destination:\n%s", out)
	}
	wait(t, a, &b, "submitted")

	// The server restarts: it lost its drafts and still knows the wallet and
	// what it signed (section 9.5).
	sudo(t, "systemctl", "restart", "mcpcardano-server")
	a = agent(t)
	var list struct {
		Wallets []struct {
			WalletID string `json:"wallet_id"`
		} `json:"wallets"`
	}
	if err := call(t, a, "list_wallets", nil, &list); err != nil || len(list.Wallets) != 1 || list.Wallets[0].WalletID != wallet {
		t.Fatalf("list_wallets after the restart: %+v, %v", list, err)
	}
	var ts struct {
		Status string `json:"status"`
	}
	if err := call(t, a, "get_transaction_status", map[string]any{"tx_id": b.Summary.TxID}, &ts); err != nil || ts.Status != "confirmed" {
		t.Errorf("the mode B payment after the restart: %+v, %v", ts, err)
	}
}

// TestLockUnderLoad measures risk R-10 (decision 32): a compromised server
// keeps the wallet's single lock as busy as it can, and the person must
// still see the status and freeze in time.
func TestLockUnderLoad(t *testing.T) {
	a := agent(t)
	wallet, _ := agentWallet(t, a)
	setPolicy(t, wallet, func(p map[string]any) { p["mode"] = "C" })

	c, err := ipc.Dial(context.Background(), admin, hello)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sample := func(n int) []time.Duration {
		var out []time.Duration
		for range n {
			start := time.Now()
			if err := c.Call(context.Background(), ipc.MsgStatus, &ipc.Empty{}, &ipc.StatusReport{}); err != nil {
				t.Fatal(err)
			}
			out = append(out, time.Since(start))
			time.Sleep(25 * time.Millisecond)
		}
		slices.Sort(out)
		return out
	}
	idle := sample(50)

	cmd := exec.Command("sudo", "-n", "-u", "mcpcardano-server", load, "-socket", service, "-wallet", wallet, "-to", shop, "-for", "15s")
	var loadOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &loadOut, &loadOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	busy := sample(300)
	start := time.Now()
	if err := c.Call(context.Background(), ipc.MsgFreeze, &ipc.Freeze{}, &ipc.Empty{}); err != nil {
		t.Fatal(err)
	}
	freeze := time.Since(start)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("load: %v\n%s", err, loadOut.String())
	}

	q := func(s []time.Duration, f float64) time.Duration { return s[int(f*float64(len(s)-1))] }
	t.Logf("R-10: %s", strings.TrimSpace(loadOut.String()))
	t.Logf("R-10: Status without load: median %v, p99 %v, slowest %v", q(idle, 0.5), q(idle, 0.99), idle[len(idle)-1])
	t.Logf("R-10: Status under load: median %v, p99 %v, slowest %v; Freeze under load: %v",
		q(busy, 0.5), q(busy, 0.99), busy[len(busy)-1], freeze)
	if busy[len(busy)-1] > 5*time.Second || freeze > 5*time.Second {
		t.Error("the person waited longer than the wallet's per-message deadline")
	}
}

// TestUnlockByMachine checks the unlock bound to the machine (decision 132),
// with the TPM2 that run.sh simulates and the credential that install
// -unlock machine seals with it. run.sh runs it after the others, since it
// leaves the wallet starting unlocked, and twice: with the TPM2 that sealed
// the credential (phase tpm-bind), and then with another (tpm-other).
func TestUnlockByMachine(t *testing.T) {
	const credential = "/etc/credstore.encrypted/mcpcardano-wallet.unlock"
	// restart restarts the wallet and returns what mcpcardano status says.
	// It resets systemd's limit of 5 starts in 10 seconds first.
	restart := func() string {
		t.Helper()
		sudo(t, "systemctl", "reset-failed", "mcpcardano-wallet")
		sudo(t, "systemctl", "restart", "mcpcardano-wallet")
		for range 50 {
			if code, out := person(t, "", "status"); code == 0 {
				return out
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatal("the wallet did not come back")
		return ""
	}
	locked := func(out string) bool { return strings.Contains(out, "locked;") }

	switch os.Getenv("MCPCARDANO_IT_PHASE") {
	case "tpm-bind":
		// Not bound yet: it starts locked, and the password binds it.
		if out := restart(); !locked(out) {
			t.Fatalf("a start before binding:\n%s", out)
		}
		mustPerson(t, password(t), "unlock")
		// From then on it starts unlocked, and the password still opens.
		if out := restart(); locked(out) {
			t.Fatalf("a start once bound:\n%s", out)
		}
		mustPerson(t, password(t), "unlock")

		// Without the credential, as with the key store on another
		// machine, it starts locked. The password opens it, and unbinds it.
		sudo(t, "mv", credential, credential+".off")
		if out := restart(); !locked(out) {
			t.Fatalf("a start without the credential:\n%s", out)
		}
		mustPerson(t, password(t), "unlock")
		sudo(t, "mv", credential+".off", credential)
		if out := restart(); !locked(out) {
			t.Fatalf("still bound after an unlock without the credential:\n%s", out)
		}
		mustPerson(t, password(t), "unlock")
		if out := restart(); locked(out) {
			t.Fatalf("bound again:\n%s", out)
		}
	case "tpm-other":
		// The credential does not decrypt with another TPM2, as after
		// clearing it: systemd skips it, the wallet starts locked, and the
		// password opens it.
		if out := restart(); !locked(out) {
			t.Fatalf("a start with another TPM2:\n%s", out)
		}
		mustPerson(t, password(t), "unlock")
	default:
		t.Skip("run.sh runs it in the phases tpm-bind and tpm-other, with a TPM2")
	}
}
