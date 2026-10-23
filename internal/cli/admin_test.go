// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/test/softkey"
	"github.com/Liet-ada/mcpcardano/test/walletkit"
)

// person runs the CLI against a real wallet process, typing input, with the
// security keys of slot, if any, and never a real one.
type person struct {
	t    *testing.T
	w    *walletkit.Wallet
	slot *softkey.Slot
}

// keysIn reaches the keys of slot, never waiting for one and never opening a
// real one.
func keysIn(slot *softkey.Slot) keys {
	if slot == nil {
		slot = &softkey.Slot{}
	}
	return keys{open: slot.Open, wait: 0}
}

type result struct {
	code        int
	out, errOut string
}

func (p person) run(input, command string, args ...string) result {
	p.t.Helper()
	full := append(strings.Fields(command), "-admin", p.w.Config.AdminSocket)
	var out, errOut bytes.Buffer
	code := runAdmin(context.Background(), append(full, args...), "test", strings.NewReader(input), &out, &errOut, keysIn(p.slot))
	return result{code, out.String(), errOut.String()}
}

// must runs a command that must succeed.
func (p person) must(input, command string, args ...string) result {
	p.t.Helper()
	r := p.run(input, command, args...)
	if r.code != ExitOK {
		p.t.Fatalf("%s %q: exit %d\n%s%s", command, args, r.code, r.out, r.errOut)
	}
	return r
}

var password = string(walletkit.Password) + "\n"

// TestAdminCommands runs every command of the person on the wallet's admin
// socket (section 6.1) against a real wallet process: those that raise what
// can be spent ask for the password after showing the wallet's summary, the
// others do not, and each ends with its exit code of section 6.5.
func TestAdminCommands(t *testing.T) {
	w := walletkit.Start(t)
	p := person{t: t, w: w}

	// Locked: status says so, and what needs the keys waits for unlock.
	if r := p.must("", "status"); !strings.Contains(r.out, "locked; unlock it") {
		t.Errorf("status while locked:\n%s", r.out)
	}
	if r := p.run(password, "wallet create", "-label", "saving"); r.code != ExitUnavailable || !strings.Contains(r.errOut, "mcpcardano unlock") {
		t.Errorf("create while locked: %+v", r)
	}
	if r := p.run("wrong password\n", "unlock"); r.code != ExitRejected || !strings.Contains(r.errOut, "AUTH_FAILED") {
		t.Errorf("unlock with a wrong password: %+v", r)
	}
	if r := p.run(password, "unlock"); r.code != ExitRejected || !strings.Contains(r.errOut, "RATE_LIMITED") {
		t.Errorf("unlock during the wait: %+v", r)
	}
	w.Clock.Advance(time.Second) // the first wait after a wrong password (section 6.2)
	p.must(password, "unlock")

	// A wallet of the person's, with the template of mode C.
	r := p.must(password, "wallet create", "-label", "saving")
	if !strings.Contains(r.errOut, "Create wallet saving with the template:") || !strings.Contains(r.errOut, "Mode C") {
		t.Errorf("the summary of create_wallet:\n%s", r.errOut)
	}
	m := regexp.MustCompile(`Wallet (w_[a-z2-7]+)  saving, mode C\n  (addr_test1\S+)`).FindStringSubmatch(r.out)
	if m == nil {
		t.Fatalf("wallet create:\n%s", r.out)
	}
	id := m[1]
	addr, err := model.ParseAddress(model.Preprod, m[2])
	if err != nil {
		t.Fatal(err)
	}

	// The server's side: a payment signed in mode C that expires unconfirmed,
	// then mode B with an approval waiting.
	service := w.Service(t)
	pay := func(to byte, lovelace uint64) *ipc.SignDraftResult {
		body := walletkit.Encode(t, walletkit.Payment(addr.Raw, walletkit.Address(6, to, 0), lovelace, w.Clock))
		res, err := walletkit.Sign(service, id, body, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := pay(7, 2_000_000); res.Status != ipc.Signed {
		t.Fatalf("mode C: %+v", res)
	}
	w.Clock.Advance(11 * time.Minute)
	file := filepath.Join(t.TempDir(), "policy.json")
	var pol policyFile
	if err := json.Unmarshal([]byte(p.must("", "policy show", "-wallet", id).out), &pol); err != nil {
		t.Fatal(err)
	}
	pol.Mode, pol.Limits.ApprovalThreshold = "B", "1000000"
	writeJSON(t, file, pol)
	p.must(password, "policy set", "-wallet", id, file)
	approval := pay(8, 5_000_000).ApprovalID
	if approval == "" {
		t.Fatal("no approval in mode B")
	}

	// Every command with no password typed: those that need one decline and
	// change nothing; the others go through.
	phrase := strings.Repeat("abandon ", 23) + "art\n"
	commands := []struct {
		input, command string
		args           []string
		authorized     bool
	}{
		{"", "status", nil, false},
		{"", "unlock", nil, true},
		{"", "approve", []string{approval}, true},
		{"", "session open", []string{"-wallet", id, "-for", "1h", "-max", "5000000"}, true},
		{"", "session close", []string{"-wallet", id}, false},
		{"", "freeze", []string{"-wallet", id}, false},
		{"", "unfreeze", []string{"-wallet", id}, true},
		{"", "policy show", []string{"-template"}, false},
		{"", "policy set", []string{"-wallet", id, file}, true},
		{"", "budget pending", nil, false},
		{"", "budget release", []string{"-wallet", id}, true},
		{"", "wallet create", []string{"-label", "other"}, true},
		{phrase, "wallet restore", []string{"-label", "other"}, true},
		{"", "wallet backup", []string{"-wallet", id}, true},
		{"", "audit show", nil, false},
		{"", "audit verify", nil, false},
	}
	for _, c := range commands {
		r := p.run(c.input, c.command, c.args...)
		switch {
		case c.authorized && (r.code != ExitRejected || !strings.Contains(r.errOut, "cancelled")):
			t.Errorf("%s without a password: %+v", c.command, r)
		case !c.authorized && r.code != ExitOK:
			t.Errorf("%s: %+v", c.command, r)
		}
	}
	if r := p.must("", "status"); !strings.Contains(r.out, "FROZEN") || !strings.Contains(r.out, approval) {
		t.Errorf("after declining unfreeze and approve:\n%s", r.out)
	}

	// With the password. A wrong one is AUTH_FAILED.
	if r := p.run("wrong password\n", "unfreeze", "-wallet", id); r.code != ExitRejected || !strings.Contains(r.errOut, "AUTH_FAILED") {
		t.Errorf("unfreeze with a wrong password: %+v", r)
	}
	w.Clock.Advance(time.Second)
	p.must(password, "unfreeze", "-wallet", id)
	if r := p.must(password, "approve", approval); !strings.Contains(r.errOut, "Spend: 5.170000 ADA") {
		t.Errorf("the summary of the approval:\n%s", r.errOut)
	}
	var as ipc.ApprovalStatus
	service.Call(context.Background(), ipc.MsgGetApprovalStatus, &ipc.GetApprovalStatus{ApprovalID: approval}, &as)
	if as.Status != ipc.ApprovalApproved {
		t.Errorf("approval %s", as.Status)
	}
	if r := p.must(password, "session open", "-wallet", id, "-for", "1h", "-max", "5000000"); !strings.Contains(r.errOut, "for 1h0m0s, up to 5.000000 ADA") {
		t.Errorf("the summary of open_session:\n%s", r.errOut)
	}
	if r := p.must("", "status"); strings.Contains(r.out, "FROZEN") || !strings.Contains(r.out, "session until") ||
		!strings.Contains(r.out, "5.000000 ADA left") || !strings.Contains(r.out, "open destinations") {
		t.Errorf("status:\n%s", r.out)
	}
	if r := p.must("", "budget pending", "-wallet", id); !strings.Contains(r.out, "2.170000 ADA") {
		t.Errorf("budget pending:\n%s", r.out)
	}
	if r := p.must(password, "budget release", "-wallet", id); !strings.Contains(r.out, "Released 2.170000 ADA") {
		t.Errorf("budget release:\n%s", r.out)
	}
	if r := p.must("", "budget pending"); !strings.Contains(r.out, "No expired_unconfirmed entries") {
		t.Errorf("after the release:\n%s", r.out)
	}

	// The template, from the CLI (decision 106): its mode and its values.
	var tpl policyFile
	json.Unmarshal([]byte(p.must("", "policy show", "-template").out), &tpl)
	shop := model.Address{Raw: walletkit.Address(6, 7, 0)}.Bech32()
	gold := strings.Repeat("0d", 28) + ".676f6c64"
	silver := strings.Repeat("0c", 28) + ".73696c766572"
	tpl.Limits.Budget, tpl.Destinations = "50000000", destinationsFile{Allowed: []string{shop, m[2]}}
	tpl.Assets = map[string]string{gold: "5", silver: "7"}
	writeJSON(t, file, tpl)
	if r := p.must(password, "policy set", "-template", file); !strings.Contains(r.errOut, "Destinations: 2 addresses") {
		t.Errorf("the summary of set_template:\n%s", r.errOut)
	}
	json.Unmarshal([]byte(p.must("", "policy show", "-template").out), &tpl)
	if tpl.Limits.Budget != "50000000" || tpl.Destinations.Any || !slices.Equal(tpl.Destinations.Allowed, []string{m[2], shop}) ||
		tpl.Assets[gold] != "5" || tpl.Assets[silver] != "7" {
		t.Errorf("template %+v", tpl)
	}

	// The recovery phrase restores the same wallet in another wallet process.
	r = p.must(password, "wallet backup", "-wallet", id)
	words := strings.Fields(r.out)
	if len(words) != 24 || !strings.Contains(r.errOut, "Show the recovery phrase of wallet saving") {
		t.Fatalf("wallet backup: %d words\n%s", len(words), r.errOut)
	}
	other := walletkit.Start(t)
	walletkit.Unlock(t, other.Admin(t))
	q := person{t: t, w: other}
	r = q.must(strings.Join(words, " ")+"\n"+password, "wallet restore", "-label", "back")
	if !strings.Contains(r.errOut, "Address: "+m[2]) || !strings.Contains(r.out, m[2]) {
		t.Errorf("restore:\n%s%s", r.out, r.errOut)
	}

	// The person rejects an approval without a password. The destination is
	// a known one: a third new one within the hour would be refused.
	second := pay(8, 4_000_000).ApprovalID
	p.must("", "reject", second)
	service.Call(context.Background(), ipc.MsgGetApprovalStatus, &ipc.GetApprovalStatus{ApprovalID: second}, &as)
	if as.Status != ipc.ApprovalRejected {
		t.Errorf("rejected approval %s", as.Status)
	}

	// The audit log, page by page, and its hash chains.
	r = p.must("", "audit show", "-limit", "3")
	next := regexp.MustCompile(`More with: mcpcardano audit show -from (\d+)\n$`).FindStringSubmatch(r.out)
	if strings.Count(r.out, "\n") != 4 || next == nil {
		t.Fatalf("audit show:\n%s", r.out)
	}
	if r := p.must("", "audit show", "-from", next[1], "-limit", "100"); !strings.Contains(r.out, `approval.rejected  {"approval_id":"`+second) {
		t.Errorf("audit show:\n%s", r.out)
	}
	if r := p.must("", "audit verify"); !strings.Contains(r.out, "Both hash chains hold") {
		t.Errorf("audit verify:\n%s", r.out)
	}
	p.must("", "freeze")
	if r := p.must("", "status"); strings.Count(r.out, "FROZEN") != 1 {
		t.Errorf("freeze all:\n%s", r.out)
	}
	// A new policy leaves the wallet frozen: only unfreeze thaws it.
	p.must(password, "policy set", "-wallet", id, file)
	if r := p.must("", "status"); !strings.Contains(r.out, "FROZEN") {
		t.Errorf("policy set unfroze the wallet:\n%s", r.out)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAdminExitCodes: wrong usage is 2, a wallet that does not answer is 4,
// and another network says how to name it (section 6.5).
func TestAdminExitCodes(t *testing.T) {
	w := walletkit.Start(t)
	walletkit.Unlock(t, w.Admin(t))
	p := person{t: t, w: w}
	id := walletkit.CreateWallet(t, w.Service(t), "agent").ID
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		os.WriteFile(path, []byte(text), 0o600)
		return path
	}
	usage := [][]string{
		{"policy"},
		{"approve"},
		{"approve", "d_notanapproval"},
		{"reject", "a_1"},
		{"session open", "-for", "1h", "-max", "1"},
		{"session open", "-wallet", id, "-for", "0s", "-max", "1"},
		{"session open", "-wallet", id, "-for", "1h", "-max", "1.5"},
		{"policy show"},
		{"policy show", "-wallet", id, "-template"},
		{"policy set", "-template"},
		{"budget release", "-wallet", id, "abc"},
		{"budget release", "-wallet", id, "abcd"},
		{"session open", "-wallet", id, "-for", "1h", "-max", "0"},
		{"wallet create"},
		{"wallet create", "-label", "a\tb"},
		{"audit show", "-limit", "101"},
		{"freeze", "-wallet", "nobody"},
		{"status", "-unknown"},
	}
	for _, args := range usage {
		if r := p.run("", args[0], args[1:]...); r.code != ExitUsage || !strings.Contains(r.errOut, "usage: mcpcardano") {
			t.Errorf("%q: %+v", args, r)
		}
	}

	var out, errOut bytes.Buffer
	if code := Admin(context.Background(), []string{"status", "-admin", filepath.Join(dir, "none.sock")}, "test", strings.NewReader(""), &out, &errOut); code != ExitUnavailable {
		t.Errorf("no wallet: %d, %s", code, errOut.String())
	}
	// Wrong usage is wrong usage whether the wallet runs or not.
	if code := Admin(context.Background(), []string{"approve", "d_notanapproval", "-admin", filepath.Join(dir, "none.sock")}, "test", strings.NewReader(""), &out, &errOut); code != ExitUsage {
		t.Errorf("wrong usage, no wallet: %d", code)
	}
	if r := p.run("", "status", "-network", "preview"); r.code != ExitError || !strings.Contains(r.errOut, "-network") {
		t.Errorf("another network: %+v", r)
	}
	if r := p.run("", "approve", "a_aaaaaaaaaaaaaaaaaaaaaaaaaa"); r.code != ExitError || !strings.Contains(r.errOut, "NOT_FOUND") {
		t.Errorf("an approval that does not exist: %+v", r)
	}
	// Flags go anywhere among the arguments; after -- all is an argument.
	for _, args := range [][]string{
		{"approve", "a_aaaaaaaaaaaaaaaaaaaaaaaaaa", "-admin", w.Config.AdminSocket},
		{"approve", "-admin", w.Config.AdminSocket, "--", "a_aaaaaaaaaaaaaaaaaaaaaaaaaa"},
	} {
		out.Reset()
		errOut.Reset()
		if code := Admin(context.Background(), args, "test", strings.NewReader(""), &out, &errOut); code != ExitError || !strings.Contains(errOut.String(), "NOT_FOUND") {
			t.Errorf("%q: %d, %s", args, code, errOut.String())
		}
	}
	errOut.Reset()
	if code := Admin(context.Background(), []string{"approve", "-admin", w.Config.AdminSocket, "--", "-x"}, "test", strings.NewReader(""), &out, &errOut); code != ExitUsage || !strings.Contains(errOut.String(), `"-x" is not an approval id`) {
		t.Errorf("an argument after --: %d, %s", code, errOut.String())
	}
	errOut.Reset()
	release := []string{"budget", "release", "-admin", w.Config.AdminSocket, "-wallet", id, "--", strings.Repeat("ab", 32), "-x"}
	if code := Admin(context.Background(), release, "test", strings.NewReader(""), &out, &errOut); code != ExitUsage || !strings.Contains(errOut.String(), `"-x" is not a transaction`) {
		t.Errorf("arguments after --: %d, %s", code, errOut.String())
	}

	// policy set reads its file strictly and checks it before asking.
	good := `{"mode": "C", "networks": ["preprod"], "destinations": {"any": true}}`
	for name, text := range map[string]string{
		"unknown field":   `{"mode": "C", "frozen": false}`,
		"trailing data":   good + ` {}`,
		"mode A":          `{"mode": "A"}`,
		"mainnet address": `{"mode": "C", "destinations": {"allowed": ["addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x"]}}`,
		"twice":           `{"mode": "C", "networks": ["preprod", "preprod"]}`,
		"bad amount":      `{"mode": "C", "limits": {"per_tx": "1.5"}}`,
		"bad asset":       `{"mode": "C", "assets": {"x": "1"}}`,
	} {
		if r := p.run(password, "policy set", "-wallet", id, write("p.json", text)); r.code != ExitError || strings.Contains(r.errOut, "The wallet asks") {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if r := p.run(password, "policy set", "-wallet", id, write("p.json", `{"mode": "A"}`)); !strings.Contains(r.errOut, "server's config.json") {
		t.Errorf("mode A: %+v", r)
	}
	// Zeros forbid (decision 38): a warning, and the summary shows them.
	if r := p.run("", "policy set", "-wallet", id, write("p.json", good)); r.code != ExitRejected ||
		!strings.Contains(r.errOut, "warning: limits.per_tx is zero") || !strings.Contains(r.errOut, "warning: limits.budget is zero") {
		t.Errorf("zeros: %+v", r)
	}
}

// TestReadLine: a secret ends at the newline, without the carriage return,
// leaves the rest of the input unread, and has a size limit.
func TestReadLine(t *testing.T) {
	in := strings.NewReader("first\r\nsecond")
	if s, err := readLine(in); err != nil || string(s) != "first" {
		t.Errorf("%q, %v", s, err)
	}
	if s, err := readLine(in); err != nil || string(s) != "second" {
		t.Errorf("%q, %v", s, err)
	}
	if s, err := readLine(in); err != nil || len(s) != 0 {
		t.Errorf("at the end: %q, %v", s, err)
	}
	if _, err := readLine(strings.NewReader(strings.Repeat("x", ipc.MaxSecret+1))); err == nil {
		t.Error("a line too long")
	}
	if _, err := readSecret(context.Background(), strings.NewReader("\n"), &bytes.Buffer{}, ""); err != errCancelled {
		t.Errorf("an empty password: %v", err)
	}
}

// TestPolicyFile: a file in the format of policy show reads back as the same
// policy, with its lists in their wire order whatever the order of the file
// and of the map of tokens.
func TestPolicyFile(t *testing.T) {
	tokens := map[string]string{}
	for i, name := range []string{"aa", "bb", "cc", "dd", "ee"} {
		tokens[strings.Repeat(fmt.Sprintf("%02x", 9-i), 28)+"."+name] = fmt.Sprint(i + 1)
	}
	addrs := []string{
		model.Address{Raw: walletkit.Address(6, 9, 0)}.Bech32(),
		model.Address{Raw: walletkit.Address(0, 2, 3)}.Bech32(),
		model.Address{Raw: walletkit.Address(6, 1, 0)}.Bech32(),
	}
	f := policyFile{Mode: "B", Networks: []string{"preview", "preprod"}, Limits: limitsFile{PerTx: "7", ApprovalThreshold: "3"},
		Destinations: destinationsFile{Allowed: addrs}, Assets: tokens, UTxO: utxoFile{MinSplit: "5"}}
	for range 50 {
		mode, p, err := f.wire(model.Preprod)
		if err != nil {
			t.Fatal(err)
		}
		back := policyFromWire(mode, p)
		if back.Mode != "B" || back.Limits.PerTx != "7" || back.Limits.ApprovalThreshold != "3" || back.Limits.Budget != "0" ||
			back.UTxO.MinSplit != "5" || !slices.Equal(back.Networks, []string{"preprod", "preview"}) ||
			!slices.Equal(back.Destinations.Allowed, []string{addrs[1], addrs[2], addrs[0]}) || len(back.Assets) != 5 {
			t.Fatalf("read back %+v", back)
		}
	}
}
