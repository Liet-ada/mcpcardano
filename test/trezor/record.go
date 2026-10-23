// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build ignore

// Command record asks the Trezor emulator for the keys and the signatures of
// the phrases of internal/hdkey/testdata/cardano_cli.json and writes them as
// internal/hdkey/testdata/trezor.json, the hardware side of hdkey's cross
// vectors (step 3 of H-3). It needs a checkout of trezor-firmware with its
// emulator built and its .venv, and cardano-hw-go built with -tags
// emulators:
//
//	go run test/trezor/record.go -firmware /path/to/trezor-firmware -hwgo /path/to/cardano-hw-go
//
// A Trezor takes BIP-39 phrases of 12, 18 and 24 words only, so the phrases of
// 15 and 21 words are left out. For each phrase it starts the emulator with
// that phrase and, once emu.py has loaded it, asks for the keys with the
// derivations ICARUS and ICARUS_TREZOR, has it witness the fixture's
// transaction body with the ICARUS keys, and stops it. Every call to
// cardano-hw-go names the emulator and checks first that it is running:
// without it, cardano-hw-go would go over USB to a real Trezor.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Key is the key of m/1852'/1815'/account'/role/index on the emulator.
type Key struct {
	Derivation string `json:"derivation"`
	Account    uint32 `json:"account"`
	Role       uint32 `json:"role"`
	Index      uint32 `json:"index"`
	// XPub is the verification key and the chain code.
	XPub string `json:"xpub"`
	// Signature is its witness of the transaction body; only for ICARUS.
	Signature string `json:"signature,omitempty"`
}

// Phrase is a phrase and what the emulator derives from it.
type Phrase struct {
	Phrase string `json:"phrase"`
	Keys   []Key  `json:"keys"`
}

// File is the fixture.
type File struct {
	Device     string   `json:"device"`
	Tool       string   `json:"tool"`
	Recorded   string   `json:"recorded"`
	TxBodyHash string   `json:"tx_body_hash"`
	Phrases    []Phrase `json:"phrases"`
}

// paths are the keys asked for with each derivation: ICARUS, the one hdkey
// implements, and ICARUS_TREZOR, the Trezor's default, which differs for 24
// words.
var paths = map[string][]struct{ account, role, index uint32 }{
	"ICARUS":        {{0, 0, 0}, {0, 2, 0}, {0, 0, 1}, {7, 0, 19}},
	"ICARUS_TREZOR": {{0, 0, 0}, {0, 2, 0}},
}

func main() {
	firmware := flag.String("firmware", "", "checkout of trezor-firmware, with the emulator built")
	hwgo := flag.String("hwgo", "", "cardano-hw-go built with -tags emulators")
	vectors := flag.String("vectors", "internal/hdkey/testdata/cardano_cli.json", "the phrases and the transaction body")
	out := flag.String("out", "internal/hdkey/testdata/trezor.json", "fixture to write")
	flag.Parse()
	if *firmware == "" || *hwgo == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := record(*firmware, *hwgo, *vectors, *out); err != nil {
		fmt.Fprintln(os.Stderr, "record:", err)
		os.Exit(1)
	}
}

func record(firmware, hwgo, vectors, out string) error {
	var in struct {
		TxBody     string `json:"tx_body"`
		TxBodyHash string `json:"tx_body_hash"`
		Phrases    []struct {
			Phrase string `json:"phrase"`
		} `json:"phrases"`
	}
	b, err := os.ReadFile(vectors)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "hdkey-trezor-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	tx := filepath.Join(dir, "tx.json")
	b, _ = json.Marshal(map[string]string{"type": "Tx ConwayEra", "description": "Ledger Cddl Format", "cborHex": in.TxBody})
	if err := os.WriteFile(tx, b, 0o600); err != nil {
		return err
	}

	f := File{Recorded: time.Now().UTC().Format(time.DateOnly), TxBodyHash: in.TxBodyHash}
	v, err := exec.Command(hwgo, "version").Output()
	if err != nil {
		return fmt.Errorf("%s version: %w", hwgo, err)
	}
	f.Tool = strings.SplitN(strings.TrimSpace(string(v)), "\n", 2)[0]

	for i, p := range in.Phrases {
		if n := len(strings.Fields(p.Phrase)); n != 12 && n != 18 && n != 24 {
			continue
		}
		e, err := start(firmware, p.Phrase)
		if err != nil {
			return fmt.Errorf("phrase %d: %w", i, err)
		}
		h := hw{bin: hwgo, dir: dir, emu: e}
		ph, err := h.phrase(p.Phrase, tx)
		if err == nil && f.Device == "" {
			f.Device, err = h.run("device", "version")
			f.Device = "Trezor Safe 7 emulator (T3W1), " + strings.TrimSpace(f.Device)
		}
		e.stop()
		if err != nil {
			return fmt.Errorf("phrase %d: %w", i, err)
		}
		f.Phrases = append(f.Phrases, ph)
		fmt.Fprintf(os.Stderr, "phrase %d of %d\n", i+1, len(in.Phrases))
	}

	b, err = json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, append(b, '\n'), 0o644)
}

// emulator is a running emu.py, in its own process group: it starts the
// firmware and the model of the secure element, and stop ends all three.
type emulator struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan struct{}
	tail  []string // the last lines of its output, for the errors
}

// loaded is what emu.py runs once it has loaded the phrase: it says so and
// waits on its input, and emu.py stops the emulator when it ends.
const loaded = "hdkey vectors: the phrase is loaded"

func start(firmware, phrase string) (*emulator, error) {
	core := filepath.Join(firmware, "core")
	venv := filepath.Join(firmware, ".venv", "bin")
	c := exec.Command(filepath.Join(venv, "python"), "./emu.py", "--headless", "--temporary-profile", "--mnemonic", phrase,
		"-c", "--", "sh", "-c", "echo '"+loaded+"'; exec cat")
	c.Dir = core
	c.Env = append(os.Environ(), "PATH="+venv+":"+os.Getenv("PATH")) // emu.py starts model_server from the .venv
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := c.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := c.StdinPipe()
	if err != nil {
		return nil, err
	}
	c.Stderr = c.Stdout
	if err := c.Start(); err != nil {
		return nil, err
	}
	e := &emulator{cmd: c, stdin: stdin, done: make(chan struct{})}
	ready := make(chan bool, 1)
	go func() {
		s := bufio.NewScanner(stdout)
		s.Buffer(nil, 1<<20)
		for s.Scan() {
			e.tail = append(e.tail[max(0, len(e.tail)-19):], s.Text())
			if s.Text() == loaded {
				select {
				case ready <- true:
				default:
				}
			}
		}
		c.Wait()
		close(e.done)
	}()
	select {
	case <-ready:
		return e, nil
	case <-e.done:
		return nil, fmt.Errorf("the emulator died while starting:\n%s", strings.Join(e.tail, "\n"))
	case <-time.After(90 * time.Second):
		e.stop()
		return nil, errors.New("the emulator did not start in 90 s")
	}
}

func (e *emulator) running() bool {
	select {
	case <-e.done:
		return false
	default:
		return true
	}
}

// stop ends the command emu.py runs, so that it stops the emulator, and
// kills them all if that takes too long.
func (e *emulator) stop() {
	e.stdin.Close()
	select {
	case <-e.done:
		return
	case <-time.After(15 * time.Second):
	}
	syscall.Kill(-e.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-e.done:
	case <-time.After(10 * time.Second):
		syscall.Kill(-e.cmd.Process.Pid, syscall.SIGKILL)
		<-e.done
	}
}

type hw struct {
	bin, dir string
	emu      *emulator
}

// run calls cardano-hw-go against the emulator, never against a device.
func (h hw) run(args ...string) (string, error) {
	if !h.emu.running() {
		return "", errors.New("the emulator is not running")
	}
	var stderr strings.Builder
	c := exec.Command(h.bin, args...)
	c.Dir = h.dir
	c.Env = append(os.Environ(), "CARDANO_HW_GO_TREZOR_EMULATOR=127.0.0.1:21324", "CARDANO_HW_GO_DEBUGLINK=1")
	c.Stderr = &stderr
	b, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("cardano-hw-go %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(b), nil
}

func (h hw) phrase(phrase, tx string) (Phrase, error) {
	p := Phrase{Phrase: phrase}
	for _, derivation := range []string{"ICARUS", "ICARUS_TREZOR"} {
		for _, d := range paths[derivation] {
			path := fmt.Sprintf("1852H/1815H/%dH/%d/%d", d.account, d.role, d.index)
			hws, vkey := filepath.Join(h.dir, "key.hwsfile"), filepath.Join(h.dir, "key.vkey")
			if _, err := h.run("address", "key-gen", "--path", path, "--hw-signing-file", hws,
				"--verification-key-file", vkey, "--derivation-type", derivation); err != nil {
				return p, err
			}
			var s struct {
				Path    string `json:"path"`
				XPubHex string `json:"cborXPubKeyHex"`
			}
			b, err := os.ReadFile(hws)
			if err != nil {
				return p, err
			}
			if err := json.Unmarshal(b, &s); err != nil || s.Path != path || len(s.XPubHex) != 4+128 || !strings.HasPrefix(s.XPubHex, "5840") {
				return p, fmt.Errorf("%s: not a signing file of %s", hws, path)
			}
			k := Key{Derivation: derivation, Account: d.account, Role: d.role, Index: d.index, XPub: s.XPubHex[4:]}
			if derivation == "ICARUS" {
				w := filepath.Join(h.dir, "w.json")
				if _, err := h.run("transaction", "witness", "--tx-file", tx, "--hw-signing-file", hws,
					"--testnet-magic", "1", "--derivation-type", derivation, "--out-file", w); err != nil {
					return p, err
				}
				if k.Signature, err = signature(w, k.XPub[:64]); err != nil {
					return p, err
				}
			}
			p.Keys = append(p.Keys, k)
		}
	}
	return p, nil
}

// signature reads the signature of a key witness, [0, [vkey, signature]],
// and checks that its verification key is vkey.
func signature(path, vkey string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var e struct {
		CBORHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(b, &e); err != nil {
		return "", err
	}
	want := "8200825820" + vkey + "5840"
	if !strings.HasPrefix(e.CBORHex, want) || len(e.CBORHex) != len(want)+128 {
		return "", fmt.Errorf("%s is not a key witness of %.8s…", path, vkey)
	}
	return e.CBORHex[len(want):], nil
}
