// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build ignore

// Command txviews reads with cardano-cli the transactions of txcheck's cross
// check (decision 131) and writes what it read as the fixture,
// test/corpus/testdata/cli/cardano_cli.json. cardano-cli reads them with the
// decoders of cardano-ledger, the Haskell code that runs a transaction on the
// network. The transactions come from the test itself:
//
//	go test ./test/corpus -run TestCardanoCLI -args -cli-bodies=/tmp/bodies.json
//	go run test/cardano-cli/txviews.go -cli /path/to/cardano-cli -in /tmp/bodies.json
//
// For each one it keeps `debug transaction view` and `transaction txid`, or
// the error if cardano-cli cannot read it.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Tx and File are those of test/corpus/cardano_cli_test.go.
type Tx struct {
	Name  string          `json:"name"`
	Body  string          `json:"body"`
	Aux   string          `json:"aux,omitempty"`
	Tx    string          `json:"tx"`
	TxID  string          `json:"txid,omitempty"`
	View  json.RawMessage `json:"view,omitempty"`
	Error string          `json:"error,omitempty"`
}

type File struct {
	Tool     string `json:"tool"`
	Recorded string `json:"recorded"`
	Txs      []Tx   `json:"txs"`
}

func main() {
	cli := flag.String("cli", "cardano-cli", "path to cardano-cli")
	in := flag.String("in", "", "the transactions, as the test writes them")
	out := flag.String("out", "test/corpus/testdata/cli/cardano_cli.json", "fixture to write")
	flag.Parse()
	if err := record(*cli, *in, *out); err != nil {
		fmt.Fprintln(os.Stderr, "txviews:", err)
		os.Exit(1)
	}
}

func record(cli, in, out string) error {
	b, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "txcheck-views-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	version, err := run(cli, "--version")
	if err != nil {
		return err
	}
	f.Tool = strings.Join(strings.Fields(version), " ")
	f.Recorded = time.Now().UTC().Format(time.DateOnly)

	for i := range f.Txs {
		x := &f.Txs[i]
		path := filepath.Join(dir, fmt.Sprintf("tx%d.json", i))
		env, _ := json.Marshal(map[string]string{"type": "Tx ConwayEra", "description": "", "cborHex": x.Tx})
		if err := os.WriteFile(path, env, 0o644); err != nil {
			return err
		}
		view, err := run(cli, "debug", "transaction", "view", "--output-json", "--tx-file", path)
		if err != nil {
			x.Error = err.Error()
			continue
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, []byte(view)); err != nil {
			return fmt.Errorf("%s: the view is not JSON: %v", x.Name, err)
		}
		x.View = compact.Bytes()
		txid, err := run(cli, "conway", "transaction", "txid", "--tx-file", path)
		if err != nil {
			return fmt.Errorf("%s: %v", x.Name, err)
		}
		var id struct {
			TxHash string `json:"txhash"`
		}
		if err := json.Unmarshal([]byte(txid), &id); err != nil || len(id.TxHash) != 64 {
			return fmt.Errorf("%s: txid %q", x.Name, txid)
		}
		x.TxID = id.TxHash
	}

	// One transaction per line, so that a new recording diffs by line.
	var w bytes.Buffer
	tool, _ := json.Marshal(f.Tool)
	fmt.Fprintf(&w, "{\n  \"tool\": %s,\n  \"recorded\": %q,\n  \"txs\": [\n", tool, f.Recorded)
	for i, x := range f.Txs {
		line, err := json.Marshal(x)
		if err != nil {
			return err
		}
		w.WriteString("    ")
		w.Write(line)
		if i < len(f.Txs)-1 {
			w.WriteByte(',')
		}
		w.WriteByte('\n')
	}
	w.WriteString("  ]\n}\n")
	return os.WriteFile(out, w.Bytes(), 0o644)
}

func run(cli string, args ...string) (string, error) {
	var stderr strings.Builder
	x := exec.Command(cli, args...)
	x.Stderr = &stderr
	b, err := x.Output()
	if err != nil {
		return "", fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(b), nil
}
