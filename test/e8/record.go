// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build ignore

// record fetches the tokens listed in real.txt from Koios on mainnet and
// writes Koios's asset_info rows for them, with the fields the server reads,
// into testdata/real_assets.json. E8 serves them to the server as they are.
//
//	go run test/e8/record.go
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const koios = "https://api.koios.rest/api/v1"

func main() {
	dir := filepath.Join("test", "e8")
	assets, err := readList(filepath.Join(dir, "real.txt"))
	if err != nil {
		fail(err)
	}
	b, err := json.Marshal(map[string]any{"_asset_list": assets})
	if err != nil {
		fail(err)
	}
	// The same fields as the server's Koios client asks for.
	url := koios + "/asset_info?select=policy_id,asset_name,total_supply,minting_tx_metadata,cip68_metadata"
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		fail(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		fail(err)
	}
	if resp.StatusCode != http.StatusOK {
		fail(fmt.Errorf("asset_info: %s: %s", resp.Status, data))
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(data, &rows); err != nil {
		fail(err)
	}
	if len(rows) != len(assets) {
		fail(fmt.Errorf("asked for %d tokens, Koios has %d", len(assets), len(rows)))
	}
	out, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testdata", "real_assets.json"), append(out, '\n'), 0o644); err != nil {
		fail(err)
	}
	fmt.Println(len(rows), "tokens")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "record:", err)
	os.Exit(1)
}

// readList returns the [policy, name] pairs of real.txt.
func readList(path string) ([][2]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][2]string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, _, _ := strings.Cut(line, " ")
		policy, name, ok := strings.Cut(id, ".")
		if !ok || len(policy) != 56 {
			return nil, fmt.Errorf("bad line %q", line)
		}
		out = append(out, [2]string{policy, name})
	}
	return out, s.Err()
}
