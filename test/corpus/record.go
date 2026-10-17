// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

//go:build ignore

// record fetches the transactions listed in txs.txt from Koios and writes,
// for each one, its CBOR and what Koios (cardano-db-sync) says it contains.
// The decoding tests compare our summary with that independent reading.
//
//	go run test/corpus/record.go
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
	"slices"
	"strconv"
	"strings"
	"time"
)

var koios = map[string]string{
	"preprod": "https://preprod.koios.rest/api/v1",
	"mainnet": "https://api.koios.rest/api/v1",
}

// Entry is one file of the corpus.
type Entry struct {
	Network string `json:"network"`
	Note    string `json:"note"`
	CBOR    string `json:"cbor"`
	Koios   Koios  `json:"koios"`
}

// Koios keeps the fields of tx_info the tests compare, with Koios's names.
type Koios struct {
	TxHash           string        `json:"tx_hash"`
	Fee              string        `json:"fee"`
	InvalidBefore    *string       `json:"invalid_before"`
	InvalidAfter     *string       `json:"invalid_after"`
	Inputs           int           `json:"inputs"`
	CollateralInputs int           `json:"collateral_inputs"`
	CollateralOutput bool          `json:"collateral_output"`
	ReferenceInputs  int           `json:"reference_inputs"`
	Outputs          []Output      `json:"outputs"`
	Withdrawals      []Withdrawal  `json:"withdrawals"`
	AssetsMinted     []Asset       `json:"assets_minted"`
	Certificates     []Certificate `json:"certificates"`
	MetadataLabels   []string      `json:"metadata_labels"`
	Message          []string      `json:"message"`
	// Metadata is the whole metadata as db-sync renders it: integers as
	// numbers, bytes as 0x and hex.
	Metadata         map[string]json.RawMessage `json:"metadata"`
	Votes            int                        `json:"votes"`
	Proposals        int                        `json:"proposals"`
	TreasuryDonation string                     `json:"treasury_donation"`
}

type Output struct {
	Address         string  `json:"address"`
	Value           string  `json:"value"`
	Assets          []Asset `json:"assets"`
	Datum           bool    `json:"datum"`
	ReferenceScript bool    `json:"reference_script"`
}

type Asset struct {
	PolicyID    string `json:"policy_id"`
	AssetName   string `json:"asset_name"`
	Fingerprint string `json:"fingerprint"`
	Quantity    string `json:"quantity"`
}

type Withdrawal struct {
	StakeAddr string `json:"stake_addr"`
	Amount    string `json:"amount"`
}

type Certificate struct {
	Index int    `json:"index"`
	Type  string `json:"type"`
}

// txInfo is the part of Koios's tx_info answer that record reads.
type txInfo struct {
	TxHash             string                     `json:"tx_hash"`
	Fee                string                     `json:"fee"`
	InvalidBefore      json.RawMessage            `json:"invalid_before"`
	InvalidAfter       json.RawMessage            `json:"invalid_after"`
	Inputs             []any                      `json:"inputs"`
	CollateralInputs   []any                      `json:"collateral_inputs"`
	CollateralOutput   any                        `json:"collateral_output"`
	ReferenceInputs    []any                      `json:"reference_inputs"`
	Outputs            []outputRow                `json:"outputs"`
	Withdrawals        []Withdrawal               `json:"withdrawals"`
	AssetsMinted       []Asset                    `json:"assets_minted"`
	Certificates       []Certificate              `json:"certificates"`
	Metadata           map[string]json.RawMessage `json:"metadata"`
	VotingProcedures   []any                      `json:"voting_procedures"`
	ProposalProcedures []any                      `json:"proposal_procedures"`
	TreasuryDonation   string                     `json:"treasury_donation"`
}

type outputRow struct {
	TxIndex     int `json:"tx_index"`
	PaymentAddr struct {
		Bech32 string `json:"bech32"`
	} `json:"payment_addr"`
	Value           string  `json:"value"`
	DatumHash       any     `json:"datum_hash"`
	InlineDatum     any     `json:"inline_datum"`
	ReferenceScript any     `json:"reference_script"`
	AssetList       []Asset `json:"asset_list"`
}

func main() {
	dir := filepath.Join("test", "corpus")
	list, err := readList(filepath.Join(dir, "txs.txt"))
	if err != nil {
		fail(err)
	}
	for network, entries := range list {
		var hashes []string
		for _, e := range entries {
			hashes = append(hashes, e[0])
		}
		cbors, err := txCBOR(network, hashes)
		if err != nil {
			fail(err)
		}
		infos, err := txInfos(network, hashes)
		if err != nil {
			fail(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, network), 0o755); err != nil {
			fail(err)
		}
		for _, e := range entries {
			h := e[0]
			info, ok := infos[h]
			if !ok || cbors[h] == "" {
				fail(fmt.Errorf("%s %s: not found in Koios", network, h))
			}
			out, err := json.MarshalIndent(Entry{Network: network, Note: e[1], CBOR: cbors[h], Koios: normalize(info)}, "", "  ")
			if err != nil {
				fail(err)
			}
			if err := os.WriteFile(filepath.Join(dir, network, h+".json"), append(out, '\n'), 0o644); err != nil {
				fail(err)
			}
			fmt.Println(network, h, e[1])
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "record:", err)
	os.Exit(1)
}

// readList returns, per network, the transaction ids and notes of txs.txt.
func readList(path string) (map[string][][2]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string][][2]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, " ", 3)
		if len(fields) != 3 || koios[fields[0]] == "" || len(fields[1]) != 64 {
			return nil, fmt.Errorf("bad line %q", line)
		}
		out[fields[0]] = append(out[fields[0]], [2]string{fields[1], fields[2]})
	}
	return out, s.Err()
}

func post(network, path string, body any, into any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Post(koios[network]+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %s: %s", network, path, resp.Status, data)
	}
	return json.Unmarshal(data, into)
}

func txCBOR(network string, hashes []string) (map[string]string, error) {
	var rows []struct {
		TxHash string `json:"tx_hash"`
		CBOR   string `json:"cbor"`
	}
	if err := post(network, "/tx_cbor", map[string]any{"_tx_hashes": hashes}, &rows); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.TxHash] = r.CBOR
	}
	return out, nil
}

func txInfos(network string, hashes []string) (map[string]txInfo, error) {
	var rows []txInfo
	body := map[string]any{
		"_tx_hashes": hashes, "_inputs": true, "_metadata": true, "_assets": true,
		"_withdrawals": true, "_certs": true, "_scripts": true, "_bytecode": false, "_governance": true,
	}
	if err := post(network, "/tx_info", body, &rows); err != nil {
		return nil, err
	}
	out := map[string]txInfo{}
	for _, r := range rows {
		out[r.TxHash] = r
	}
	return out, nil
}

func present(v any) bool { return v != nil }

// slot reads invalid_before or invalid_after, which Koios gives as a string,
// a number or null.
func slot(raw json.RawMessage) *string {
	s := strings.Trim(string(raw), `"`)
	if s == "" || s == "null" {
		return nil
	}
	if _, err := strconv.ParseUint(s, 10, 64); err != nil {
		fail(fmt.Errorf("slot %s", raw))
	}
	return &s
}

func normalize(t txInfo) Koios {
	k := Koios{
		TxHash:           t.TxHash,
		Fee:              t.Fee,
		InvalidBefore:    slot(t.InvalidBefore),
		InvalidAfter:     slot(t.InvalidAfter),
		Inputs:           len(t.Inputs),
		CollateralInputs: len(t.CollateralInputs),
		CollateralOutput: present(t.CollateralOutput),
		ReferenceInputs:  len(t.ReferenceInputs),
		Withdrawals:      t.Withdrawals,
		AssetsMinted:     t.AssetsMinted,
		Certificates:     t.Certificates,
		Metadata:         t.Metadata,
		Votes:            len(t.VotingProcedures),
		Proposals:        len(t.ProposalProcedures),
		TreasuryDonation: t.TreasuryDonation,
	}
	outs := slices.Clone(t.Outputs)
	slices.SortFunc(outs, func(a, b outputRow) int { return a.TxIndex - b.TxIndex })
	for i, o := range outs {
		if o.TxIndex != i {
			fail(fmt.Errorf("%s: output indexes are not 0..n-1", t.TxHash))
		}
		k.Outputs = append(k.Outputs, Output{
			Address:         o.PaymentAddr.Bech32,
			Value:           o.Value,
			Assets:          o.AssetList,
			Datum:           present(o.DatumHash) || present(o.InlineDatum),
			ReferenceScript: present(o.ReferenceScript),
		})
	}
	var labels []uint64
	for label := range t.Metadata {
		n, err := strconv.ParseUint(label, 10, 64)
		if err != nil {
			fail(fmt.Errorf("%s: metadata label %q", t.TxHash, label))
		}
		labels = append(labels, n)
	}
	slices.Sort(labels)
	for _, n := range labels {
		k.MetadataLabels = append(k.MetadataLabels, strconv.FormatUint(n, 10))
	}
	if raw, ok := t.Metadata["674"]; ok {
		var m struct {
			Msg []string `json:"msg"`
		}
		if json.Unmarshal(raw, &m) == nil {
			k.Message = m.Msg
		}
	}
	return k
}
