// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Command koios is the data source of the integration tests (section 11.1):
// it answers the requests of the server's Koios client as preprod would.
// Under /blockfrost it answers the latest block and the genesis of
// Blockfrost to a client with the project id BlockfrostKey, and 403 to
// any other, so that the tests can see the key reach the server (decision
// 138).
// Every address it is asked about holds ten UTxOs of 100 ADA; every
// transaction it receives is taken, spends its inputs and gains one
// confirmation a second.
package main

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// epochParams are the parameters of a preprod epoch, as Koios answered.
//
//go:embed epoch_params.json
var epochParams []byte

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "the address to serve on")
	flag.Parse()
	c := &chain{spent: map[string]bool{}, submitted: map[string]time.Time{}}
	log.Fatal(http.ListenAndServe(*listen, c))
}

// chain is what the fake knows: the outputs spent and the transactions taken.
type chain struct {
	mu        sync.Mutex
	spent     map[string]bool      // "tx_hash#index"
	submitted map[string]time.Time // tx id, and when it came
}

// BlockfrostKey is the only project id the fake's Blockfrost takes.
const BlockfrostKey = "preprodIntegration2026"

func (c *chain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var out any
	if path, ok := strings.CutPrefix(r.URL.Path, "/blockfrost"); ok {
		if r.Header.Get("project_id") != BlockfrostKey {
			http.Error(w, `{"status_code":403,"error":"Forbidden","message":"Invalid project token."}`, http.StatusForbidden)
			return
		}
		now := time.Now()
		switch path {
		case "/genesis":
			out = map[string]any{"network_magic": 1}
		case "/blocks/latest":
			out = map[string]any{"hash": hex.EncodeToString(make([]byte, 32)), "epoch": 319,
				"slot": model.Preprod.Clock().Slot(now), "height": now.Unix(), "time": now.Unix()}
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
		return
	}
	switch r.URL.Path {
	case "/genesis":
		out = []map[string]string{{"networkmagic": "1", "networkid": "Testnet"}}
	case "/tip":
		now := time.Now()
		out = []map[string]any{{"hash": hex.EncodeToString(make([]byte, 32)), "epoch_no": 319,
			"abs_slot": model.Preprod.Clock().Slot(now), "block_height": now.Unix(), "block_time": now.Unix()}}
	case "/epoch_params":
		w.Header().Set("Content-Type", "application/json")
		w.Write(epochParams)
		return
	case "/address_utxos":
		var body struct {
			Addresses []string `json:"_addresses"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		out = c.utxos(body.Addresses, r.URL.Query().Get("offset"))
	case "/submittx":
		tx, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		id, err := c.take(tx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(id)
		return
	case "/tx_status":
		var body struct {
			Hashes []string `json:"_tx_hashes"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		out = c.status(body.Hashes)
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// utxos lists ten UTxOs of 100 ADA for each address, all in the first page.
func (c *chain) utxos(addresses []string, offset string) []map[string]any {
	rows := []map[string]any{}
	if offset != "" && offset != "0" {
		return rows
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range addresses {
		for i := range 10 {
			id := blake2b.Sum256(fmt.Appendf(nil, "%s#%d", a, i))
			h := hex.EncodeToString(id[:])
			rows = append(rows, map[string]any{"tx_hash": h, "tx_index": 0, "address": a, "value": "100000000",
				"datum_hash": nil, "inline_datum": nil, "reference_script": nil, "asset_list": []any{},
				"is_spent": c.spent[h+"#0"]})
		}
	}
	return rows
}

var txCodec = func() *cborx.Codec {
	c, err := cborx.New(cborx.Limits{MaxDepth: 16, MaxArrayElements: 4096, MaxMapPairs: 4096, AllowTags: true})
	if err != nil {
		panic(err)
	}
	return c
}()

// take reads a signed transaction, [body, witnesses, valid, auxiliary data],
// marks its inputs spent and returns its id, the hash of its body.
func (c *chain) take(tx []byte) (string, error) {
	var parts []cborx.Raw
	if err := txCodec.Unmarshal(tx, &parts); err != nil || len(parts) != 4 {
		return "", errors.New("not a transaction")
	}
	var body map[uint64]cborx.Raw
	if err := txCodec.Unmarshal(parts[0], &body); err != nil {
		return "", errors.New("not a transaction body")
	}
	var inputs any
	if err := txCodec.Unmarshal(body[0], &inputs); err != nil {
		return "", errors.New("no inputs")
	}
	if t, ok := inputs.(cborx.Tag); ok {
		inputs = t.Content
	}
	list, _ := inputs.([]any)
	sum := blake2b.Sum256(parts[0])
	id := hex.EncodeToString(sum[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, in := range list {
		pair, ok := in.([]any)
		if !ok || len(pair) != 2 {
			return "", errors.New("bad input")
		}
		h, _ := pair[0].([]byte)
		c.spent[fmt.Sprintf("%x#%v", h, pair[1])] = true
	}
	if _, ok := c.submitted[id]; !ok {
		c.submitted[id] = time.Now()
	}
	return id, nil
}

// status gives each transaction taken one confirmation a second.
func (c *chain) status(hashes []string) []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	rows := []map[string]any{}
	for _, h := range hashes {
		row := map[string]any{"tx_hash": h, "num_confirmations": nil}
		if at, ok := c.submitted[h]; ok {
			row["num_confirmations"] = 1 + int(time.Since(at)/time.Second)
		}
		rows = append(rows, row)
	}
	return rows
}
