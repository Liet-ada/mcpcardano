// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package datasource

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// ErrRejected reports a transaction the node refused. The error text names
// the ledger's reason, such as BadInputsUTxO.
var ErrRejected = errors.New("datasource: the node rejected the transaction")

// maxRejection bounds the node's message kept in an error.
const maxRejection = 512

// Submit implements Source. It sends once and never retries (section 9.6):
// after a network error nobody knows whether the node took the transaction,
// so the caller asks the chain before sending again. id is the transaction's
// id, which the node must answer with.
func (k *Koios) Submit(ctx context.Context, tx []byte, id [32]byte) error {
	u := *k.base
	u.Path += "/submittx"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(tx))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/cbor")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mcpcardano")
	resp, err := k.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("%w: reading the answer: %v", ErrUnavailable, err)
	}
	switch {
	case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK:
		var got string
		if json.Unmarshal(body, &got) != nil || got != hex.EncodeToString(id[:]) {
			return fmt.Errorf("%w: the node answered with another transaction id", ErrInvalidResponse)
		}
		return nil
	case resp.StatusCode == http.StatusBadRequest:
		return fmt.Errorf("%w: %s", ErrRejected, rejection(body))
	default:
		return fmt.Errorf("%w: HTTP %d", ErrUnavailable, resp.StatusCode)
	}
}

// rejection keeps the ledger's reasons from the node's answer, the words
// that end in UTxO, UTXOW or the like, or else a cut of the text.
func rejection(body []byte) string {
	var reasons []string
	for _, w := range strings.FieldsFunc(string(body), func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		if (strings.HasSuffix(w, "UTxO") || strings.HasSuffix(w, "UTXOW") || strings.HasSuffix(w, "UTXO")) && !contains(reasons, w) {
			reasons = append(reasons, w)
		}
	}
	if len(reasons) > 0 {
		return strings.Join(reasons, ", ")
	}
	s := string(body)
	if len(s) > maxRejection {
		s = s[:maxRejection]
	}
	return strings.ToValidUTF8(s, "?")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// maxTxHashes is the most transactions one tx_status request asks about. The
// public Koios endpoints refuse a body over 5 KiB with HTTP 413, and each hash
// takes 67 bytes of it, so no more than 76 fit.
const maxTxHashes = 50

// Confirmations implements Source: for each transaction, how many blocks
// contain or follow its block; zero if it is not in the chain. It asks about
// maxTxHashes transactions per request.
func (k *Koios) Confirmations(ctx context.Context, ids [][32]byte) (map[[32]byte]uint64, error) {
	out := make(map[[32]byte]uint64, len(ids))
	for batch := range slices.Chunk(ids, maxTxHashes) {
		asked := make(map[string][32]byte, len(batch))
		hashes := make([]string, 0, len(batch))
		for _, id := range batch {
			h := hex.EncodeToString(id[:])
			asked[h] = id
			hashes = append(hashes, h)
		}
		var rows []struct {
			TxHash        *string `json:"tx_hash"`
			Confirmations *uint64 `json:"num_confirmations"`
		}
		if err := k.call(ctx, "/tx_status", nil, map[string]any{"_tx_hashes": hashes}, &rows); err != nil {
			return nil, err
		}
		for _, r := range rows {
			if r.TxHash == nil {
				return nil, fmt.Errorf("%w: tx_status is missing fields", ErrInvalidResponse)
			}
			id, ok := asked[*r.TxHash]
			if !ok {
				return nil, fmt.Errorf("%w: tx_status about %s, which was not asked", ErrInvalidResponse, *r.TxHash)
			}
			if r.Confirmations != nil {
				out[id] = *r.Confirmations
			}
		}
	}
	for _, id := range ids {
		if _, ok := out[id]; !ok {
			out[id] = 0
		}
	}
	return out, nil
}
