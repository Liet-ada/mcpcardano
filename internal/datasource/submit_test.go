// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package datasource

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSubmit(t *testing.T) {
	id := [32]byte{0: 0xab, 31: 0xcd}
	idHex := hex.EncodeToString(id[:])
	cases := []struct {
		name   string
		status int
		answer string
		want   error
		reason string
	}{
		{"accepted", http.StatusAccepted, `"` + idHex + `"`, nil, ""},
		{"another id", http.StatusAccepted, `"` + strings.Repeat("0", 64) + `"`, ErrInvalidResponse, ""},
		{"inputs spent", http.StatusBadRequest, `{"contents":{"contents":{"contents":{"era":"ShelleyBasedEraConway","error":["ConwayUtxowFailure (UtxoFailure (BadInputsUTxO (fromList [...])))"]}}},"tag":"TxSubmitFail"}`, ErrRejected, "BadInputsUTxO"},
		{"too late", http.StatusBadRequest, `{"error":"OutsideValidityIntervalUTxO ... and ValueNotConservedUTxO"}`, ErrRejected, "OutsideValidityIntervalUTxO, ValueNotConservedUTxO"},
		{"server error", http.StatusBadGateway, "", ErrUnavailable, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []byte
			k := serve(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/submittx" {
					return false
				}
				if r.Header.Get("Content-Type") != "application/cbor" {
					t.Errorf("content type %q", r.Header.Get("Content-Type"))
				}
				got, _ = io.ReadAll(r.Body)
				w.WriteHeader(c.status)
				fmt.Fprint(w, c.answer)
				return true
			})
			err := k.Submit(ctx, []byte{0x84, 1, 2}, id)
			if !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if c.reason != "" && !strings.HasSuffix(err.Error(), c.reason) {
				t.Errorf("reason: %v", err)
			}
			if string(got) != "\x84\x01\x02" {
				t.Errorf("sent %x", got)
			}
		})
	}
}

func TestConfirmations(t *testing.T) {
	a, b := [32]byte{1}, [32]byte{2}
	answer := fmt.Sprintf(`[{"tx_hash":"%s","num_confirmations":7},{"tx_hash":"%s","num_confirmations":null}]`, hex.EncodeToString(a[:]), hex.EncodeToString(b[:]))
	k := serve(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/v1/tx_status" {
			return false
		}
		fmt.Fprint(w, answer)
		return true
	})
	got, err := k.Confirmations(ctx, [][32]byte{a, b})
	if err != nil || got[a] != 7 || got[b] != 0 || len(got) != 2 {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := k.Confirmations(ctx, [][32]byte{a}); !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("an answer about a transaction not asked: %v", err)
	}
}
