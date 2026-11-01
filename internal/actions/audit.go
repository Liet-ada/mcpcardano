// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package actions

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/cborx"
)

// AuditEntry is an entry of the audit log as the person reads it.
type AuditEntry struct {
	Seq    uint64
	Time   int64 // Unix seconds
	Type   string
	Wallet string // the wallet it names, if any
	Body   string // as JSON
}

var auditCodec = func() *cborx.Codec {
	c, err := cborx.New(cborx.RecordLimits())
	if err != nil {
		panic(err) // constant limits
	}
	return c
}()

// ReadAudit decodes an entry of ShowAudit.
func ReadAudit(raw []byte) (AuditEntry, error) {
	var e audit.Entry
	var body any
	if err := auditCodec.Unmarshal(raw, &e); err != nil {
		return AuditEntry{}, err
	}
	if err := auditCodec.Unmarshal(e.Body, &body); err != nil {
		return AuditEntry{}, err
	}
	readable := jsonable(body)
	text, err := json.Marshal(readable)
	if err != nil {
		return AuditEntry{}, err
	}
	out := AuditEntry{Seq: e.Seq, Time: e.Time, Type: e.Type, Body: string(text)}
	if m, ok := readable.(map[string]any); ok {
		out.Wallet, _ = m["wallet_id"].(string)
	}
	return out, nil
}

// jsonable turns a decoded CBOR value into one encoding/json can write: map
// keys as text and bytes as hex.
func jsonable(v any) any {
	switch x := v.(type) {
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[fmt.Sprint(jsonable(k))] = jsonable(val)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = jsonable(x[i])
		}
		return out
	case []byte:
		return hex.EncodeToString(x)
	}
	return v
}
