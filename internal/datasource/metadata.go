// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package datasource

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"unicode/utf8"

	"github.com/Liet-ada/mcpcardano/internal/model"
)

func decodeJSON(raw json.RawMessage) any {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil
	}
	return v
}

// cip25Entry returns the metadata of one token under label 721: keyed by
// policy and then by the name as text (version 1) or in hex (version 2).
func cip25Entry(raw json.RawMessage, id model.AssetID) any {
	top, _ := decodeJSON(raw).(map[string]any)
	l721, _ := top["721"].(map[string]any)
	byName, _ := l721[hex.EncodeToString(id.Policy[:])].(map[string]any)
	if byName == nil {
		return nil
	}
	if utf8.ValidString(id.Name) {
		if e, ok := byName[id.Name]; ok {
			return e
		}
	}
	return byName[hex.EncodeToString([]byte(id.Name))]
}

// cip68Fields reads the reference datum of a CIP-68 token, which a data
// source renders as detailed Plutus JSON: its first field is the metadata
// map, with byte strings as keys and mostly as values, and its second the
// version.
func cip68Fields(raw json.RawMessage) any {
	top, _ := decodeJSON(raw).(map[string]any)
	if len(top) != 1 {
		return nil
	}
	for _, datum := range top {
		d, _ := datum.(map[string]any)
		fields, _ := d["fields"].([]any)
		if len(fields) == 0 {
			return nil
		}
		out := map[string]any{}
		if m, ok := plutusJSON(fields[0]).(map[string]any); ok {
			out = m
		}
		if len(fields) > 1 {
			out["version"] = plutusJSON(fields[1])
		}
		return out
	}
	return nil
}

// plutusJSON turns detailed Plutus JSON into plain values: byte strings that
// are UTF-8 become text, others 0x and hex; maps with text keys become
// objects.
func plutusJSON(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	switch {
	case m["bytes"] != nil:
		s, _ := m["bytes"].(string)
		b, err := hex.DecodeString(s)
		if err == nil && utf8.Valid(b) {
			return string(b)
		}
		return "0x" + s
	case m["int"] != nil:
		return m["int"]
	case m["list"] != nil:
		items, _ := m["list"].([]any)
		out := make([]any, 0, len(items))
		for _, x := range items {
			out = append(out, plutusJSON(x))
		}
		return out
	case m["map"] != nil:
		entries, _ := m["map"].([]any)
		obj := map[string]any{}
		for _, e := range entries {
			kv, _ := e.(map[string]any)
			k, ok := plutusJSON(kv["k"]).(string)
			if !ok || obj[k] != nil {
				return plainMap(entries)
			}
			obj[k] = plutusJSON(kv["v"])
		}
		return obj
	case m["fields"] != nil:
		fields, _ := m["fields"].([]any)
		out := make([]any, 0, len(fields))
		for _, x := range fields {
			out = append(out, plutusJSON(x))
		}
		return map[string]any{"constructor": m["constructor"], "fields": out}
	}
	return nil
}

func plainMap(entries []any) []any {
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		kv, _ := e.(map[string]any)
		out = append(out, map[string]any{"k": plutusJSON(kv["k"]), "v": plutusJSON(kv["v"])})
	}
	return out
}
