// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretNeverPrints(t *testing.T) {
	s := Secret("hunter2")
	holder := struct{ Password Secret }{s}
	var out []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		out = append(out, fmt.Sprintf(verb, s), fmt.Sprintf(verb, holder), fmt.Sprintf(verb, &holder))
	}
	out = append(out, fmt.Sprint(s), fmt.Sprintln(s), s.String())

	var logs bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&logs, nil), slog.NewJSONHandler(&logs, nil)} {
		l := slog.New(h)
		l.Info("unlock", "password", s)
		l.Info("unlock", "holder", holder)
	}
	out = append(out, logs.String())

	j, err := json.Marshal(holder)
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, string(j))

	for _, o := range out {
		if strings.Contains(o, "hunter2") || strings.Contains(o, fmt.Sprintf("%x", []byte(s))) {
			t.Errorf("the secret leaked: %s", o)
		}
		if !strings.Contains(o, "[REDACTED]") {
			t.Errorf("no [REDACTED] in %q", o)
		}
	}
}

func TestSecretWipe(t *testing.T) {
	s := Secret("hunter2")
	s.Wipe()
	if !bytes.Equal(s, make([]byte, 7)) {
		t.Errorf("after Wipe: %v", []byte(s))
	}
}
