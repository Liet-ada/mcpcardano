// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package fido

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	authn "github.com/go-authn/fido"
)

// The transport of Linux: the hidraw devices of the kernel, with the standard
// library only. It lives in a file of its own, without a build tag, so that
// it is tested on every system.

// fidoUsagePage is the HID usage page every FIDO authenticator publishes
// (CTAP 2.1, section 11.2.8.1). Matching on it rather than on vendor ids
// finds every brand.
const fidoUsagePage = 0xF1D0

// isFIDO reports whether a HID report descriptor declares the FIDO usage
// page. It walks the descriptor item by item, so a byte pattern inside
// another item's data does not match.
func isFIDO(desc []byte) bool {
	for i := 0; i < len(desc); {
		prefix := desc[i]
		if prefix == 0xfe { // a long item: the next byte is its size
			if i+1 >= len(desc) {
				return false
			}
			i += 3 + int(desc[i+1])
			continue
		}
		size := int(prefix & 0x03)
		if size == 3 {
			size = 4
		}
		if i+1+size > len(desc) {
			return false
		}
		if prefix&0xfc == 0x04 { // Usage Page, a global item, little-endian
			var v uint32
			for j := size - 1; j >= 0; j-- {
				v = v<<8 | uint32(desc[i+1+j])
			}
			if v == fidoUsagePage {
				return true
			}
		}
		i += 1 + size
	}
	return false
}

// hidrawDevice is a security key found under /sys/class/hidraw.
type hidrawDevice struct {
	path, name string
}

// hidrawKeys lists the hidraw devices under sys (/sys/class/hidraw) whose
// report descriptor is FIDO's, as paths under dev (/dev), with the name the
// kernel gives them.
func hidrawKeys(sys, dev string) ([]hidrawDevice, error) {
	entries, err := os.ReadDir(sys)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []hidrawDevice
	for _, e := range entries {
		dir := filepath.Join(sys, e.Name(), "device")
		desc, err := os.ReadFile(filepath.Join(dir, "report_descriptor"))
		if err != nil || !isFIDO(desc) {
			continue
		}
		out = append(out, hidrawDevice{path: filepath.Join(dev, e.Name()), name: hidName(filepath.Join(dir, "uevent"), e.Name())})
	}
	return out, nil
}

// hidName reads HID_NAME from a uevent file, or returns fallback.
func hidName(uevent, fallback string) string {
	data, err := os.ReadFile(uevent)
	if err != nil {
		return fallback
	}
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		if name, ok := strings.CutPrefix(s.Text(), "HID_NAME="); ok && name != "" {
			return name
		}
	}
	return fallback
}

// hidraw carries reports over a hidraw device: each write is one output
// report after its report id, 0, and each read one input report. A reader
// runs from the start, so no report is lost between two Receive calls, as
// go-authn/fido requires of a transport.
type hidraw struct {
	f       io.ReadWriteCloser
	name    string
	reports chan []byte
	done    chan struct{}
}

func newHidraw(f io.ReadWriteCloser, name string) *hidraw {
	t := &hidraw{f: f, name: name, reports: make(chan []byte, 32), done: make(chan struct{})}
	go t.read()
	return t
}

func (t *hidraw) read() {
	defer close(t.reports)
	for {
		buf := make([]byte, authn.ReportSize)
		n, err := t.f.Read(buf)
		if err != nil {
			return
		}
		select {
		case t.reports <- buf[:n]:
		case <-t.done:
			return
		}
	}
}

func (t *hidraw) Name() string { return t.name }

func (t *hidraw) Send(report []byte) error {
	_, err := t.f.Write(append([]byte{0}, report...))
	return err
}

func (t *hidraw) Receive(ctx context.Context) ([]byte, error) {
	select {
	case r, ok := <-t.reports:
		if !ok {
			return nil, errors.New("fido: the security key went away")
		}
		return r, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *hidraw) Close() error {
	close(t.done)
	return t.f.Close()
}
