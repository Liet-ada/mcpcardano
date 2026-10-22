// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package fido

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	authn "github.com/go-authn/fido"
)

// The report descriptor of a YubiKey's FIDO interface: usage page 0xF1D0,
// usage 1, and 64-byte input and output reports.
var yubikeyFIDO = []byte{
	0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08,
	0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
	0x02, 0xc0,
}

func TestIsFIDO(t *testing.T) {
	for _, tc := range []struct {
		name string
		desc []byte
		want bool
	}{
		{"a YubiKey's FIDO interface", yubikeyFIDO, true},
		{"a keyboard", []byte{0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0xc0}, false},
		{"the page's bytes inside another item's data", []byte{0x27, 0x06, 0xd0, 0xf1, 0x00, 0x05, 0x01}, false},
		{"after a long item", []byte{0xfe, 0x02, 0x10, 0xaa, 0xbb, 0x06, 0xd0, 0xf1}, true},
		{"the page in four bytes", []byte{0x07, 0xd0, 0xf1, 0x00, 0x00}, true},
		{"cut in the middle of the page", []byte{0x06, 0xd0}, false},
		{"empty", nil, false},
	} {
		if got := isFIDO(tc.desc); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

// TestHidrawKeys finds the FIDO interfaces in a /sys/class/hidraw of its own.
func TestHidrawKeys(t *testing.T) {
	sys := t.TempDir()
	write := func(dev, file string, data []byte) {
		dir := filepath.Join(sys, dev, "device")
		os.MkdirAll(dir, 0o755)
		if err := os.WriteFile(filepath.Join(dir, file), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("hidraw0", "report_descriptor", []byte{0x05, 0x01, 0x09, 0x06})
	write("hidraw1", "report_descriptor", yubikeyFIDO)
	write("hidraw1", "uevent", []byte("DRIVER=hid-generic\nHID_NAME=Yubico YubiKey OTP+FIDO+CCID\n"))
	write("hidraw2", "uevent", []byte("HID_NAME=no descriptor\n"))
	write("hidraw3", "report_descriptor", yubikeyFIDO)
	keys, err := hidrawKeys(sys, "/dev")
	if err != nil {
		t.Fatal(err)
	}
	want := []hidrawDevice{{"/dev/hidraw1", "Yubico YubiKey OTP+FIDO+CCID"}, {"/dev/hidraw3", "hidraw3"}}
	if len(keys) != 2 || keys[0] != want[0] || keys[1] != want[1] {
		t.Errorf("keys %+v", keys)
	}
	if keys, err := hidrawKeys(filepath.Join(sys, "none"), "/dev"); err != nil || keys != nil {
		t.Errorf("no hidraw at all: %v, %v", keys, err)
	}
}

// device is a hidraw device in memory: what is written goes to answer, which
// may queue reports to read.
type device struct {
	reads   chan []byte
	written [][]byte
	answer  func(d *device, report []byte)
	closed  chan struct{}
}

func newDevice(answer func(*device, []byte)) *device {
	return &device{reads: make(chan []byte, 8), answer: answer, closed: make(chan struct{})}
}

func (d *device) Read(p []byte) (int, error) {
	select {
	case r := <-d.reads:
		return copy(p, r), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *device) Write(p []byte) (int, error) {
	d.written = append(d.written, bytes.Clone(p))
	if d.answer != nil {
		d.answer(d, p)
	}
	return len(p), nil
}

func (d *device) Close() error { close(d.closed); return nil }

// TestHidrawHandshake opens a key over the hidraw transport: go-authn/fido
// sends CTAPHID_INIT, and the device, which reads reports without their
// report id, answers with a channel. A transport that left out the report id,
// or kept it in what it reads, would fail here.
func TestHidrawHandshake(t *testing.T) {
	d := newDevice(func(d *device, w []byte) {
		if len(w) != 1+authn.ReportSize || w[0] != 0 {
			return // not a report with its id; no answer
		}
		r := w[1:]
		if binary.BigEndian.Uint32(r) != authn.BroadcastChannel || r[4] != 0x80|authn.CmdInit {
			return
		}
		reply := make([]byte, authn.ReportSize)
		copy(reply, r[:5])
		binary.BigEndian.PutUint16(reply[5:], 17)
		copy(reply[7:15], r[7:15]) // the nonce
		binary.BigEndian.PutUint32(reply[15:], 0x01020304)
		copy(reply[19:], []byte{2, 5, 7, 4, byte(authn.CapWink | authn.CapCBOR)})
		d.reads <- reply
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	k, err := authn.Open(ctx, newHidraw(d, "test key"))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer k.Close()
	if k.Channel() != 0x01020304 || k.Version().Major != 5 || !k.Capabilities().Has(authn.CapCBOR) || k.Name() != "test key" {
		t.Errorf("key %v", k)
	}
}

// TestHidrawReceive: reports that arrive before Receive is called are kept,
// in order; Receive gives up with its context, and fails once the device is
// gone.
func TestHidrawReceive(t *testing.T) {
	d := newDevice(nil)
	tr := newHidraw(d, "test key")
	d.reads <- []byte{1}
	d.reads <- []byte{2}
	time.Sleep(10 * time.Millisecond) // the reader takes both before anyone asks
	ctx := context.Background()
	for want := byte(1); want <= 2; want++ {
		if r, err := tr.Receive(ctx); err != nil || len(r) != 1 || r[0] != want {
			t.Fatalf("report %d: %v, %v", want, r, err)
		}
	}
	short, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	if _, err := tr.Receive(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("with nothing to read: %v", err)
	}
	if err := tr.Send(bytes.Repeat([]byte{7}, authn.ReportSize)); err != nil || len(d.written[0]) != 65 || d.written[0][0] != 0 {
		t.Errorf("send: %v, %x", err, d.written)
	}
	tr.Close()
	if _, err := tr.Receive(ctx); err == nil {
		t.Error("a report from a closed device")
	}
}
