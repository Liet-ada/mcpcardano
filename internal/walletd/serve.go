// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package walletd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
)

// maxAdminConns bounds the connections of the admin socket, as section 5.5
// bounds the service socket's.
const maxAdminConns = 4

// Serve checks the isolation of section 10.3, creates the two sockets and
// serves them until ctx ends. In development mode the isolation check is
// skipped, and the audit log records it.
func (d *Daemon) Serve(ctx context.Context) error {
	if d.cfg.Development {
		d.record("isolation.skipped", map[string]any{"reason": "development mode"})
	} else if err := checkIsolation(); err != nil {
		d.record("isolation.failed", map[string]any{"error": err.Error()})
		return err
	}
	service, err := listen(d.cfg.ServiceSocket)
	if err != nil {
		return err
	}
	defer service.Close()
	admin, err := listen(d.cfg.AdminSocket)
	if err != nil {
		return err
	}
	defer admin.Close()

	var wg sync.WaitGroup
	wg.Go(func() { d.accept(ctx, service, ipc.Service, *d.cfg.ServiceUID, ipc.MaxServiceConns, &wg) })
	wg.Go(func() { d.accept(ctx, admin, ipc.Admin, *d.cfg.AdminUID, maxAdminConns, &wg) })
	<-ctx.Done()
	service.Close()
	admin.Close()
	wg.Wait()
	return nil
}

// listen creates a socket with mode 0660 in a directory that others cannot
// enter (section 5.1). A stale socket from an earlier run is replaced; any
// other file in its place is an error.
func listen(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	if err := checkMode(dir, 0o750); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("walletd: %s exists and is not a socket", path)
		}
		os.Remove(path)
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// accept serves the connections of one socket, at most max at once; one
// beyond is closed at once.
func (d *Daemon) accept(ctx context.Context, l *net.UnixListener, sock ipc.Socket, uid uint32, max int, wg *sync.WaitGroup) {
	slots := make(chan struct{}, max)
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			d.log.Error("accept", "socket", sock.String(), "err", err)
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		wg.Go(func() {
			// The slot is free before the connection closes, so that whoever
			// sees it closed can connect again at once.
			defer c.Close()
			defer func() { <-slots }()
			d.serveConn(ctx, c, sock, uid)
		})
	}
}

// serveConn answers the requests of one connection in turn. The kernel
// certifies who is at the other end, and only the user configured for the
// socket stays. Hello comes first; a request whose envelope does not decode
// ends the connection, since it may have been read only in part.
func (d *Daemon) serveConn(ctx context.Context, c *net.UnixConn, sock ipc.Socket, want uint32) {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if uid, err := ipc.PeerUID(c); err != nil || uid != want {
		d.record("peer.refused", map[string]any{"socket": sock.String(), "uid": uid})
		return
	}
	limits := ipc.DefaultConnLimits()
	greeted := false
	for {
		frame, err := ipc.ReadFrame(c, limits)
		if err != nil {
			var e *ipc.Error
			if errors.As(err, &e) {
				d.send(c, limits, nil, nil, e)
			}
			return
		}
		req, err := d.codec.DecodeRequest(sock, frame)
		if err != nil {
			d.send(c, limits, req.ID, nil, asError(err))
			return
		}
		if !greeted && req.T != ipc.MsgHello {
			d.send(c, limits, req.ID, nil, &ipc.Error{Code: ipc.Malformed, Detail: "Hello comes first"})
			return
		}
		resp, err := d.handle(ctx, sock, req)
		if err != nil {
			e := d.failure(req.T, err)
			if !d.send(c, limits, req.ID, nil, e) || req.T == ipc.MsgHello {
				return
			}
			continue
		}
		if !d.send(c, limits, req.ID, resp, nil) {
			return
		}
		greeted = true
	}
}

// send writes a response, or the error of a failed one.
func (d *Daemon) send(c net.Conn, limits ipc.ConnLimits, id []byte, body ipc.Body, e *ipc.Error) bool {
	var frame []byte
	var err error
	if e != nil {
		frame, err = d.codec.EncodeError(id, e)
	} else {
		frame, err = d.codec.EncodeResponse(id, body)
	}
	if err == nil {
		err = ipc.WriteFrame(c, frame, limits)
	}
	if err != nil {
		d.log.Error("write response", "err", err)
		return false
	}
	return true
}

// failure turns an error into the error of a failed response. One that is
// not a protocol error is a bug: the audit records it, and the other end
// learns only that it happened (section 5.6).
func (d *Daemon) failure(t string, err error) *ipc.Error {
	var e *ipc.Error
	if errors.As(err, &e) {
		return e
	}
	d.record("internal_error", map[string]any{"request": t, "error": err.Error()})
	d.log.Error("internal error", "request", t, "err", err)
	return &ipc.Error{Code: ipc.Internal, Detail: "internal error"}
}

func asError(err error) *ipc.Error {
	var e *ipc.Error
	if errors.As(err, &e) {
		return e
	}
	return &ipc.Error{Code: ipc.Malformed, Detail: ipc.Detail(err.Error())}
}

// fail returns a protocol error with a detail made safe to send.
func fail(code ipc.Code, format string, args ...any) *ipc.Error {
	return &ipc.Error{Code: code, Detail: ipc.Detail(fmt.Sprintf(format, args...))}
}
