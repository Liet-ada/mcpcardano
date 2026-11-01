// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Liet-ada/mcpcardano/internal/doctor"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/tui"
)

// view opens the interactive view (section 6.4) on the terminal. It keeps
// its own connection to the admin socket, which it makes again if the
// wallet restarts.
func (a *admin) view(*options, []string) error {
	in, okIn := a.in.(*os.File)
	out, okOut := a.out.(*os.File)
	if !okIn || !okOut || !isTerminal(int(in.Fd())) || !isTerminal(int(out.Fd())) {
		return errors.New("the view needs a terminal; the other commands work without one")
	}
	conn := &tui.Conn{Socket: a.socket, Hello: a.hello}
	defer conn.Close()
	if _, err := conn.Status(a.ctx); err != nil {
		var e *ipc.Error
		if !errors.As(err, &e) {
			err = fmt.Errorf("%w at %s: %v", errUnreachable, a.socket, err)
		}
		return err
	}
	check := func(ctx context.Context) (doctor.Report, error) {
		env, err := doctor.NewEnv(strings.TrimPrefix(a.hello.Software, "mcpcardano "))
		if err != nil {
			return nil, err
		}
		return doctor.Run(ctx, env), nil
	}
	return tui.Run(a.ctx, conn, a.keys.open, a.network, check, in, out)
}
