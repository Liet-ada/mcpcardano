// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// errCancelled reports an empty answer where a password was asked: the
// person declined, and nothing was done.
var errCancelled = errors.New("cancelled: nothing was done")

// readSecret reads a password or a recovery phrase, one line: from the
// terminal without echo, or from in as it comes when in is not a terminal,
// as in a script. The caller clears it once used (section 6.2).
func readSecret(ctx context.Context, in io.Reader, errOut io.Writer, prompt string) (model.Secret, error) {
	var s model.Secret
	var err error
	if f, ok := in.(*os.File); ok && isTerminal(int(f.Fd())) {
		fmt.Fprint(errOut, prompt)
		s, err = withoutEcho(ctx, int(f.Fd()), func() (model.Secret, error) { return readLine(f) })
		fmt.Fprintln(errOut)
	} else {
		s, err = readLine(in)
	}
	// An interrupt at the prompt declines, as an empty answer does.
	if (err == nil && len(s) == 0) || ctx.Err() != nil {
		clear(s)
		return nil, errCancelled
	}
	return s, err
}

// readLine reads up to a newline, one byte at a time so that nothing after
// it is consumed, and within ipc.MaxSecret bytes. Its buffer never grows, so
// no copy of the secret is left behind.
func readLine(in io.Reader) (model.Secret, error) {
	line := make(model.Secret, 0, ipc.MaxSecret)
	b := make([]byte, 1)
	for {
		n, err := in.Read(b)
		if n == 1 && b[0] == '\n' {
			break
		}
		if n == 1 {
			if len(line) == cap(line) {
				clear(line)
				return nil, fmt.Errorf("cli: more than %d bytes in one line", ipc.MaxSecret)
			}
			line = append(line, b[0])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			clear(line)
			return nil, fmt.Errorf("cli: %w", err)
		}
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line[n-1] = 0
		line = line[:n-1]
	}
	return line, nil
}
