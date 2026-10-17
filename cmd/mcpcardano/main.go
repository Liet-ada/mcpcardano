// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Command mcpcardano is the person's CLI. In milestone H-1 it has the MCP
// bridge that MCP clients start, and the mode A signer:
//
//	mcpcardano mcp [-socket path]
//	mcpcardano sign <draft_id>
//	mcpcardano signer
//	mcpcardano signer init [-network preprod]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Liet-ada/mcpcardano/internal/cli"
)

func main() { os.Exit(run(os.Args[1:])) }

func usage() int {
	fmt.Fprintln(os.Stderr, "usage: mcpcardano mcp | sign <draft_id> | signer | signer init")
	return cli.ExitUsage
}

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func run(args []string) int {
	if len(args) == 0 {
		return usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "mcp":
		fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
		socket := fs.String("socket", cli.DefaultSocket(), "the server's MCP socket (or set "+cli.SocketEnv+")")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 {
			return usage()
		}
		if err := cli.Bridge(ctx, *socket, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "mcpcardano:", err)
			return cli.ExitError
		}
		return cli.ExitOK
	case "sign":
		return cli.Sign(ctx, args[1:], version, os.Stdout, os.Stderr)
	case "signer":
		return cli.Signer(ctx, args[1:], version, os.Stdout, os.Stderr)
	}
	return usage()
}
