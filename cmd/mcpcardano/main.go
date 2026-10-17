// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Command mcpcardano is the person's CLI. In milestone H-1 it has the MCP
// bridge that MCP clients start:
//
//	mcpcardano mcp [-socket path]
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
	fmt.Fprintln(os.Stderr, "usage: mcpcardano mcp [-socket path]")
	return 2
}

func run(args []string) int {
	if len(args) == 0 || args[0] != "mcp" {
		return usage()
	}
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	socket := fs.String("socket", cli.DefaultSocket(), "the server's MCP socket (or set "+cli.SocketEnv+")")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 {
		return usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cli.Bridge(ctx, *socket, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mcpcardano:", err)
		return 1
	}
	return 0
}
