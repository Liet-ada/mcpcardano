// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Command mcpcardano is the person's CLI: the MCP bridge that MCP clients
// start, the mode A signer, the commands on the wallet's admin socket, and
// those that install and check mcpcardano (section 6.1):
//
//	sudo mcpcardano install [-network preprod] [-unlock password|machine] ...
//	sudo mcpcardano uninstall [-delete-data]
//	mcpcardano doctor
//	mcpcardano mcp [-socket path]
//	mcpcardano sign <draft_id>
//	mcpcardano signer
//	mcpcardano signer init [-network preprod]
//	mcpcardano status | unlock | approve <id> | reject <id> | freeze | unfreeze
//	mcpcardano session open | session close
//	mcpcardano policy show | policy set
//	mcpcardano budget pending | budget release
//	mcpcardano wallet create | wallet restore | wallet backup
//	mcpcardano audit show | audit verify
//	mcpcardano key add | key remove | key list
//	mcpcardano recover start | recover status | recover cancel
//	mcpcardano view                                  the interactive view
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Liet-ada/mcpcardano/internal/cli"
)

func main() { os.Exit(run(os.Args[1:])) }

func usage() int {
	lines := append([]string{"install", "uninstall", "doctor", "mcp", "sign <draft_id>", "signer", "signer init"}, cli.AdminUsage()...)
	fmt.Fprintln(os.Stderr, "usage: mcpcardano "+strings.Join(lines, "\n       mcpcardano "))
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
	case "install":
		return cli.Install(ctx, args[1:], os.Stdin, os.Stdout, os.Stderr)
	case "uninstall":
		return cli.Uninstall(ctx, args[1:], os.Stdin, os.Stdout, os.Stderr)
	case "doctor":
		return cli.Doctor(ctx, args[1:], version, os.Stdout, os.Stderr)
	case "sign":
		return cli.Sign(ctx, args[1:], version, os.Stdout, os.Stderr)
	case "signer":
		return cli.Signer(ctx, args[1:], version, os.Stdout, os.Stderr)
	}
	if cli.IsAdminCommand(args[0]) {
		return cli.Admin(ctx, args, version, os.Stdin, os.Stdout, os.Stderr)
	}
	return usage()
}
