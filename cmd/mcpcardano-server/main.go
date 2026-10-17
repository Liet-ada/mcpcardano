// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Command mcpcardano-server is the MCP server of mcpcardano.
//
//	mcpcardano-server -config config.json     serve MCP on the configured socket
//	mcpcardano-server -config config.json -check   only check the configuration
//	mcpcardano-server -new-wallet-id          print a fresh wallet id
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/server"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	config := flag.String("config", "", "path to config.json")
	check := flag.Bool("check", false, "check the configuration and exit")
	newID := flag.Bool("new-wallet-id", false, "print a fresh wallet id and exit")
	flag.Parse()
	if *newID {
		id, err := model.NewWalletID(nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(id)
		return 0
	}
	if *config == "" || flag.NArg() > 0 {
		flag.Usage()
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	c, err := server.Load(*config)
	if err != nil {
		logger.Error("configuration", "err", err)
		return 1
	}
	settings, warnings, err := server.Resolve(c)
	if err != nil {
		logger.Error("configuration", "err", err)
		return 1
	}
	for _, w := range warnings {
		logger.Warn("configuration: " + w)
	}
	if *check {
		fmt.Printf("configuration ok: %s, %d wallets, socket %s\n", settings.Network, len(settings.Wallets), settings.Socket)
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.Run(ctx, settings, server.Options{Logger: logger, Version: version}); err != nil {
		logger.Error("server", "err", err)
		return 1
	}
	return 0
}
