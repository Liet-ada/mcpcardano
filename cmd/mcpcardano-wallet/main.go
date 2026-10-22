// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Command mcpcardano-wallet is the wallet of mcpcardano: a process apart,
// with its own user and no network, that keeps the keys of the wallets of
// modes B and C and signs only what their policies allow.
//
//	mcpcardano-wallet -config config.json          serve the two sockets
//	mcpcardano-wallet -config config.json -check   only check the configuration
//	mcpcardano-wallet -config config.json init     create the key store
//
// init reads the password from standard input, once, up to the end of the
// first line; the person's CLI asks for it without echo and passes it on.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/walletd"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// minPassword is the shortest password init accepts.
const minPassword = 8

func main() { os.Exit(run()) }

func run() int {
	config := flag.String("config", "", "path to config.json")
	check := flag.Bool("check", false, "check the configuration and exit")
	flag.Parse()
	if *config == "" || flag.NArg() > 1 || (flag.NArg() == 1 && flag.Arg(0) != "init") {
		flag.Usage()
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := walletd.LoadConfig(*config)
	if err != nil {
		logger.Error("configuration", "err", err)
		return 1
	}
	if *check {
		return 0
	}
	if flag.NArg() == 1 {
		return initialize(cfg, os.Stdin, logger)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d, err := walletd.Open(ctx, cfg, walletd.Options{Version: version, Logger: logger})
	if err != nil {
		logger.Error("start", "err", err)
		return 1
	}
	defer d.Close()
	logger.Info("serving", "service", cfg.ServiceSocket, "admin", cfg.AdminSocket, "network", string(cfg.Network))
	if err := d.Serve(ctx); err != nil {
		logger.Error("serve", "err", err)
		return 1
	}
	return 0
}

// initialize creates the key store with the password read from in.
func initialize(cfg walletd.Config, in io.Reader, logger *slog.Logger) int {
	password, err := readPassword(in)
	if err != nil {
		logger.Error("init", "err", err)
		return 1
	}
	defer clear(password)
	if err := walletd.Init(cfg, password); err != nil {
		logger.Error("init", "err", err)
		return 1
	}
	fmt.Println("key store created in", cfg.DataDir)
	return 0
}

func readPassword(in io.Reader) (model.Secret, error) {
	r := bufio.NewReaderSize(in, ipc.MaxSecret+2)
	line, err := r.ReadSlice('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading the password: %w", err)
	}
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	if len(line) < minPassword || len(line) > ipc.MaxSecret {
		return nil, fmt.Errorf("the password must have %d to %d bytes", minPassword, ipc.MaxSecret)
	}
	return model.Secret(append([]byte(nil), line...)), nil
}
