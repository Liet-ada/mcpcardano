// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/mcpclient"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/signer"
)

// Exit codes of the CLI (section 6.5).
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitRejected    = 3 // the authorization was refused, expired or declined
	ExitUnavailable = 4 // the wallet does not answer, or is locked
)

// HWCLIEnv names the environment variable with the path of cardano-hw-go.
const HWCLIEnv = "MCPCARDANO_HW_CLI"

// common are the flags of the signing commands.
type common struct {
	socket, hwCLI, keys string
}

func (c *common) flags(fs *flag.FlagSet) {
	keys, _ := signer.DefaultKeysDir()
	hw := os.Getenv(HWCLIEnv)
	if hw == "" {
		hw = "cardano-hw-go"
	}
	fs.StringVar(&c.socket, "socket", DefaultSocket(), "the server's MCP socket (or set "+SocketEnv+")")
	fs.StringVar(&c.hwCLI, "hw-cli", hw, "the cardano-hw-go executable (or set "+HWCLIEnv+")")
	fs.StringVar(&c.keys, "keys", keys, "where the hardware wallet's signing files are kept")
}

func (c *common) signer(client signer.Caller, log *slog.Logger) *signer.Signer {
	return &signer.Signer{Client: client, Device: signer.HWCLI{Path: c.hwCLI}, KeysDir: c.keys, Logger: log}
}

// Sign is `mcpcardano sign <draft>`: it takes one mode A draft to the
// hardware wallet by hand, for when the signer is not running.
func Sign(ctx context.Context, args []string, version string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var c common
	c.flags(fs)
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: mcpcardano sign [-socket path] [-hw-cli path] <draft_id>")
		return ExitUsage
	}
	client, err := mcpclient.Dial(ctx, c.socket, version)
	if err != nil {
		fmt.Fprintln(errOut, "mcpcardano:", err)
		return ExitError
	}
	defer client.Close()
	r, err := c.signer(client, nil).Sign(ctx, fs.Arg(0), func(line string) {
		fmt.Fprintln(out, line)
		fmt.Fprintln(out, "Check it on the hardware wallet's screen and confirm there.")
	})
	switch {
	case errors.Is(err, signer.ErrRejected):
		fmt.Fprintln(errOut, "mcpcardano: rejected on the hardware wallet; the draft is", r.State)
		return ExitRejected
	case err != nil:
		fmt.Fprintln(errOut, "mcpcardano:", err)
		return ExitError
	}
	fmt.Fprintln(out, "Sent: the draft is", r.State)
	return ExitOK
}

// Signer is `mcpcardano signer`, the mode A signer in the background
// (section 6.6), and `mcpcardano signer init`, which prepares a hardware
// wallet for it.
func Signer(ctx context.Context, args []string, version string, out, errOut io.Writer) int {
	if len(args) > 0 && args[0] == "init" {
		return signerInit(ctx, args[1:], out, errOut)
	}
	fs := flag.NewFlagSet("signer", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var c common
	c.flags(fs)
	every := fs.Duration("every", 5*time.Second, "how often to look for drafts to sign")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(errOut, "usage: mcpcardano signer [-socket path] [-hw-cli path] [-every 5s] | signer init [-network preprod]")
		return ExitUsage
	}
	log := slog.New(slog.NewTextHandler(errOut, nil))
	log.Info("signer started", "socket", c.socket, "keys", c.keys)
	c.signer(nil, log).CheckDevice(ctx)
	// Reconnect when the server restarts, until the person stops the signer.
	for ctx.Err() == nil {
		client, err := mcpclient.Dial(ctx, c.socket, version)
		if err == nil {
			s := c.signer(client, log)
			s.Notify = signer.SystemNotify
			err = s.Run(ctx, *every)
			client.Close()
		}
		if err != nil && ctx.Err() == nil {
			log.Warn("server unreachable; retrying", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(10 * time.Second):
			}
		}
	}
	return ExitOK
}

func signerInit(ctx context.Context, args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("signer init", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var c common
	c.flags(fs)
	network := fs.String("network", string(model.Preprod), "preprod or preview; mainnet stays disabled")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(errOut, "usage: mcpcardano signer init [-network preprod] [-hw-cli path]")
		return ExitUsage
	}
	n := model.Network(*network)
	if n != model.Preprod && n != model.Preview {
		fmt.Fprintln(errOut, "mcpcardano: the network must be preprod or preview")
		return ExitUsage
	}
	fmt.Fprintln(out, "Connect and unlock the hardware wallet; it will ask to export the public keys of account 0, and to show the address.")
	s := c.signer(nil, nil)
	address, err := s.Init(ctx, n)
	if address != "" {
		fmt.Fprintln(out, "Address:", address)
	}
	if err != nil {
		fmt.Fprintln(errOut, "mcpcardano:", err)
		if errors.Is(err, signer.ErrRejected) {
			return ExitRejected
		}
		return ExitError
	}
	fmt.Fprintln(out, "Compare it with the one the device showed. Then add it as a wallet in the server's config.json,")
	fmt.Fprintln(out, "with an id from `mcpcardano-server -new-wallet-id`, and restart the server.")
	return ExitOK
}
