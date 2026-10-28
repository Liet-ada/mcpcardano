// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Liet-ada/mcpcardano/internal/doctor"
	"github.com/Liet-ada/mcpcardano/internal/install"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// The commands that install, remove and check mcpcardano (sections 10.1 and
// 10.5; decision 134). install and uninstall run as root; doctor as the
// person.

// minPassword is the shortest password of a key store, as the wallet's init
// requires: install checks it before it changes anything.
const minPassword = 8

// deletePhrase is what the person types to delete the data with uninstall.
const deletePhrase = "delete the wallets"

// Install runs mcpcardano install.
func Install(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(errOut)
	o := install.Options{}
	fs.StringVar(&o.Person, "user", os.Getenv("SUDO_USER"), "the person, who joins the group and whom the admin socket admits; whoever ran sudo by default")
	network := fs.String("network", "", "the network of a first install: preprod, the default, or preview")
	fs.StringVar(&o.DataSource, "datasource", "", "the data source of a first install: koios, the default, or blockfrost, or several in order of preference, as blockfrost,koios")
	fs.StringVar(&o.DataSourceURL, "datasource-url", "", "the URL of a single data source, if not its public one")
	fs.StringVar(&o.Unlock, "unlock", "", "how the wallet unlocks when it starts: "+install.UnlockPassword+", the default, or "+install.UnlockMachine+", with a TPM2 on Linux")
	fs.BoolVar(&o.FIDOOwner, "fido-owner", false, "give the security keys to the person alone, also over SSH, on Linux")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(errOut, "usage: sudo mcpcardano install [-network preprod] [-datasource koios] [-datasource-url url] [-unlock password|machine] [-fido-owner] [-user name]")
		return ExitUsage
	}
	o.Network = model.Network(*network)
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		fmt.Fprintln(errOut, "mcpcardano: cannot find the binaries:", err)
		return ExitError
	}
	o.Source = filepath.Dir(exe)
	m := install.NewMachine(out)
	if err := m.Check(&o); err != nil {
		fmt.Fprintln(errOut, "mcpcardano:", err)
		return ExitError
	}
	var password model.Secret
	if m.NeedsPassword() {
		if password, err = newPassword(ctx, in, errOut); err != nil {
			return report(errOut, err)
		}
		defer clear(password)
	}
	if slices.Contains(o.Sources, "blockfrost") {
		fmt.Fprintf(errOut, "Blockfrost needs the project id of a project for %s, from blockfrost.io. It is not shown, and only the server reads it.\n", o.Network)
		if o.BlockfrostKey, err = readSecret(ctx, in, errOut, "Project id: "); err != nil {
			return report(errOut, err)
		}
		defer clear(o.BlockfrostKey)
	}
	if err := m.Install(o, password); err != nil {
		fmt.Fprintln(errOut, "mcpcardano:", err)
		return ExitError
	}
	return ExitOK
}

// newPassword asks for the password of a new key store twice, without echo,
// or reads it once from a script.
func newPassword(ctx context.Context, in io.Reader, errOut io.Writer) (model.Secret, error) {
	fmt.Fprintln(errOut, "The wallet keeps its keys encrypted with a password, which unlocks it and authorizes until you register a security key.")
	p, err := readSecret(ctx, in, errOut, fmt.Sprintf("Password, at least %d bytes: ", minPassword))
	if err != nil {
		return nil, err
	}
	if len(p) < minPassword {
		clear(p)
		return nil, fmt.Errorf("the password must have at least %d bytes", minPassword)
	}
	if f, ok := in.(*os.File); !ok || !isTerminal(int(f.Fd())) {
		return p, nil
	}
	again, err := readSecret(ctx, in, errOut, "The same password again: ")
	defer clear(again)
	if err != nil || !bytes.Equal(p, again) {
		clear(p)
		if err == nil {
			err = errors.New("the two passwords differ: nothing was done")
		}
		return nil, err
	}
	return p, nil
}

// APIKey runs mcpcardano apikey set <name> and apikey remove <name>: the API
// keys of the server's data sources, as Blockfrost's project id, which
// systemd-creds keeps encrypted for the server alone (decision 138), or, on
// macOS, a file of the server's user (decision 139). set asks for the key
// without echo, or reads a line from a script.
func APIKey(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) != 2 || (args[0] != "set" && args[0] != "remove") {
		fmt.Fprintln(errOut, "usage: sudo mcpcardano apikey set <name>\n       sudo mcpcardano apikey remove <name>")
		return ExitUsage
	}
	name := args[1]
	m := install.NewMachine(out)
	if err := m.CheckAPIKey(name); err != nil {
		fmt.Fprintln(errOut, "mcpcardano:", err)
		return ExitError
	}
	var err error
	if args[0] == "remove" {
		err = m.RemoveAPIKey(name)
	} else {
		fmt.Fprintf(errOut, "The key %s is encrypted for the server alone. It is not shown.\n", name)
		var key model.Secret
		if key, err = readSecret(ctx, in, errOut, "Key: "); err != nil {
			return report(errOut, err)
		}
		defer clear(key)
		err = m.SetAPIKey(name, key)
	}
	if err != nil {
		fmt.Fprintln(errOut, "mcpcardano:", err)
		return ExitError
	}
	return ExitOK
}

// Uninstall runs mcpcardano uninstall. With -delete-data it asks the person
// to type a phrase first.
func Uninstall(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(errOut)
	deleteData := fs.Bool("delete-data", false, "delete also the configuration, the key store and the records")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(errOut, "usage: sudo mcpcardano uninstall [-delete-data]")
		return ExitUsage
	}
	m := install.NewMachine(out)
	if err := m.CheckUninstall(); err != nil {
		fmt.Fprintln(errOut, "mcpcardano:", err)
		return ExitError
	}
	if *deleteData {
		fmt.Fprintf(errOut, "This deletes %s, with the configuration, the key store of every wallet, their policies and the records.\n",
			strings.Join(m.Data(), ", "))
		fmt.Fprintln(errOut, "The funds of a wallet whose recovery phrase is not written down are lost.")
		fmt.Fprintf(errOut, "Type %q to go on: ", deletePhrase)
		line, err := readLine(in)
		if err != nil {
			return report(errOut, err)
		}
		if strings.TrimSpace(string(line)) != deletePhrase {
			return report(errOut, errCancelled)
		}
	}
	if err := m.Uninstall(*deleteData); err != nil {
		fmt.Fprintln(errOut, "mcpcardano:", err)
		return ExitError
	}
	return ExitOK
}

// Doctor runs mcpcardano doctor: 0 if nothing failed, 1 otherwise.
func Doctor(ctx context.Context, args []string, version string, out, errOut io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintln(errOut, "usage: mcpcardano doctor")
		return ExitUsage
	}
	env, err := doctor.NewEnv(version)
	if err != nil {
		fmt.Fprintln(errOut, "mcpcardano:", err)
		return ExitError
	}
	r := doctor.Run(ctx, env)
	r.Write(out)
	if r.Failed() {
		return ExitError
	}
	return ExitOK
}
