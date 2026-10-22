// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Environment variables that override the defaults of the wallet's admin
// socket and network.
const (
	AdminSocketEnv = "MCPCARDANO_ADMIN_SOCKET"
	NetworkEnv     = "MCPCARDANO_NETWORK"
)

// DefaultAdminSocket is where the wallet's admin socket lives once installed:
// in the wallet's own runtime directory (section 5.1).
func DefaultAdminSocket() string {
	if s := os.Getenv(AdminSocketEnv); s != "" {
		return s
	}
	if runtime.GOOS == "darwin" {
		return "/private/var/run/mcpcardano-wallet/admin.sock"
	}
	return "/run/mcpcardano-wallet/admin.sock"
}

func defaultNetwork() string {
	if n := os.Getenv(NetworkEnv); n != "" {
		return n
	}
	return string(model.Preprod)
}

// options are the flags of the admin commands; each command defines those
// it takes.
type options struct {
	wallet, label string
	name          string
	template      bool
	duration      time.Duration
	max           string
	from          uint64
	limit         uint
}

func walletFlag(fs *flag.FlagSet, o *options) {
	fs.StringVar(&o.wallet, "wallet", "", "the wallet's id")
}

// command is a command of the admin socket: its usage after its name, its
// flags, how many arguments it takes (-1 for any number) and what it does.
type command struct {
	usage string
	flags func(*flag.FlagSet, *options)
	nargs int
	run   func(*admin, *options, []string) error
}

// commands are the person's commands of section 6.1 that go to the wallet.
var commands = map[string]command{
	"status":   {"", nil, 0, (*admin).status},
	"unlock":   {"", nil, 0, (*admin).unlock},
	"approve":  {"<approval_id>", nil, 1, (*admin).approve},
	"reject":   {"<approval_id>", nil, 1, (*admin).reject},
	"freeze":   {"[-wallet id]", walletFlag, 0, (*admin).freeze},
	"unfreeze": {"-wallet id", walletFlag, 0, (*admin).unfreeze},
	"session open": {"-wallet id -for 1h -max lovelace", func(fs *flag.FlagSet, o *options) {
		walletFlag(fs, o)
		fs.DurationVar(&o.duration, "for", 0, "how long the session lasts")
		fs.StringVar(&o.max, "max", "", "the most it lets the wallet spend, in lovelace")
	}, 0, (*admin).sessionOpen},
	"session close":  {"-wallet id", walletFlag, 0, (*admin).sessionClose},
	"policy show":    {"-wallet id | -template", policyFlags, 0, (*admin).policyShow},
	"policy set":     {"-wallet id | -template <policy.json>", policyFlags, 1, (*admin).policySet},
	"budget pending": {"[-wallet id]", walletFlag, 0, (*admin).budgetPending},
	"budget release": {"-wallet id [transaction ...]", walletFlag, -1, (*admin).budgetRelease},
	"wallet create": {"-label name", func(fs *flag.FlagSet, o *options) {
		fs.StringVar(&o.label, "label", "", "a name for the wallet")
	}, 0, (*admin).walletCreate},
	"wallet restore": {"-label name", func(fs *flag.FlagSet, o *options) {
		fs.StringVar(&o.label, "label", "", "a name for the wallet")
	}, 0, (*admin).walletRestore},
	"wallet backup": {"-wallet id", walletFlag, 0, (*admin).walletBackup},
	"audit show": {"[-from seq] [-limit 20]", func(fs *flag.FlagSet, o *options) {
		fs.Uint64Var(&o.from, "from", 0, "the first entry")
		fs.UintVar(&o.limit, "limit", 20, fmt.Sprintf("how many entries, up to %d", ipc.MaxAuditPage))
	}, 0, (*admin).auditShow},
	"audit verify":   {"", nil, 0, (*admin).auditVerify},
	"key add":        {"-name name", nameFlag, 0, (*admin).keyAdd},
	"key remove":     {"-name name", nameFlag, 0, (*admin).keyRemove},
	"key list":       {"", nil, 0, (*admin).keyList},
	"recover start":  {"", nil, 0, (*admin).recoverStart},
	"recover status": {"", nil, 0, (*admin).recoverStatus},
	"recover cancel": {"", nil, 0, (*admin).recoverCancel},
	"view":           {"", nil, 0, (*admin).view},
}

func policyFlags(fs *flag.FlagSet, o *options) {
	walletFlag(fs, o)
	fs.BoolVar(&o.template, "template", false, "the template of the wallets the agent creates")
}

// IsAdminCommand reports whether name starts a command of the admin socket.
func IsAdminCommand(name string) bool {
	for c := range commands {
		if c == name || strings.HasPrefix(c, name+" ") {
			return true
		}
	}
	return false
}

// AdminUsage lists the commands of the admin socket.
func AdminUsage() []string {
	var out []string
	for name, c := range commands {
		out = append(out, strings.TrimSpace(name+" "+c.usage))
	}
	slices.Sort(out)
	return out
}

// errUsage reports arguments the command does not take.
var errUsage = errors.New("usage")

// errUnreachable reports a wallet that does not answer on its admin socket.
var errUnreachable = errors.New("the wallet does not answer")

// Admin runs one of the person's commands on the wallet's admin socket
// (section 6.1). Reducing the risk needs no authorization; what raises what
// can be spent shows the summary the wallet computed and asks for a touch of
// a registered security key, or the password when there is none (section
// 6.2). The exit code is that of section 6.5.
func Admin(ctx context.Context, args []string, version string, in io.Reader, out, errOut io.Writer) int {
	return runAdmin(ctx, args, version, in, out, errOut, defaultKeys)
}

// runAdmin is Admin with the way to the security key, which the tests
// replace with a key in software.
func runAdmin(ctx context.Context, args []string, version string, in io.Reader, out, errOut io.Writer, k keys) int {
	name, rest := args[0], args[1:]
	if _, ok := commands[name]; !ok && len(rest) > 0 {
		name, rest = name+" "+rest[0], rest[1:]
	}
	c, ok := commands[name]
	if !ok {
		fmt.Fprintln(errOut, "usage: mcpcardano "+strings.Join(AdminUsage(), "\n       mcpcardano "))
		return ExitUsage
	}
	usage := func() int {
		fmt.Fprintf(errOut, "usage: mcpcardano %s [-admin path] [-network preprod]\n", strings.TrimSpace(name+" "+c.usage))
		return ExitUsage
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	socket := fs.String("admin", DefaultAdminSocket(), "the wallet's admin socket (or set "+AdminSocketEnv+")")
	network := fs.String("network", defaultNetwork(), "the wallet's network (or set "+NetworkEnv+")")
	var o options
	if c.flags != nil {
		c.flags(fs, &o)
	}
	args, err := parseAnywhere(fs, rest)
	if err != nil || (c.nargs >= 0 && len(args) != c.nargs) {
		return usage()
	}
	a := &admin{ctx: ctx, socket: *socket, hello: ipc.Hello{Software: "mcpcardano " + version, Network: *network},
		codec: ipc.NewCodec(), in: in, out: out, errOut: errOut, network: *network, keys: k, command: name}
	defer a.close()
	err = c.run(a, &o, args)
	if errors.Is(err, errUsage) {
		if msg := strings.TrimPrefix(err.Error(), errUsage.Error()); msg != "" {
			fmt.Fprintln(errOut, "mcpcardano"+msg)
		}
		return usage()
	}
	return report(errOut, err)
}

// parseAnywhere parses the flags wherever they come among the arguments, as
// in `mcpcardano approve <id> -admin path`, and returns the arguments; after
// "--" everything is an argument.
func parseAnywhere(fs *flag.FlagSet, args []string) ([]string, error) {
	var out []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return out, nil
		}
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			return append(out, rest...), nil
		}
		out, args = append(out, rest[0]), rest[1:]
	}
}

// usageError reports what is wrong with the arguments.
func usageError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errUsage}, args...)...)
}

// report writes err, if any, and returns its exit code (section 6.5).
func report(errOut io.Writer, err error) int {
	if err == nil {
		return ExitOK
	}
	var e *ipc.Error
	if !errors.As(err, &e) {
		// The error may carry what a security key said about itself.
		fmt.Fprintln(errOut, "mcpcardano:", ipc.Detail(err.Error()))
		switch {
		case errors.Is(err, errCancelled), errors.Is(err, errKeyRefused):
			return ExitRejected
		case errors.Is(err, errUnreachable):
			return ExitUnavailable
		}
		return ExitError
	}
	msg := e.Detail
	if msg == "" {
		msg = strings.ToLower(strings.ReplaceAll(string(e.Code), "_", " "))
	}
	fmt.Fprintf(errOut, "mcpcardano: %s (%s)\n", msg, e.Code)
	switch e.Code {
	case ipc.AuthFailed, ipc.AuthExpired, ipc.RateLimited:
		return ExitRejected
	case ipc.Locked:
		fmt.Fprintln(errOut, "Unlock it with: mcpcardano unlock")
		return ExitUnavailable
	case ipc.NetworkMismatch:
		fmt.Fprintln(errOut, "Name its network with -network or "+NetworkEnv+".")
	}
	return ExitError
}

// admin is a command's connection to the wallet's admin socket. It connects
// at the first call, after the command has checked its arguments: wrong
// usage is exit 2 whether the wallet runs or not.
type admin struct {
	ctx         context.Context
	socket      string
	hello       ipc.Hello
	client      *ipc.Client
	codec       *ipc.Codec
	in          io.Reader
	out, errOut io.Writer
	network     string
	keys        keys
	command     string            // the command's name, as "recover status"
	st          *ipc.StatusReport // the status when the command connected
}

func (a *admin) call(t string, req, resp ipc.Body) error {
	if a.client == nil {
		c, err := ipc.Dial(a.ctx, a.socket, a.hello)
		var e *ipc.Error
		if err != nil && !errors.As(err, &e) {
			err = fmt.Errorf("%w at %s: %v", errUnreachable, a.socket, err)
		}
		if err != nil {
			return err
		}
		a.client = c
		// Every command learns the status first, to warn of a recovery that
		// is waiting and to know whether a key is registered.
		var st ipc.StatusReport
		if c.Call(a.ctx, ipc.MsgStatus, &ipc.Empty{}, &st) == nil {
			a.st = &st
			a.warnRecovery(&st)
		}
	}
	return a.client.Call(a.ctx, t, req, resp)
}

func (a *admin) close() {
	if a.client != nil {
		a.client.Close()
	}
}

func (a *admin) printf(format string, args ...any) { fmt.Fprintf(a.out, format, args...) }

// secret asks for a password or a recovery phrase.
func (a *admin) secret(prompt string) (model.Secret, error) {
	return readSecret(a.ctx, a.in, a.errOut, prompt)
}

// authorize runs an action that raises what can be spent (section 6.2): it
// shows the summary the wallet computed, as it comes, asks for a touch of a
// registered key, with its PIN if the action needs it, or for the password,
// and decodes the action's result into result. An empty password or PIN
// declines.
func (a *admin) authorize(action string, params, result ipc.Body) error {
	raw, err := a.codec.Encode(params)
	if err != nil {
		return err
	}
	defer clear(raw) // restore_wallet carries the recovery phrase
	var ch ipc.Challenge
	if err := a.call(ipc.MsgBeginAuthorization, &ipc.BeginAuthorization{Action: action, Params: raw}, &ch); err != nil {
		return err
	}
	fmt.Fprintln(a.errOut, "The wallet asks you to confirm:")
	for _, line := range ch.Summary {
		fmt.Fprintln(a.errOut, "  "+line)
	}
	complete := &ipc.CompleteAuthorization{AuthID: ch.AuthID}
	if ch.Methods[0] == ipc.MethodKey {
		if complete.Assertion, err = a.assert(&ch); err != nil {
			return err
		}
	} else {
		if complete.Password, err = a.secret(fmt.Sprintf("Password, before %s (empty to decline): ", clock(ch.ExpiresAt))); err != nil {
			return err
		}
		defer clear(complete.Password)
	}
	var done ipc.Completed
	if err := a.call(ipc.MsgCompleteAuthorization, complete, &done); err != nil {
		return err
	}
	if result == nil {
		result = &ipc.Empty{}
	}
	return a.codec.DecodeBody(done.Result, result)
}

// clock writes a Unix time as the local time of day, or with its date if it
// is not today.
func clock(unix int64) string {
	t := time.Unix(unix, 0)
	if t.Format(time.DateOnly) != time.Now().Format(time.DateOnly) {
		return t.Format(time.DateTime)
	}
	return t.Format(time.TimeOnly)
}

// ada writes lovelace as ADA with six decimals, as the wallet's summaries do.
func ada(lovelace uint64) string {
	return fmt.Sprintf("%d.%06d ADA", lovelace/1_000_000, lovelace%1_000_000)
}
