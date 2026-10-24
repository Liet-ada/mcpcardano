// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/datasource"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

func exampleConfig(t *testing.T) Config {
	t.Helper()
	c, err := Load(filepath.Join("testdata", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestResolveExample(t *testing.T) {
	s, warnings, err := Resolve(exampleConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) > 0 {
		t.Errorf("warnings %v", warnings)
	}
	w := s.Wallets[0]
	if s.Socket != "/var/lib/mcpcardano-server/mcp.sock" || s.WalletSocket != "/run/mcpcardano-wallet/service.sock" ||
		w.Mode != model.ModeA || w.Policy.Limits.PerTx != 100_000_000 ||
		w.Policy.UTxO.DustThreshold != 1_000_000 || len(w.Policy.Assets) != 1 {
		t.Errorf("settings %+v", s)
	}
}

func TestResolveRejects(t *testing.T) {
	cases := map[string]func(*Config){
		"mainnet":           func(c *Config) { c.Network = "mainnet" },
		"unknown network":   func(c *Config) { c.Network = "testnet" },
		"relative data dir": func(c *Config) { c.DataDir = "data" },
		"no source":         func(c *Config) { c.DataSource = nil },
		"unknown source":    func(c *Config) { c.DataSource[0].Kind = "ogmios" },
		"a source twice":    func(c *Config) { c.DataSource = append(c.DataSource, c.DataSource[0]) },
		"a name twice": func(c *Config) {
			c.DataSource = DataSources{{Kind: "koios", Name: "x"}, {Kind: "blockfrost", Name: "x"}}
		},
		"a name with a slash": func(c *Config) { c.DataSource[0].Name = "a/b" },
		"koios with a secret": func(c *Config) { c.DataSource[0].Secret = "koios" },
		"a secret that is a path": func(c *Config) {
			c.DataSource = DataSources{{Kind: "blockfrost", Secret: "../blockfrost"}}
		},
		"too many sources": func(c *Config) {
			c.DataSource = DataSources{{Kind: "koios"}, {Kind: "blockfrost"}, {Kind: "koios"}, {Kind: "blockfrost"}, {Kind: "koios"}}
		},
		"long socket":            func(c *Config) { c.Socket = "/" + strings.Repeat("s", maxSocketPath) },
		"relative wallet socket": func(c *Config) { c.WalletSocket = "wallet.sock" },
		"long wallet socket":     func(c *Config) { c.WalletSocket = "/" + strings.Repeat("s", maxSocketPath) },
		"bad wallet id":          func(c *Config) { c.Wallets[0].ID = "w_1" },
		"no label":               func(c *Config) { c.Wallets[0].Label = "" },
		"mainnet address": func(c *Config) {
			c.Wallets[0].Address = "addr1vpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5eg0yu80w"
		},
		"script address": func(c *Config) {
			c.Wallets[0].Address = "addr_test1zrphkx6acpnf78fuvxn0mkew3l0fd058hzquvz7w36x4gtupnz75xxcrtw79hu"
		},
		"amount with a point": func(c *Config) { c.Wallets[0].Policy.Limits.PerTx = "1.5" },
		"bad asset":           func(c *Config) { c.Wallets[0].Policy.Assets = map[string]string{"x": "1"} },
		"twice":               func(c *Config) { c.Wallets = append(c.Wallets, c.Wallets[0]) },
	}
	for name, change := range cases {
		c := exampleConfig(t)
		change(&c)
		if _, _, err := Resolve(c); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestResolveWithoutWallets: a server with neither wallets nor a wallet
// process only reads, and says so; with a wallet process alone it can pay.
func TestResolveWithoutWallets(t *testing.T) {
	c := exampleConfig(t)
	c.Wallets = nil
	if _, warnings, err := Resolve(c); err != nil || len(warnings) != 0 {
		t.Errorf("only a wallet process: %v, %v", warnings, err)
	}
	c.WalletSocket = ""
	if _, warnings, err := Resolve(c); err != nil || len(warnings) != 1 {
		t.Errorf("nothing to pay with: %v, %v", warnings, err)
	}
}

func TestResolveWarnsAboutZeros(t *testing.T) {
	c := exampleConfig(t)
	c.Wallets[0].Policy.Limits = LimitsConfig{}
	c.Wallets[0].Policy.Destinations = DestinationsConfig{}
	c.Wallets[0].Policy.Networks = nil
	_, warnings, err := Resolve(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 6 {
		t.Errorf("%d warnings: %v", len(warnings), warnings)
	}
}

// TestDataSources: the datasource field takes one source or a list of them
// in order of preference (decision 136).
func TestDataSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"network": "preprod", "data_dir": "/x", "wallets": [],
		"datasource": [{"kind": "blockfrost"}, {"kind": "koios", "url": "https://koios.example/api/v1"}]}`), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s, _, err := Resolve(c)
	want := []DataSourceConfig{{Kind: "blockfrost", Name: "blockfrost", Secret: "blockfrost"}, {Kind: "koios", Name: "koios", URL: "https://koios.example/api/v1"}}
	if err != nil || !slices.Equal(s.Sources, want) {
		t.Errorf("sources %+v, %v", s.Sources, err)
	}
	if s, _, err := Resolve(exampleConfig(t)); err != nil || len(s.Sources) != 1 || s.Sources[0].Kind != "koios" {
		t.Errorf("one source as an object: %+v, %v", s.Sources, err)
	}
	// Two of one kind, with their own names.
	c.DataSource = DataSources{{Kind: "koios"}, {Kind: "koios", Name: "my-koios", URL: "http://127.0.0.1:8053/api/v1"}}
	if s, _, err := Resolve(c); err != nil || s.Sources[1].Name != "my-koios" {
		t.Errorf("two Koios: %+v, %v", s.Sources, err)
	}
	for name, field := range map[string]string{
		"an unknown field in the object": `{"kind": "koios", "token": "x"}`,
		"an unknown field in the list":   `[{"kind": "koios"}, {"kind": "blockfrost", "key": "x"}]`,
		"a string":                       `"koios"`,
	} {
		os.WriteFile(path, []byte(`{"network": "preprod", "data_dir": "/x", "wallets": [], "datasource": `+field+`}`), 0o600)
		if _, err := Load(path); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestOpenSources: Blockfrost takes its key from the encrypted credential;
// without a usable key it is a source that does not answer, and the server
// starts with the others; a key in clear is for development, and warned
// about (decision 138).
func TestOpenSources(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	var logged bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logged, nil))
	s := Settings{Network: model.Preprod, DataDir: dir, Sources: []DataSourceConfig{
		{Kind: "blockfrost", Name: "blockfrost", Secret: "blockfrost"}, {Kind: "koios", Name: "koios"}}}

	got, err := openSources(s, log)
	if err != nil || len(got) != 2 || got[0].Name() != "blockfrost" || got[1].Name() != "koios" {
		t.Fatalf("no key: %v, %v", got, err)
	}
	if _, err := got[0].Tip(t.Context()); !errors.Is(err, datasource.ErrUnavailable) || !strings.Contains(err.Error(), "sudo mcpcardano apikey set blockfrost") {
		t.Errorf("Blockfrost without a key: %v", err)
	}
	if !strings.Contains(logged.String(), "cannot work") {
		t.Errorf("no warning: %s", logged.String())
	}

	creds := t.TempDir()
	os.WriteFile(filepath.Join(creds, "mcpcardano-server.blockfrost"), []byte("preprodFromSystemd\n"), 0o400)
	t.Setenv("CREDENTIALS_DIRECTORY", creds)
	logged.Reset()
	got, err = openSources(s, log)
	if _, ok := got[0].(*datasource.Blockfrost); err != nil || !ok || logged.Len() != 0 {
		t.Errorf("from the credential: %T, %v; logged %s", got[0], err, logged.String())
	}

	t.Setenv("CREDENTIALS_DIRECTORY", "")
	os.Mkdir(filepath.Join(dir, "secrets"), 0o700)
	os.WriteFile(filepath.Join(dir, "secrets", "blockfrost"), []byte("preprodAbc123\n"), 0o600)
	got, err = openSources(s, log)
	if _, ok := got[0].(*datasource.Blockfrost); err != nil || !ok || !strings.Contains(logged.String(), "file in clear") {
		t.Errorf("from a file in clear: %T, %v; logged %s", got[0], err, logged.String())
	}
	if strings.Contains(logged.String(), "preprodAbc123") {
		t.Error("the log shows the key")
	}

	os.WriteFile(filepath.Join(dir, "secrets", "blockfrost"), []byte("not a key\n"), 0o600)
	if got, err := openSources(s, log); err != nil || got[0].Name() != "blockfrost" {
		t.Errorf("a malformed key: %v, %v", got, err)
	} else if _, err := got[0].Tip(t.Context()); !errors.Is(err, datasource.ErrUnavailable) {
		t.Errorf("a malformed key: %v", err)
	}
	// A key anyone can read stops the server.
	os.Chmod(filepath.Join(dir, "secrets", "blockfrost"), 0o644)
	if _, err := openSources(s, log); err == nil || !strings.Contains(err.Error(), "mode 0600") {
		t.Errorf("a key others can read: %v", err)
	}
	os.Chmod(filepath.Join(dir, "secrets", "blockfrost"), 0o600)
	os.WriteFile(filepath.Join(dir, "secrets", "blockfrost"), []byte("preprodAbc123\n"), 0o600)
	s.Sources[0].URL = "http://blockfrost.example"
	if _, err := openSources(s, log); err == nil {
		t.Error("plain HTTP to another machine")
	}
}

func TestReadSecret(t *testing.T) {
	const key = "preprodSecretKey42"
	dir := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	secrets := filepath.Join(dir, "secrets")
	os.Mkdir(secrets, 0o700)
	path := filepath.Join(secrets, "bf")
	os.WriteFile(path, []byte(key+"\n"), 0o600)
	if got, plain, err := readSecret(dir, "bf"); err != nil || got != key || !plain {
		t.Errorf("got %q, %v, %v", got, plain, err)
	}
	os.Chmod(path, 0o640)
	if _, _, err := readSecret(dir, "bf"); err == nil || strings.Contains(err.Error(), key) {
		t.Errorf("readable by the group: %v", err)
	}
	os.Chmod(path, 0o600)
	os.Symlink(path, filepath.Join(secrets, "link"))
	if _, _, err := readSecret(dir, "link"); err == nil {
		t.Error("a symbolic link")
	}
	os.WriteFile(filepath.Join(secrets, "big"), bytes.Repeat([]byte("a"), maxSecretBytes+1), 0o600)
	if _, _, err := readSecret(dir, "big"); err == nil {
		t.Error("a file too large for a key")
	}

	// systemd's credential, under the server's prefix, comes first.
	creds := t.TempDir()
	os.WriteFile(filepath.Join(creds, "mcpcardano-server.bf"), []byte("fromSystemd"), 0o400)
	os.WriteFile(filepath.Join(creds, "other"), []byte("notOurs"), 0o400)
	t.Setenv("CREDENTIALS_DIRECTORY", creds)
	if got, plain, err := readSecret(dir, "bf"); err != nil || got != "fromSystemd" || plain {
		t.Errorf("credential: %q, %v, %v", got, plain, err)
	}
	if got, _, err := readSecret(dir, "other"); !errors.Is(err, fs.ErrNotExist) || got != "" {
		t.Errorf("in neither place: %q, %v", got, err)
	}
}

func TestLoadIsStrict(t *testing.T) {
	dir := t.TempDir()
	for name, text := range map[string]string{
		"unknown field": `{"network": "preprod", "data_dir": "/x", "datasource": {"kind": "koios"}, "wallets": [], "max_fee": "1"}`,
		"trailing data": `{"network": "preprod", "data_dir": "/x", "datasource": {"kind": "koios"}, "wallets": []} {}`,
		"number amount": `{"network": "preprod", "data_dir": "/x", "datasource": {"kind": "koios"}, "wallets": [{"id": "w_k3fq2mx7c4v6bn5ta2sd7hpely", "label": "a", "address": "x", "policy": {"limits": {"per_tx": 5}}}]}`,
	} {
		path := filepath.Join(dir, "config.json")
		os.WriteFile(path, []byte(text), 0o600)
		if _, err := Load(path); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// source is a data source that always answers.
type source struct{}

func (source) Name() string                       { return "test" }
func (source) Network() model.Network             { return model.Preprod }
func (source) CheckNetwork(context.Context) error { return nil }
func (source) Tip(context.Context) (datasource.Tip, error) {
	return datasource.Tip{Slot: 1, Time: time.Unix(0, 0)}, nil
}
func (source) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{}, datasource.ErrUnavailable
}
func (source) UTxOs(context.Context, model.Address) ([]chain.UTxO, error) { return nil, nil }
func (source) Account(context.Context, string) (datasource.Account, error) {
	return datasource.Account{}, datasource.ErrNotFound
}
func (source) Asset(context.Context, model.AssetID) (datasource.Asset, error) {
	return datasource.Asset{}, datasource.ErrNotFound
}
func (source) AssetByFingerprint(context.Context, string) (model.AssetID, error) {
	return model.AssetID{}, datasource.ErrNotFound
}
func (source) Transaction(context.Context, [32]byte) (datasource.Transaction, error) {
	return datasource.Transaction{}, datasource.ErrNotFound
}
func (source) Submit(context.Context, []byte, [32]byte) error { return datasource.ErrUnavailable }
func (source) Confirmations(_ context.Context, ids [][32]byte) (map[[32]byte]uint64, error) {
	return map[[32]byte]uint64{}, nil
}

// shortDir returns a directory whose path fits a Unix socket name; the
// temporary directory of macOS is too long.
func shortDir(t *testing.T) string {
	dir, err := os.MkdirTemp("/tmp", "mcpc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// session speaks MCP over the socket as a client does: JSON-RPC, one message
// per line.
type session struct {
	t    *testing.T
	conn net.Conn
	in   *bufio.Scanner
	id   int
}

func dial(t *testing.T, path string) *session {
	t.Helper()
	var conn net.Conn
	var err error
	for range 50 {
		if conn, err = net.Dial("unix", path); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	s := &session{t: t, conn: conn, in: bufio.NewScanner(conn)}
	s.in.Buffer(nil, 1<<20)
	s.request("initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "test", "version": "0"},
	})
	s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return s
}

func (s *session) send(msg any) {
	b, _ := json.Marshal(msg)
	if _, err := s.conn.Write(append(b, '\n')); err != nil {
		s.t.Fatal(err)
	}
}

func (s *session) request(method string, params any) map[string]any {
	s.t.Helper()
	s.id++
	s.send(map[string]any{"jsonrpc": "2.0", "id": s.id, "method": method, "params": params})
	for s.in.Scan() {
		var msg map[string]any
		if err := json.Unmarshal(s.in.Bytes(), &msg); err != nil {
			s.t.Fatal(err)
		}
		if msg["id"] == float64(s.id) {
			if msg["error"] != nil {
				s.t.Fatalf("%s: %v", method, msg["error"])
			}
			return msg["result"].(map[string]any)
		}
	}
	s.t.Fatalf("%s: no answer: %v", method, s.in.Err())
	return nil
}

// TestRun starts the server on a real socket, talks MCP to it and stops it.
func TestRun(t *testing.T) {
	dir := shortDir(t)
	c := exampleConfig(t)
	c.DataDir = filepath.Join(dir, "data")
	s, _, err := Resolve(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s, Options{Source: source{}, Version: "test"}) }()

	a := dial(t, s.Socket)
	res := a.request("tools/call", map[string]any{"name": "list_wallets", "arguments": map[string]any{}})
	wallets := res["structuredContent"].(map[string]any)["wallets"].([]any)
	if len(wallets) != 1 || wallets[0].(map[string]any)["wallet_id"] != "w_k3fq2mx7c4v6bn5ta2sd7hpely" {
		t.Fatalf("list_wallets: %v", res)
	}
	b := dial(t, s.Socket) // the signer, at the same time
	if res := b.request("tools/call", map[string]any{"name": "get_protocol_parameters"}); res["isError"] != true {
		t.Fatalf("an unavailable source: %v", res)
	}
	info, err := os.Stat(s.Socket)
	if err != nil || info.Mode().Perm() != 0o660 {
		t.Errorf("socket mode %v, %v", info.Mode().Perm(), err)
	}
	if err := Run(ctx, s, Options{Source: source{}}); err == nil || !strings.Contains(err.Error(), "another server") {
		t.Errorf("a second server: %v", err)
	}
	other := s
	other.Socket = filepath.Join(dir, "other.sock")
	if err := Run(ctx, other, Options{Source: source{}}); err == nil || !strings.Contains(err.Error(), "another server uses") {
		t.Errorf("a second server on another socket: %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not stop")
	}
	if _, err := os.Stat(s.Socket); !os.IsNotExist(err) {
		t.Error("the socket was left behind")
	}
	entries, _, err := audit.Read(t.Context(), filepath.Join(c.DataDir, "audit.log"), audit.Options{Kind: "audit"})
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, e := range entries {
		types = append(types, e.Type)
	}
	if got := strings.Join(types, " "); got != "log.header server_start tool_call tool_call server_stop" {
		t.Errorf("audit log: %s", got)
	}
}

func TestDataDirMustBePrivate(t *testing.T) {
	dir := shortDir(t)
	open := filepath.Join(dir, "open")
	os.Mkdir(open, 0o755)
	c := exampleConfig(t)
	c.DataDir = open
	s, _, _ := Resolve(c)
	if err := Run(t.Context(), s, Options{Source: source{}}); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Errorf("a readable data directory: %v", err)
	}
}

func TestStaleSocketIsReplaced(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "mcp.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close() // a crashed server leaves the file
	again, err := listen(path)
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	again.Close()
}
