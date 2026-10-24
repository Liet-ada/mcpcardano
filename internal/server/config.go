// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package server

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"unicode/utf8"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/mcp"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

// Config is the server's config.json (section 7.5 of the specification),
// written by the person. Amounts are lovelace or token units as decimal
// strings, as in the tools; an empty amount is zero, and zero forbids
// (decision 38).
type Config struct {
	Network string `json:"network"`
	DataDir string `json:"data_dir"`
	Socket  string `json:"socket,omitempty"`
	// WalletSocket is the service socket of the wallet process, which keeps
	// and signs for the wallets of modes B and C; empty if there is none.
	WalletSocket string      `json:"wallet_socket,omitempty"`
	DataSource   DataSources `json:"datasource"`
	// ConfirmationDepth is how many blocks make a transaction confirmed;
	// zero means DefaultConfirmationDepth.
	ConfirmationDepth uint32         `json:"confirmation_depth,omitempty"`
	Wallets           []WalletConfig `json:"wallets"`
}

// DataSourceConfig is one data source: Koios or Blockfrost (decision 136).
type DataSourceConfig struct {
	Kind string `json:"kind"`
	// Name tells the source from the others, also to the agent, which may
	// choose the order of the sources for its session (decision 137): its
	// kind if empty.
	Name string `json:"name,omitempty"`
	// URL is empty for the source's public endpoint.
	URL string `json:"url,omitempty"`
	// Secret names the file with Blockfrost's project id, in secrets/ of
	// the data directory or among the unit's systemd credentials:
	// "blockfrost" if empty. The key itself never goes in config.json.
	Secret string `json:"secret,omitempty"`
}

// DataSources is the datasource field: one source, as an object, or
// several in order of preference, as a list (decision 136).
type DataSources []DataSourceConfig

// UnmarshalJSON reads an object or a list, as strictly as Load.
func (d *DataSources) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if t := bytes.TrimSpace(b); len(t) > 0 && t[0] == '{' {
		var one DataSourceConfig
		if err := dec.Decode(&one); err != nil {
			return err
		}
		*d = DataSources{one}
		return nil
	}
	var list []DataSourceConfig
	if err := dec.Decode(&list); err != nil {
		return err
	}
	*d = list
	return nil
}

// WalletConfig is a mode A wallet: the person's hardware wallet, of which
// the server only knows the address (section 7.5).
type WalletConfig struct {
	ID      string       `json:"id"`
	Label   string       `json:"label"`
	Address string       `json:"address"`
	Policy  PolicyConfig `json:"policy"`
}

// PolicyConfig is the policy of section 3.6.
type PolicyConfig struct {
	Frozen       bool               `json:"frozen,omitempty"`
	Networks     []string           `json:"networks"`
	Limits       LimitsConfig       `json:"limits"`
	Destinations DestinationsConfig `json:"destinations"`
	Assets       map[string]string  `json:"assets,omitempty"`
	UTxO         UTxOConfig         `json:"utxo"`
}

// LimitsConfig holds the limits. Mode A uses per_tx, max_fee,
// max_live_drafts and max_ttl_seconds; the others come with the wallet
// process in H-2.
type LimitsConfig struct {
	PerTx                  string `json:"per_tx"`
	PerHour                string `json:"per_hour,omitempty"`
	PerDay                 string `json:"per_day,omitempty"`
	Budget                 string `json:"budget,omitempty"`
	ApprovalThreshold      string `json:"approval_threshold,omitempty"`
	MaxFee                 string `json:"max_fee"`
	TxPerHour              uint32 `json:"tx_per_hour,omitempty"`
	NewDestinationsPerHour uint32 `json:"new_destinations_per_hour,omitempty"`
	NewDestinationsPerDay  uint32 `json:"new_destinations_per_day,omitempty"`
	MaxLiveDrafts          uint32 `json:"max_live_drafts"`
	MaxTTLSeconds          uint32 `json:"max_ttl_seconds"`
}

// DestinationsConfig is either any address or a list of addresses.
type DestinationsConfig struct {
	Any     bool     `json:"any,omitempty"`
	Allowed []string `json:"allowed,omitempty"`
}

// UTxOConfig steers change and input selection (sections 8.2 and 8.3).
type UTxOConfig struct {
	TargetADAOnly uint32 `json:"target_ada_only"`
	MinSplit      string `json:"min_split"`
	DustThreshold string `json:"dust_threshold"`
	MaxDustSweep  uint32 `json:"max_dust_sweep"`
}

// Settings is a checked configuration, in the project's types.
type Settings struct {
	Network           model.Network
	DataDir           string
	Socket            string
	WalletSocket      string
	Sources           []DataSourceConfig // in order of preference, each named, and each Blockfrost secret too
	ConfirmationDepth uint32
	Wallets           []mcp.Wallet
}

// maxSources bounds the data sources of the list.
const maxSources = 4

// maxConfigBytes bounds config.json.
const maxConfigBytes = 1 << 20

// maxSocketPath keeps the socket path within sun_path on Linux and macOS.
const maxSocketPath = 100

// ErrConfig reports a configuration the server cannot run with.
var ErrConfig = errors.New("server: invalid configuration")

// Load reads config.json strictly: unknown fields and trailing data are
// errors, so a typo never silently leaves a limit at zero.
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return Config{}, err
	}
	if len(data) > maxConfigBytes {
		return Config{}, fmt.Errorf("%w: %s is larger than %d bytes", ErrConfig, path, maxConfigBytes)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%w: %s: %v", ErrConfig, path, err)
	}
	if dec.More() {
		return Config{}, fmt.Errorf("%w: %s: data after the configuration", ErrConfig, path)
	}
	return c, nil
}

// Resolve checks a configuration and turns it into settings. Warnings are
// for values that are valid but probably not meant, such as a limit at zero,
// which forbids.
func Resolve(c Config) (Settings, []string, error) {
	fail := func(format string, args ...any) (Settings, []string, error) {
		return Settings{}, nil, fmt.Errorf("%w: "+format, append([]any{ErrConfig}, args...)...)
	}
	n := model.Network(c.Network)
	switch {
	case n == model.Mainnet:
		return fail("mainnet stays disabled until the condition of section 9.4 of the paper is met")
	case !n.Valid():
		return fail("network %q is not preprod or preview", c.Network)
	case !filepath.IsAbs(c.DataDir):
		return fail("data_dir must be an absolute path")
	case len(c.DataSource) == 0:
		return fail("datasource must name a data source")
	case len(c.DataSource) > maxSources:
		return fail("datasource lists more than %d data sources", maxSources)
	}
	s := Settings{Network: n, DataDir: filepath.Clean(c.DataDir), Socket: c.Socket, WalletSocket: c.WalletSocket,
		ConfirmationDepth: c.ConfirmationDepth}
	for _, d := range c.DataSource {
		d.Name = cmp.Or(d.Name, d.Kind)
		switch {
		case d.Kind != "koios" && d.Kind != "blockfrost":
			return fail("datasource kind %q is not koios or blockfrost", d.Kind)
		case !plainName(d.Name):
			return fail("datasource name %q must be 1 to 64 letters, digits, - and _", d.Name)
		case slices.ContainsFunc(s.Sources, func(o DataSourceConfig) bool { return o.Name == d.Name }):
			return fail("datasource lists %s twice: give each one its own name", d.Name)
		case d.Kind == "koios" && d.Secret != "":
			return fail("koios takes no secret")
		}
		if d.Kind == "blockfrost" {
			d.Secret = cmp.Or(d.Secret, "blockfrost")
			if !plainName(d.Secret) {
				return fail("secret %q must be 1 to 64 letters, digits, - and _", d.Secret)
			}
		}
		s.Sources = append(s.Sources, d)
	}
	if s.ConfirmationDepth == 0 {
		s.ConfirmationDepth = DefaultConfirmationDepth
	}
	if s.Socket == "" {
		s.Socket = filepath.Join(s.DataDir, "mcp.sock")
	}
	if !filepath.IsAbs(s.Socket) || len(s.Socket) > maxSocketPath {
		return fail("socket must be an absolute path of at most %d bytes", maxSocketPath)
	}
	if s.WalletSocket != "" && (!filepath.IsAbs(s.WalletSocket) || len(s.WalletSocket) > maxSocketPath) {
		return fail("wallet_socket must be an absolute path of at most %d bytes", maxSocketPath)
	}
	var warnings []string
	seen := map[model.WalletID]bool{}
	for i, wc := range c.Wallets {
		w, ws, err := resolveWallet(n, wc)
		if err != nil {
			return fail("wallet %d: %v", i, err)
		}
		if seen[w.ID] {
			return fail("wallet %s appears twice", w.ID)
		}
		seen[w.ID] = true
		s.Wallets = append(s.Wallets, w)
		for _, msg := range ws {
			warnings = append(warnings, fmt.Sprintf("wallet %s: %s", w.ID, msg))
		}
	}
	if len(s.Wallets) == 0 && s.WalletSocket == "" {
		warnings = append(warnings, "no wallets and no wallet process: the agent can only read")
	}
	return s, warnings, nil
}

func resolveWallet(n model.Network, c WalletConfig) (mcp.Wallet, []string, error) {
	id := model.WalletID(c.ID)
	if err := id.Validate(); err != nil {
		return mcp.Wallet{}, nil, fmt.Errorf("id %q: %w; mcpcardano-server -new-wallet-id prints one", c.ID, err)
	}
	if c.Label == "" || len(c.Label) > 64 || !utf8.ValidString(c.Label) {
		return mcp.Wallet{}, nil, fmt.Errorf("label must be valid UTF-8 of 1 to 64 bytes")
	}
	addr, err := chain.ParseAddress(n, c.Address)
	if err != nil {
		return mcp.Wallet{}, nil, err
	}
	if addr.Payment.Kind != model.KeyHash {
		return mcp.Wallet{}, nil, fmt.Errorf("address: a hardware wallet address has a key payment credential")
	}
	p, warnings, err := resolvePolicy(n, c.Policy)
	if err != nil {
		return mcp.Wallet{}, nil, fmt.Errorf("policy: %w", err)
	}
	return mcp.Wallet{
		Wallet: model.Wallet{ID: id, Label: c.Label, Network: n, Mode: model.ModeA, Address: addr, CreatedBy: model.ByPerson},
		Policy: p,
	}, warnings, nil
}

func resolvePolicy(n model.Network, c PolicyConfig) (model.Policy, []string, error) {
	p := model.Policy{Frozen: c.Frozen}
	var warnings []string
	for _, x := range c.Networks {
		m := model.Network(x)
		if !m.Valid() {
			return p, nil, fmt.Errorf("network %q", x)
		}
		p.Networks = append(p.Networks, m)
	}
	amounts := []struct {
		name string
		text string
		to   *uint64
	}{
		{"limits.per_tx", c.Limits.PerTx, &p.Limits.PerTx},
		{"limits.per_hour", c.Limits.PerHour, &p.Limits.PerHour},
		{"limits.per_day", c.Limits.PerDay, &p.Limits.PerDay},
		{"limits.budget", c.Limits.Budget, &p.Limits.Budget},
		{"limits.approval_threshold", c.Limits.ApprovalThreshold, &p.Limits.ApprovalThreshold},
		{"limits.max_fee", c.Limits.MaxFee, &p.Limits.MaxFee},
		{"utxo.min_split", c.UTxO.MinSplit, &p.UTxO.MinSplit},
		{"utxo.dust_threshold", c.UTxO.DustThreshold, &p.UTxO.DustThreshold},
	}
	for _, a := range amounts {
		if a.text == "" {
			continue
		}
		v, err := model.ParseAmount(a.text)
		if err != nil {
			return p, nil, fmt.Errorf("%s: %w", a.name, err)
		}
		*a.to = v
	}
	l := c.Limits
	p.Limits.TxPerHour, p.Limits.NewDestinationsPerHour, p.Limits.NewDestinationsPerDay = l.TxPerHour, l.NewDestinationsPerHour, l.NewDestinationsPerDay
	p.Limits.MaxLiveDrafts, p.Limits.MaxTTLSeconds = l.MaxLiveDrafts, l.MaxTTLSeconds
	p.UTxO.TargetADAOnly, p.UTxO.MaxDustSweep = c.UTxO.TargetADAOnly, c.UTxO.MaxDustSweep

	p.Destinations.Any = c.Destinations.Any
	for _, x := range c.Destinations.Allowed {
		a, err := chain.ParseAddress(n, x)
		if err != nil {
			return p, nil, fmt.Errorf("destinations: %w", err)
		}
		p.Destinations.Allowed = append(p.Destinations.Allowed, a)
	}
	for k, v := range c.Assets {
		id, err := model.ParseAssetID(k)
		if err != nil {
			return p, nil, fmt.Errorf("assets: %q: %w", k, err)
		}
		q, err := model.ParseAmount(v)
		if err != nil {
			return p, nil, fmt.Errorf("assets: %s: %w", k, err)
		}
		if p.Assets == nil {
			p.Assets = map[model.AssetID]uint64{}
		}
		p.Assets[id] = q
	}

	zero := func(ok bool, what string) {
		if !ok {
			warnings = append(warnings, what+" is zero, which forbids every payment")
		}
	}
	zero(p.Limits.PerTx > 0, "limits.per_tx")
	zero(p.Limits.MaxFee > 0, "limits.max_fee")
	zero(p.Limits.MaxLiveDrafts > 0, "limits.max_live_drafts")
	zero(p.Limits.MaxTTLSeconds > 0, "limits.max_ttl_seconds")
	if !p.Destinations.Any && len(p.Destinations.Allowed) == 0 {
		warnings = append(warnings, "destinations allow nobody, which forbids every payment")
	}
	enabled := false
	for _, m := range p.Networks {
		enabled = enabled || m == n
	}
	if !enabled {
		warnings = append(warnings, fmt.Sprintf("policy.networks does not include %s, which blocks the wallet", n))
	}
	return p, warnings, nil
}
