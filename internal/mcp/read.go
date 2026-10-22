// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package mcp

import (
	"context"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/chain"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
	"github.com/Liet-ada/mcpcardano/internal/txdecode"
)

// MaxDecodeBytes bounds decode_transaction: the largest transaction the
// ledger accepts. The size bounds the decoding time (decision 39).
const MaxDecodeBytes = 16384

// Pages of list_utxos (section 4.1).
const (
	defaultPage = 50
	maxPage     = 100
)

type noArgs struct{}

type walletArg struct {
	WalletID string `json:"wallet_id" jsonschema:"The wallet, as list_wallets gives it."`
}

func (s *Server) registerRead() error {
	for _, err := range []error{
		addTool(s, tool{name: "get_network_status", readOnly: true, openWorld: true,
			description: "Network, chain tip (slot, height, time), the data source and whether it answers, the server's own slot, and the protocol version."},
			s.networkStatus),
		addTool(s, tool{name: "get_protocol_parameters", readOnly: true, openWorld: true,
			description: "Protocol parameters of the current epoch: fee coefficients, sizes, cost per UTxO byte, deposits, execution prices and limits. Amounts are lovelace as decimal strings; prices are exact fractions."},
			s.protocolParameters),
		addTool(s, tool{name: "list_wallets", readOnly: true,
			description: "The wallets this server manages, with wallet_id, label, signing mode, network, address, who created them and whether they are frozen. In mode A the person signs every payment on a hardware wallet; in mode B the wallet process signs below an approval threshold and asks the person above it; in mode C it signs within a budget. The agent never sees the keys of any mode."},
			s.listWallets),
		addTool(s, tool{name: "get_wallet_overview", readOnly: true, openWorld: true,
			description: "Balance of a wallet (lovelace and tokens), its UTxOs, what drafts hold, live drafts, and the health of its UTxOs with a suggestion. Amounts are lovelace or token units as decimal strings."},
			s.walletOverview),
		addTool(s, tool{name: "get_policy_status", readOnly: true,
			description: "The policy of a wallet: mode, limits, allowed destinations and tokens, live drafts and whether it is frozen; in modes B and C also what it spent in the last hour and day, the budget left and the open session, as the wallet process counts them. The agent cannot change it. Amounts are lovelace as decimal strings."},
			s.policyStatus),
		addTool(s, tool{name: "list_utxos", readOnly: true, openWorld: true,
			description: "Unspent outputs of a wallet (wallet_id) or of any payment address (address), by pages of at most 100 with a cursor. Amounts are lovelace or token units as decimal strings."},
			s.listUTxOs),
		addTool(s, tool{name: "decode_transaction", readOnly: true,
			description: "Summary of a whole Conway transaction in CBOR hex, without asking the network: outputs, fee, validity, certificates, withdrawals, mint and metadata. It does not sign or send anything."},
			s.decodeTransaction),
	} {
		if err != nil {
			return err
		}
	}
	return nil
}

type tipView struct {
	Slot   string `json:"slot"`
	Height string `json:"height"`
	Epoch  string `json:"epoch"`
	Hash   string `json:"hash"`
	Time   string `json:"time"`
}

type sourceView struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok or unavailable
}

type networkStatus struct {
	Network         string     `json:"network"`
	ServerSlot      string     `json:"server_slot"`
	DataSource      sourceView `json:"datasource"`
	Tip             *tipView   `json:"tip,omitempty"`
	ProtocolVersion string     `json:"protocol_version,omitempty"`
}

// networkStatus reports the data source as unavailable instead of failing,
// since that is part of the answer.
func (s *Server) networkStatus(ctx context.Context, _ noArgs) (networkStatus, error) {
	out := networkStatus{
		Network:    string(s.d.Network),
		ServerSlot: model.FormatAmount(chain.Clock(s.d.Network).Slot(s.d.Now())),
		DataSource: sourceView{Name: s.d.Source.Name(), Status: "unavailable"},
	}
	tip, err := s.d.Source.Tip(ctx)
	if err != nil {
		return out, nil
	}
	out.DataSource.Status = "ok"
	out.Tip = &tipView{
		Slot: model.FormatAmount(tip.Slot), Height: model.FormatAmount(tip.Height), Epoch: model.FormatAmount(tip.Epoch),
		Hash: hex.EncodeToString(tip.Hash[:]), Time: tip.Time.UTC().Format(time.RFC3339),
	}
	if p, err := s.d.Source.ProtocolParameters(ctx); err == nil {
		out.ProtocolVersion = version(p)
	}
	return out, nil
}

func version(p chain.ProtocolParameters) string {
	return strconv.FormatUint(uint64(p.ProtocolMajor), 10) + "." + strconv.FormatUint(uint64(p.ProtocolMinor), 10)
}

func fraction(r chain.Rational) string {
	return strconv.FormatUint(r.Num, 10) + "/" + strconv.FormatUint(r.Den, 10)
}

type parametersView struct {
	Network             string `json:"network"`
	Epoch               string `json:"epoch"`
	ProtocolVersion     string `json:"protocol_version"`
	MinFeeA             string `json:"min_fee_a"`
	MinFeeB             string `json:"min_fee_b"`
	MaxTxSize           uint32 `json:"max_tx_size"`
	MaxValueSize        uint32 `json:"max_value_size"`
	CoinsPerUTxOByte    string `json:"coins_per_utxo_byte"`
	KeyDeposit          string `json:"key_deposit"`
	PoolDeposit         string `json:"pool_deposit"`
	DRepDeposit         string `json:"drep_deposit"`
	GovActionDeposit    string `json:"gov_action_deposit"`
	PriceMem            string `json:"price_mem"`
	PriceStep           string `json:"price_step"`
	MaxTxExMem          string `json:"max_tx_ex_mem"`
	MaxTxExSteps        string `json:"max_tx_ex_steps"`
	CollateralPercent   uint32 `json:"collateral_percent"`
	MaxCollateralInputs uint32 `json:"max_collateral_inputs"`
	MinFeeRefScriptByte string `json:"min_fee_ref_script_cost_per_byte"`
}

func (s *Server) protocolParameters(ctx context.Context, _ noArgs) (parametersView, error) {
	p, err := s.d.Source.ProtocolParameters(ctx)
	if err != nil {
		return parametersView{}, err
	}
	f := model.FormatAmount
	return parametersView{
		Network: string(s.d.Network), Epoch: f(p.Epoch), ProtocolVersion: version(p),
		MinFeeA: f(p.MinFeeA), MinFeeB: f(p.MinFeeB), MaxTxSize: p.MaxTxSize, MaxValueSize: p.MaxValueSize,
		CoinsPerUTxOByte: f(p.CoinsPerUTxOByte),
		KeyDeposit:       f(p.KeyDeposit), PoolDeposit: f(p.PoolDeposit), DRepDeposit: f(p.DRepDeposit), GovActionDeposit: f(p.GovActionDeposit),
		PriceMem: fraction(p.PriceMem), PriceStep: fraction(p.PriceStep),
		MaxTxExMem: f(p.MaxTxExMem), MaxTxExSteps: f(p.MaxTxExSteps),
		CollateralPercent: p.CollateralPercent, MaxCollateralInputs: p.MaxCollateralInputs,
		MinFeeRefScriptByte: fraction(p.MinFeeRefScriptByte),
	}, nil
}

type walletView struct {
	WalletID  string `json:"wallet_id"`
	Label     string `json:"label"`
	Mode      string `json:"mode"`
	Network   string `json:"network"`
	Address   string `json:"address"`
	CreatedBy string `json:"created_by"`
	Frozen    bool   `json:"frozen"`
}

type walletList struct {
	Network string       `json:"network"`
	Wallets []walletView `json:"wallets"`
}

func (s *Server) listWallets(ctx context.Context, _ noArgs) (walletList, error) {
	if err := s.refresh(ctx); err != nil {
		// What the server knows is still the answer; the wallet process may
		// be back later.
		s.d.Logger.Warn("wallet process", "err", err)
	}
	out := walletList{Network: string(s.d.Network), Wallets: []walletView{}}
	for _, w := range s.all() {
		addr, err := chain.FormatAddress(w.Address)
		if err != nil {
			return walletList{}, err
		}
		out.Wallets = append(out.Wallets, walletView{
			WalletID: string(w.ID), Label: w.Label, Mode: string(w.Mode), Network: string(w.Network),
			Address: addr, CreatedBy: string(w.CreatedBy), Frozen: w.Policy.Frozen,
		})
	}
	return out, nil
}

type balanceView struct {
	Lovelace    string           `json:"lovelace"`
	Assets      []txdecode.Asset `json:"assets,omitempty"`
	AssetsCount int              `json:"assets_count,omitempty"`
}

type reservedView struct {
	UTxOs    int    `json:"utxos"`
	Lovelace string `json:"lovelace"`
}

type healthView struct {
	Total      int    `json:"total"`
	Dust       int    `json:"dust"`
	WithTokens int    `json:"with_tokens"`
	ADAOnly    int    `json:"ada_only"`
	Target     uint32 `json:"target"`
	Suggestion string `json:"suggestion"` // none or consolidate
}

type overview struct {
	Network    string       `json:"network"`
	WalletID   string       `json:"wallet_id"`
	Address    string       `json:"address"`
	Balance    balanceView  `json:"balance"`
	UTxOs      int          `json:"utxos"`
	Reserved   reservedView `json:"reserved"`
	LiveDrafts int          `json:"live_drafts"`
	UTxOHealth healthView   `json:"utxo_health"`
}

func (s *Server) walletOverview(ctx context.Context, a walletArg) (overview, error) {
	w, err := s.wallet(ctx, a.WalletID)
	if err != nil {
		return overview{}, err
	}
	utxos, err := s.d.Source.UTxOs(ctx, w.Address)
	if err != nil {
		return overview{}, err
	}
	addr, err := chain.FormatAddress(w.Address)
	if err != nil {
		return overview{}, err
	}
	held := map[chain.TxIn]bool{}
	for _, in := range s.d.Drafts.Reserved(w.ID) {
		held[in] = true
	}
	var total, reserved model.Value
	h := healthView{Total: len(utxos), Target: w.Policy.UTxO.TargetADAOnly, Suggestion: "none"}
	r := reservedView{}
	for _, u := range utxos {
		if total, err = total.Add(u.Value); err != nil {
			return overview{}, err
		}
		if held[u.In] {
			r.UTxOs++
			if reserved, err = reserved.Add(u.Value); err != nil {
				return overview{}, err
			}
		}
		switch {
		case u.Value.HasAssets():
			h.WithTokens++
		default:
			h.ADAOnly++
			if u.Value.Lovelace < w.Policy.UTxO.DustThreshold {
				h.Dust++
			}
		}
	}
	r.Lovelace = model.FormatAmount(reserved.Lovelace)
	if h.Dust > int(w.Policy.UTxO.MaxDustSweep) || (h.Target > 0 && h.ADAOnly > 2*int(h.Target)) {
		h.Suggestion = "consolidate"
	}
	b := balanceView{Lovelace: model.FormatAmount(total.Lovelace)}
	b.Assets, b.AssetsCount = txdecode.Tokens(txdecode.NewBudget(txdecode.MaxTokens, s.verified), total.Assets)
	return overview{
		Network: string(s.d.Network), WalletID: string(w.ID), Address: addr,
		Balance: b, UTxOs: len(utxos), Reserved: r,
		LiveDrafts: len(s.d.Drafts.List(w.ID, "")), UTxOHealth: h,
	}, nil
}

type limitsView struct {
	PerTx                  string `json:"per_tx"`
	PerHour                string `json:"per_hour"`
	PerDay                 string `json:"per_day"`
	Budget                 string `json:"budget"`
	ApprovalThreshold      string `json:"approval_threshold"`
	MaxFee                 string `json:"max_fee"`
	TxPerHour              uint32 `json:"tx_per_hour"`
	NewDestinationsPerHour uint32 `json:"new_destinations_per_hour"`
	NewDestinationsPerDay  uint32 `json:"new_destinations_per_day"`
	MaxLiveDrafts          uint32 `json:"max_live_drafts"`
	MaxTTLSeconds          uint32 `json:"max_ttl_seconds"`
}

type destinationsView struct {
	Any     bool     `json:"any"`
	Allowed []string `json:"allowed"`
}

type assetCap struct {
	Asset string `json:"asset"`
	Cap   string `json:"cap"`
}

type policyStatus struct {
	Network      string           `json:"network"`
	WalletID     string           `json:"wallet_id"`
	Mode         string           `json:"mode"`
	Frozen       bool             `json:"frozen"`
	Networks     []string         `json:"networks"`
	Limits       limitsView       `json:"limits"`
	Destinations destinationsView `json:"destinations"`
	Assets       []assetCap       `json:"assets"`
	LiveDrafts   int              `json:"live_drafts"`
	// SpendTracked says whether spending windows and budgets are counted. In
	// mode A they are not: the person confirms every payment on the device.
	SpendTracked bool `json:"spend_tracked"`
	// In modes B and C, what the wallet process counts (section 3.9).
	SpentHour       string       `json:"spent_hour,omitempty"`
	SpentDay        string       `json:"spent_day,omitempty"`
	BudgetRemaining string       `json:"budget_remaining,omitempty"`
	Locked          string       `json:"locked,omitempty"`
	Committed       string       `json:"committed,omitempty"`
	Session         *sessionView `json:"session,omitempty"`
}

// sessionView is an open session: until when, and the lovelace it still
// allows.
type sessionView struct {
	ExpiresAt string `json:"expires_at"`
	Remaining string `json:"remaining_lovelace"`
}

func (s *Server) policyStatus(ctx context.Context, a walletArg) (policyStatus, error) {
	w, err := s.wallet(ctx, a.WalletID)
	if err != nil {
		return policyStatus{}, err
	}
	var ps *ipc.PolicyStatus
	if w.Mode != model.ModeA {
		if ps, err = s.status(ctx, w.ID); err != nil {
			return policyStatus{}, err
		}
		w.Mode, w.Policy = model.Mode(ps.Mode), ps.Policy.Model()
	}
	p, f := w.Policy, model.FormatAmount
	out := policyStatus{
		Network: string(s.d.Network), WalletID: string(w.ID), Mode: string(w.Mode), Frozen: p.Frozen,
		Networks: []string{},
		Limits: limitsView{
			PerTx: f(p.Limits.PerTx), PerHour: f(p.Limits.PerHour), PerDay: f(p.Limits.PerDay),
			Budget: f(p.Limits.Budget), ApprovalThreshold: f(p.Limits.ApprovalThreshold), MaxFee: f(p.Limits.MaxFee),
			TxPerHour: p.Limits.TxPerHour, NewDestinationsPerHour: p.Limits.NewDestinationsPerHour,
			NewDestinationsPerDay: p.Limits.NewDestinationsPerDay, MaxLiveDrafts: p.Limits.MaxLiveDrafts,
			MaxTTLSeconds: p.Limits.MaxTTLSeconds,
		},
		Destinations: destinationsView{Any: p.Destinations.Any, Allowed: []string{}},
		Assets:       []assetCap{},
		LiveDrafts:   len(s.d.Drafts.List(w.ID, "")),
		SpendTracked: w.Mode != model.ModeA,
	}
	for _, n := range p.Networks {
		out.Networks = append(out.Networks, string(n))
	}
	for _, d := range p.Destinations.Allowed {
		text, err := chain.FormatAddress(d)
		if err != nil {
			return policyStatus{}, err
		}
		out.Destinations.Allowed = append(out.Destinations.Allowed, text)
	}
	for _, id := range sortedAssets(p.Assets) {
		out.Assets = append(out.Assets, assetCap{Asset: id.String(), Cap: f(p.Assets[id])})
	}
	if ps != nil {
		out.SpentHour, out.SpentDay, out.BudgetRemaining = f(ps.SpentHour), f(ps.SpentDay), f(ps.BudgetRemaining)
		out.Locked, out.Committed = f(ps.Locked), f(ps.Committed)
		if ps.Session != nil {
			out.Session = &sessionView{ExpiresAt: time.Unix(ps.Session.ExpiresAt, 0).UTC().Format(time.RFC3339),
				Remaining: f(ps.Session.Remaining)}
		}
	}
	return out, nil
}

type utxosArg struct {
	WalletID string `json:"wallet_id,omitempty" jsonschema:"A wallet, as list_wallets gives it. Give this or address."`
	Address  string `json:"address,omitempty" jsonschema:"Any payment address in bech32. Give this or wallet_id."`
	Cursor   string `json:"cursor,omitempty" jsonschema:"next_cursor of the previous page."`
	Limit    int    `json:"limit,omitempty" jsonschema:"UTxOs per page, 1 to 100; 50 by default."`
}

type utxoView struct {
	Ref             string           `json:"ref"`
	Lovelace        string           `json:"lovelace"`
	Assets          []txdecode.Asset `json:"assets,omitempty"`
	AssetsCount     int              `json:"assets_count,omitempty"`
	Datum           bool             `json:"datum,omitempty"`
	ReferenceScript bool             `json:"reference_script,omitempty"`
	Reserved        bool             `json:"reserved,omitempty"`
}

type utxoPage struct {
	Network    string     `json:"network"`
	Address    string     `json:"address"`
	UTxOs      []utxoView `json:"utxos"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

func (s *Server) listUTxOs(ctx context.Context, a utxosArg) (utxoPage, error) {
	if (a.WalletID == "") == (a.Address == "") {
		return utxoPage{}, invalid("give wallet_id or address, not both")
	}
	limit := a.Limit
	switch {
	case limit == 0:
		limit = defaultPage
	case limit < 1 || limit > maxPage:
		return utxoPage{}, invalid("limit must be between 1 and %d", maxPage)
	}
	var addr model.Address
	held := map[chain.TxIn]bool{}
	if a.WalletID != "" {
		w, err := s.wallet(ctx, a.WalletID)
		if err != nil {
			return utxoPage{}, err
		}
		addr = w.Address
		for _, in := range s.d.Drafts.Reserved(w.ID) {
			held[in] = true
		}
	} else {
		var err error
		if addr, err = chain.ParseAddress(s.d.Network, a.Address); err != nil {
			return utxoPage{}, err
		}
	}
	var after *chain.TxIn
	if a.Cursor != "" {
		in, err := parseRef(a.Cursor)
		if err != nil {
			return utxoPage{}, err
		}
		after = &in
	}
	utxos, err := s.d.Source.UTxOs(ctx, addr)
	if err != nil {
		return utxoPage{}, err
	}
	text, err := chain.FormatAddress(addr)
	if err != nil {
		return utxoPage{}, err
	}
	page := utxoPage{Network: string(s.d.Network), Address: text, UTxOs: []utxoView{}}
	budget := txdecode.NewBudget(txdecode.MaxTokens, s.verified)
	for _, u := range utxos {
		if after != nil && u.In.Compare(*after) <= 0 {
			continue
		}
		if len(page.UTxOs) == limit {
			page.NextCursor = page.UTxOs[len(page.UTxOs)-1].Ref
			break
		}
		v := utxoView{
			Ref: u.In.String(), Lovelace: model.FormatAmount(u.Value.Lovelace),
			Datum: u.HasDatum, ReferenceScript: u.HasScript, Reserved: held[u.In],
		}
		v.Assets, v.AssetsCount = txdecode.Tokens(budget, u.Value.Assets)
		page.UTxOs = append(page.UTxOs, v)
	}
	return page, nil
}

// parseRef reads a UTxO reference txid#index.
func parseRef(s string) (chain.TxIn, error) {
	id, ix, ok := strings.Cut(s, "#")
	b, err := hex.DecodeString(id)
	n, errN := strconv.ParseUint(ix, 10, 32)
	if !ok || err != nil || len(b) != 32 || errN != nil || strings.ToLower(id) != id {
		return chain.TxIn{}, invalid("cursor %q is not a UTxO reference", s)
	}
	return chain.TxIn{TxID: [32]byte(b), Index: uint32(n)}, nil
}

type decodeArg struct {
	CBORHex string `json:"cbor_hex" jsonschema:"A whole Conway transaction, signed or not, in hex."`
}

type decodedView struct {
	Network string           `json:"network"`
	Summary txdecode.Summary `json:"summary"`
}

func (s *Server) decodeTransaction(_ context.Context, a decodeArg) (decodedView, error) {
	if len(a.CBORHex) > 2*MaxDecodeBytes {
		return decodedView{}, invalid("cbor_hex holds more than %d bytes", MaxDecodeBytes)
	}
	raw, err := hex.DecodeString(a.CBORHex)
	if err != nil {
		return decodedView{}, invalid("cbor_hex is not hex")
	}
	tx, err := txdecode.Decode(raw, MaxDecodeBytes)
	if err != nil {
		return decodedView{}, err
	}
	summary, err := tx.Summary(txdecode.Options{Verified: s.verified})
	if err != nil {
		return decodedView{}, err
	}
	return decodedView{Network: string(s.d.Network), Summary: summary}, nil
}
