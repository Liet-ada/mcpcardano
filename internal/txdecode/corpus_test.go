// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package txdecode

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// corpusEntry is a file of test/corpus: a real transaction and what Koios,
// that is cardano-db-sync, says it contains.
type corpusEntry struct {
	Network string `json:"network"`
	Note    string `json:"note"`
	CBOR    string `json:"cbor"`
	Koios   struct {
		TxHash           string  `json:"tx_hash"`
		Fee              string  `json:"fee"`
		InvalidBefore    *string `json:"invalid_before"`
		InvalidAfter     *string `json:"invalid_after"`
		Inputs           int     `json:"inputs"`
		CollateralInputs int     `json:"collateral_inputs"`
		CollateralOutput bool    `json:"collateral_output"`
		ReferenceInputs  int     `json:"reference_inputs"`
		Outputs          []struct {
			Address         string       `json:"address"`
			Value           string       `json:"value"`
			Assets          []koiosAsset `json:"assets"`
			Datum           bool         `json:"datum"`
			ReferenceScript bool         `json:"reference_script"`
		} `json:"outputs"`
		Withdrawals []struct {
			StakeAddr string `json:"stake_addr"`
			Amount    string `json:"amount"`
		} `json:"withdrawals"`
		AssetsMinted []koiosAsset `json:"assets_minted"`
		Certificates []struct {
			Index int    `json:"index"`
			Type  string `json:"type"`
		} `json:"certificates"`
		MetadataLabels   []string                   `json:"metadata_labels"`
		Message          []string                   `json:"message"`
		Metadata         map[string]json.RawMessage `json:"metadata"`
		Votes            int                        `json:"votes"`
		Proposals        int                        `json:"proposals"`
		TreasuryDonation string                     `json:"treasury_donation"`
	} `json:"koios"`
}

type koiosAsset struct {
	PolicyID    string `json:"policy_id"`
	AssetName   string `json:"asset_name"`
	Fingerprint string `json:"fingerprint"`
	Quantity    string `json:"quantity"`
}

func loadCorpus(t testing.TB) map[string]corpusEntry {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "test", "corpus", "*", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus: %v", err)
	}
	out := map[string]corpusEntry{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var e corpusEntry
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out[e.Network+"/"+e.Note] = e
	}
	return out
}

// koiosCertificates says which rows of Koios's certificate list each Conway
// certificate becomes: db-sync splits the combined ones.
var koiosCertificates = map[string][]string{
	"stake_registration":        {"stake_registration"},
	"stake_deregistration":      {"stake_deregistration"},
	"stake_delegation":          {"pool_delegation"},
	"pool_registration":         {"pool_update"},
	"pool_retirement":           {"pool_retire"},
	"reg_cert":                  {"stake_registration"},
	"unreg_cert":                {"stake_deregistration"},
	"vote_deleg_cert":           {"vote_delegation"},
	"stake_vote_deleg_cert":     {"pool_delegation", "vote_delegation"},
	"stake_reg_deleg_cert":      {"pool_delegation", "stake_registration"},
	"vote_reg_deleg_cert":       {"stake_registration", "vote_delegation"},
	"stake_vote_reg_deleg_cert": {"pool_delegation", "stake_registration", "vote_delegation"},
	"reg_drep_cert":             {"drep_registration"},
	"unreg_drep_cert":           {"drep_retire"},
	"update_drep_cert":          {"drep_update"},
}

func koiosAssets(list []koiosAsset) []Asset {
	var out []Asset
	for _, a := range list {
		out = append(out, Asset{Asset: a.PolicyID + "." + a.AssetName, Fingerprint: a.Fingerprint, Quantity: a.Quantity})
	}
	slices.SortFunc(out, func(x, y Asset) int { return strings.Compare(x.Asset, y.Asset) })
	return out
}

// withoutNames drops the neutralized names, which Koios does not give.
func withoutNames(list []Asset) []Asset {
	out := slices.Clone(list)
	for i := range out {
		out[i].NameUnverified = ""
	}
	slices.SortFunc(out, func(x, y Asset) int { return strings.Compare(x.Asset, y.Asset) })
	return out
}

func orEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// TestCorpusSummaries compares our summary of every real transaction in the
// corpus with Koios's reading of the same transaction.
func TestCorpusSummaries(t *testing.T) {
	for name, e := range loadCorpus(t) {
		t.Run(name, func(t *testing.T) {
			raw, err := hex.DecodeString(e.CBOR)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := Decode(raw, 1<<16)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			s, err := tx.Summary(Options{})
			if err != nil {
				t.Fatalf("summary: %v", err)
			}
			k := e.Koios
			check := func(what string, got, want any) {
				t.Helper()
				g, _ := json.Marshal(got)
				w, _ := json.Marshal(want)
				if string(g) != string(w) {
					t.Errorf("%s: got %s, Koios says %s", what, g, w)
				}
			}
			check("tx id", s.TxID, k.TxHash)
			check("fee", s.Fee, k.Fee)
			check("ttl", s.TTLSlot, orEmpty(k.InvalidAfter))
			check("validity start", s.ValidityStartSlot, orEmpty(k.InvalidBefore))
			check("inputs", max(len(s.Inputs), s.InputsCount), k.Inputs)
			check("collateral inputs", s.CollateralInputs, k.CollateralInputs)
			check("collateral return", s.CollateralReturn, k.CollateralOutput)
			check("reference inputs", s.ReferenceInputs, k.ReferenceInputs)
			check("votes", s.Votes, k.Votes)
			check("proposals", s.Proposals, k.Proposals)
			donation := s.Donation
			if donation == "" {
				donation = "0"
			}
			check("donation", donation, k.TreasuryDonation)

			// Koios lists every token; the summary shows MaxTokens in all and
			// the length of each list it cuts.
			left := MaxTokens
			expect := func(all []Asset) ([]Asset, int) {
				n := min(len(all), left)
				left -= n
				shown := all[:n]
				if n == 0 {
					shown = nil
				}
				if n < len(all) {
					return shown, len(all)
				}
				return shown, 0
			}
			check("outputs", len(s.Outputs), len(k.Outputs))
			for i := range min(len(s.Outputs), len(k.Outputs)) {
				o, ko := s.Outputs[i], k.Outputs[i]
				check("output address", o.Address, ko.Address)
				check("output lovelace", o.Lovelace, ko.Value)
				check("output datum", o.Datum, ko.Datum)
				check("output reference script", o.ReferenceScript, ko.ReferenceScript)
				want, count := expect(koiosAssets(ko.Assets))
				check("output assets", withoutNames(o.Assets), want)
				check("output assets count", o.AssetsCount, count)
				if o.Own != nil {
					t.Error("own is set without a wallet")
				}
			}

			var withdrawals, kw []string
			for _, w := range s.Withdrawals {
				withdrawals = append(withdrawals, w.Account+" "+w.Lovelace)
			}
			for _, w := range k.Withdrawals {
				kw = append(kw, w.StakeAddr+" "+w.Amount)
			}
			slices.Sort(withdrawals)
			slices.Sort(kw)
			check("withdrawals", withdrawals, kw)
			want, count := expect(koiosAssets(k.AssetsMinted))
			check("mint", withoutNames(s.Mint), want)
			check("mint count", s.MintCount, count)

			var kinds [][]string
			for _, c := range k.Certificates {
				for len(kinds) <= c.Index {
					kinds = append(kinds, nil)
				}
				kinds[c.Index] = append(kinds[c.Index], c.Type)
			}
			check("certificates", len(s.Certificates), len(kinds))
			for i := range min(len(s.Certificates), len(kinds)) {
				want, ok := koiosCertificates[s.Certificates[i]]
				if !ok {
					t.Errorf("certificate %q has no Koios mapping", s.Certificates[i])
					continue
				}
				slices.Sort(kinds[i])
				check("certificate "+s.Certificates[i], want, kinds[i])
			}

			check("metadata labels", s.MetadataLabels, k.MetadataLabels)
			if len(k.Metadata) > 0 {
				check("metadata", tx.Metadata(), koiosMetadata(t, k.Metadata))
			} else if tx.Metadata() != nil {
				t.Error("metadata that Koios does not see")
			}
			check("message", s.MessageUnverified, message(k.Message))
		})
	}
}

// TestCorpusCovers keeps the corpus honest: every feature the summary shows
// appears in at least one real transaction.
func TestCorpusCovers(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range loadCorpus(t) {
		raw, _ := hex.DecodeString(e.CBOR)
		tx, err := Decode(raw, 1<<16)
		if err != nil {
			t.Fatal(err)
		}
		s, err := tx.Summary(Options{})
		if err != nil {
			t.Fatal(err)
		}
		mark := func(feature string, present bool) {
			if present {
				seen[feature] = true
			}
		}
		for _, o := range s.Outputs {
			mark("tokens", len(o.Assets) > 0)
			mark("datum", o.Datum)
			mark("reference script", o.ReferenceScript)
			mark("Byron address", !strings.HasPrefix(o.Address, "addr"))
		}
		mark("no ttl", s.TTLSlot == "")
		mark("validity start", s.ValidityStartSlot != "")
		mark("certificates", len(s.Certificates) > 0)
		mark("withdrawals", len(s.Withdrawals) > 0)
		for _, a := range s.Mint {
			mark("mint", !strings.HasPrefix(a.Quantity, "-"))
			mark("burn", strings.HasPrefix(a.Quantity, "-"))
		}
		mark("message", len(s.MessageUnverified) > 0)
		mark("other metadata", slices.ContainsFunc(s.MetadataLabels, func(l string) bool { return l != "674" }))
		mark("collateral", s.CollateralInputs > 0)
		mark("collateral return", s.CollateralReturn)
		mark("reference inputs", s.ReferenceInputs > 0)
		mark("required signers", len(s.RequiredSigners) > 0)
		mark("script data", s.ScriptData)
		mark("votes", s.Votes > 0)
		mark("proposals", s.Proposals > 0)
		mark("donation", s.Donation != "")
	}
	for _, f := range []string{"tokens", "datum", "reference script", "Byron address", "no ttl", "validity start",
		"certificates", "withdrawals", "mint", "burn", "message", "other metadata", "collateral",
		"collateral return", "reference inputs", "script data", "votes", "proposals", "donation"} {
		if !seen[f] {
			t.Errorf("no transaction in the corpus has %s", f)
		}
	}
}

// koiosMetadata reads db-sync's rendering of metadata with integers as
// decimal strings, the one difference from ours.
func koiosMetadata(t *testing.T, m map[string]json.RawMessage) map[string]any {
	out := map[string]any{}
	for label, raw := range m {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		out[label] = numbersAsText(v)
	}
	return out
}

func numbersAsText(v any) any {
	switch v := v.(type) {
	case json.Number:
		return v.String()
	case map[string]any:
		for k, x := range v {
			v[k] = numbersAsText(x)
		}
	case []any:
		for i, x := range v {
			v[i] = numbersAsText(x)
		}
	}
	return v
}
