// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Liet-ada/mcpcardano/internal/actions"
	"github.com/Liet-ada/mcpcardano/internal/audit"
	"github.com/Liet-ada/mcpcardano/internal/cborx"
	"github.com/Liet-ada/mcpcardano/internal/ipc"
	"github.com/Liet-ada/mcpcardano/internal/model"
)

func (a *admin) status(*options, []string) error {
	var r ipc.StatusReport
	if err := a.call(ipc.MsgStatus, &ipc.Empty{}, &r); err != nil {
		return err
	}
	state := "locked; unlock it with mcpcardano unlock"
	if r.Unlocked {
		state = "unlocked"
	}
	a.printf("Wallet on %s: %s\n", a.network, state)
	if len(r.Wallets) == 0 {
		a.printf("No wallets yet: mcpcardano wallet create, or create_wallet from the agent.\n")
	}
	for _, w := range r.Wallets {
		frozen := ""
		if w.Wallet.Frozen {
			frozen = ", FROZEN"
		}
		a.printf("\n%s  %s\n  mode %s, created by %s%s\n  %s\n", w.Wallet.ID, w.Wallet.Label, w.Wallet.Mode, w.Wallet.CreatedBy,
			frozen, model.Address{Raw: w.Wallet.Address}.Bech32())
		if s := w.Session; s != nil {
			a.printf("  session until %s, %s left\n", clock(s.ExpiresAt), ada(s.Remaining))
		}
		if w.OpenDestinations {
			// Open destinations are shown with their brakes (section 3.7).
			var p ipc.WalletPolicy
			if err := a.call(ipc.MsgShowPolicy, &ipc.WalletRef{WalletID: w.Wallet.ID}, &p); err != nil {
				return err
			}
			l := p.Policy.Limits
			a.printf("  open destinations: any address, up to %s per transaction, %d new per hour and %d per day\n",
				ada(l.PerTx), l.NewDestinationsPerHour, l.NewDestinationsPerDay)
		}
	}
	if len(r.Approvals) > 0 {
		a.printf("\nWaiting for you (mcpcardano approve <id>, or reject <id>):\n")
	}
	for _, ap := range r.Approvals {
		a.printf("  %s  wallet %s, spends %s%s, until %s\n", ap.ID, ap.WalletID, ada(ap.Spend.Lovelace), tokens(ap.Spend), clock(ap.ExpiresAt))
	}
	if r.LastLedgerEntry != 0 {
		a.printf("\nLast entry of the spending record: %s\n", time.Unix(r.LastLedgerEntry, 0).Format(time.DateTime))
	}
	return nil
}

// tokens notes the tokens a spend carries besides lovelace.
func tokens(s ipc.Spend) string {
	if len(s.Assets) == 0 {
		return ""
	}
	return fmt.Sprintf(" and %d kinds of tokens", len(s.Assets))
}

func (a *admin) unlock(*options, []string) error {
	password, err := a.secret("Password: ")
	if err != nil {
		return err
	}
	defer clear(password)
	if err := a.call(ipc.MsgUnlock, &ipc.Unlock{Password: password}, &ipc.Empty{}); err != nil {
		return err
	}
	a.printf("The wallet is unlocked.\n")
	return nil
}

// approvalArg checks an approval id from the command line.
func approvalArg(id string) error {
	if model.ApprovalID(id).Validate() != nil {
		return usageError("%q is not an approval id; mcpcardano status lists them", id)
	}
	return nil
}

// walletArg checks the -wallet flag, which some commands require.
func walletArg(id string, required bool) error {
	switch {
	case id == "" && required:
		return usageError("-wallet is required")
	case id != "" && model.WalletID(id).Validate() != nil:
		return usageError("%q is not a wallet id; mcpcardano status lists them", id)
	}
	return nil
}

func (a *admin) approve(_ *options, args []string) error {
	if err := approvalArg(args[0]); err != nil {
		return err
	}
	act := actions.ApproveDraft(args[0])
	if err := a.authorize(act.Name, act.Params, nil); err != nil {
		return err
	}
	a.printf("Approved. The server sends the transaction on its next round, within 20 seconds.\n")
	return nil
}

func (a *admin) reject(_ *options, args []string) error {
	if err := approvalArg(args[0]); err != nil {
		return err
	}
	if err := a.call(ipc.MsgReject, &ipc.ApprovalRef{ApprovalID: args[0]}, &ipc.Empty{}); err != nil {
		return err
	}
	a.printf("Rejected.\n")
	return nil
}

func (a *admin) freeze(o *options, _ []string) error {
	if err := walletArg(o.wallet, false); err != nil {
		return err
	}
	if err := a.call(ipc.MsgFreeze, &ipc.Freeze{WalletID: o.wallet}, &ipc.Empty{}); err != nil {
		return err
	}
	if o.wallet == "" {
		a.printf("Every wallet is frozen.\n")
	} else {
		a.printf("Wallet %s is frozen.\n", o.wallet)
	}
	return nil
}

func (a *admin) unfreeze(o *options, _ []string) error {
	if err := walletArg(o.wallet, true); err != nil {
		return err
	}
	act := actions.Unfreeze(o.wallet)
	if err := a.authorize(act.Name, act.Params, nil); err != nil {
		return err
	}
	a.printf("Wallet %s is unfrozen.\n", o.wallet)
	return nil
}

func (a *admin) sessionOpen(o *options, _ []string) error {
	if err := walletArg(o.wallet, true); err != nil {
		return err
	}
	max, err := model.ParseAmount(o.max)
	if err != nil {
		return usageError("-max must be an amount of lovelace above zero")
	}
	act, err := actions.OpenSession(o.wallet, o.duration, max)
	if err != nil {
		return usageError("%v", err)
	}
	if err := a.authorize(act.Name, act.Params, nil); err != nil {
		return err
	}
	a.printf("Session open on wallet %s.\n", o.wallet)
	return nil
}

func (a *admin) sessionClose(o *options, _ []string) error {
	if err := walletArg(o.wallet, true); err != nil {
		return err
	}
	if err := a.call(ipc.MsgCloseSession, &ipc.WalletRef{WalletID: o.wallet}, &ipc.Empty{}); err != nil {
		return err
	}
	a.printf("Session closed on wallet %s.\n", o.wallet)
	return nil
}

// expired lists the expired_unconfirmed entries of a wallet, or of all.
func (a *admin) expired(wallet string) ([]ipc.Expired, error) {
	var l ipc.ExpiredList
	err := a.call(ipc.MsgListExpired, &ipc.ListExpired{WalletID: wallet}, &l)
	return l.Entries, err
}

func (a *admin) budgetPending(o *options, _ []string) error {
	if err := walletArg(o.wallet, false); err != nil {
		return err
	}
	entries, err := a.expired(o.wallet)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		a.printf("No expired_unconfirmed entries.\n")
		return nil
	}
	a.printf("Transactions the wallet signed whose TTL passed by its clock. They count as spent until you release\n")
	a.printf("them; first check on the chain that none of them entered it (section 9.2).\n")
	for _, e := range entries {
		a.printf("  %x  wallet %s, %s%s, signed %s, valid until slot %d\n",
			e.BodyHash, e.WalletID, ada(e.Spend.Lovelace), tokens(e.Spend), clock(e.Time), e.TTL)
	}
	a.printf("Release them with: mcpcardano budget release -wallet <id> [transaction ...]\n")
	return nil
}

func (a *admin) budgetRelease(o *options, args []string) error {
	if err := walletArg(o.wallet, true); err != nil {
		return err
	}
	var ids [][]byte
	for _, s := range args {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			return usageError("%q is not a transaction of mcpcardano budget pending", s)
		}
		ids = append(ids, b)
	}
	if len(ids) == 0 { // all of the wallet's
		entries, err := a.expired(o.wallet)
		if err != nil {
			return err
		}
		for _, e := range entries {
			ids = append(ids, e.BodyHash)
		}
	}
	if len(ids) == 0 {
		a.printf("No expired_unconfirmed entries.\n")
		return nil
	}
	var r ipc.Released
	act := actions.ReleaseBudget(o.wallet, ids)
	if err := a.authorize(act.Name, act.Params, &r); err != nil {
		return err
	}
	a.printf("Released %s of the budget of wallet %s.\n", ada(r.Lovelace), o.wallet)
	return nil
}

func (a *admin) printWallet(w ipc.Wallet) {
	a.printf("Wallet %s  %s, mode %s\n  %s\n", w.ID, w.Label, w.Mode, model.Address{Raw: w.Address}.Bech32())
}

func (a *admin) walletCreate(o *options, _ []string) error {
	act, err := actions.CreateWallet(o.label)
	if err != nil {
		return usageError("%v", err)
	}
	var w ipc.Wallet
	if err := a.authorize(act.Name, act.Params, &w); err != nil {
		return err
	}
	a.printWallet(w)
	a.printf("Write down its recovery phrase with: mcpcardano wallet backup -wallet %s\n", w.ID)
	a.suggestKey()
	return nil
}

func (a *admin) walletRestore(o *options, _ []string) error {
	if _, err := actions.RestoreWallet(o.label, nil); err != nil {
		return usageError("%v", err)
	}
	phrase, err := a.secret("Recovery phrase, its words separated by spaces: ")
	if err != nil {
		return err
	}
	defer clear(phrase)
	act, err := actions.RestoreWallet(o.label, phrase)
	if err != nil {
		return usageError("%v", err)
	}
	var w ipc.Wallet
	if err := a.authorize(act.Name, act.Params, &w); err != nil {
		return err
	}
	a.printWallet(w)
	a.suggestKey()
	return nil
}

func (a *admin) walletBackup(o *options, _ []string) error {
	if err := walletArg(o.wallet, true); err != nil {
		return err
	}
	var r ipc.RecoveryPhrase
	act := actions.ShowPhrase(o.wallet)
	if err := a.authorize(act.Name, act.Params, &r); err != nil {
		return err
	}
	defer clear(r.Phrase)
	fmt.Fprintln(a.errOut, "Write these words down on paper, in order, and keep them offline: whoever has them has the wallet.")
	// Written as bytes: through fmt a model.Secret prints as [REDACTED].
	a.out.Write(r.Phrase)
	a.printf("\n")
	return nil
}

var auditCodec = func() *cborx.Codec {
	c, err := cborx.New(cborx.RecordLimits())
	if err != nil {
		panic(err) // constant limits
	}
	return c
}()

func (a *admin) auditShow(o *options, _ []string) error {
	if o.limit == 0 || o.limit > ipc.MaxAuditPage {
		return usageError("-limit must be 1 to %d", ipc.MaxAuditPage)
	}
	var p ipc.AuditPage
	if err := a.call(ipc.MsgShowAudit, &ipc.ShowAudit{From: o.from, Limit: uint32(o.limit)}, &p); err != nil {
		return err
	}
	for _, raw := range p.Entries {
		var e audit.Entry
		var body any
		if err := auditCodec.Unmarshal(raw, &e); err != nil {
			return err
		}
		if err := auditCodec.Unmarshal(e.Body, &body); err != nil {
			return err
		}
		text, err := json.Marshal(jsonable(body))
		if err != nil {
			return err
		}
		a.printf("%d  %s  %s  %s\n", e.Seq, time.Unix(e.Time, 0).Format(time.DateTime), e.Type, text)
	}
	if p.Next != 0 {
		a.printf("More with: mcpcardano audit show -from %d\n", p.Next)
	}
	return nil
}

// jsonable turns a decoded CBOR value into one encoding/json can write: map
// keys as text and bytes as hex.
func jsonable(v any) any {
	switch x := v.(type) {
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[fmt.Sprint(jsonable(k))] = jsonable(val)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = jsonable(x[i])
		}
		return out
	case []byte:
		return hex.EncodeToString(x)
	}
	return v
}

func (a *admin) auditVerify(*options, []string) error {
	var r ipc.AuditCheck
	if err := a.call(ipc.MsgVerifyAudit, &ipc.Empty{}, &r); err != nil {
		return err
	}
	a.printf("Both hash chains hold: %d entries in the audit log and %d in the spending record.\n", r.AuditEntries, r.LedgerEntries)
	return nil
}
