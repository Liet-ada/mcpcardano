# UTxOs in mcpcardano

A Cardano balance is a set of unspent outputs. A transaction spends whole UTxOs and returns the rest as change, so their number and size decide how many payments can run at once, what they cost, and whether they fit.

## Reading a wallet

`get_wallet_overview` gives `utxos` (a count), `reserved` (held by drafts), and `utxo_health`:

| Field | Meaning |
| --- | --- |
| `total`, `ada_only`, `with_tokens` | How many UTxOs of each kind |
| `dust` | ADA-only UTxOs below `dust_threshold` |
| `target` | The ADA-only UTxOs the policy wants |
| `suggestion` | `consolidate` or `none` |

It suggests `consolidate` when `dust` exceeds `max_dust_sweep`, or when `ada_only` is more than twice `target`. Use `list_utxos` only if you need the UTxOs themselves.

## The policy's knobs

The person sets these with the wallet's policy. An agent sees only `target`, in `utxo_health`; the rest of the table is what the template gives a new wallet unless the person changed it.

| Field | Template | Effect |
| --- | --- | --- |
| `target_ada_only` | 3 | How many ADA-only UTxOs change aims for |
| `min_split` | 5 ADA | The smallest piece change is split into |
| `dust_threshold` | 1 ADA | ADA-only UTxOs below this are dust |
| `max_dust_sweep` | 2 | Dust a payment may pick up as extra inputs |

## How a draft picks inputs

Selection is deterministic: the same state gives the same inputs.

- Free UTxOs are those not held by a draft and not already spent in the mempool.
- One UTxO that covers the payment is preferred, avoiding one that would leave under 1.5 ADA of change. Otherwise it favors UTxOs near the wallet's average, which reduces fragmentation by itself.
- It then sweeps up to `max_dust_sweep` dust UTxOs.
- UTxOs with tokens outside the policy's list are used only if the payment cannot be covered without them.

Change goes back to the wallet. Tokens are grouped by policy, up to 10 in an output. ADA is split into equal parts only when the wallet would otherwise end below `target` and there is enough for at least two pieces of `min_split`. Otherwise it goes in one output. So after the first payments a wallet tends to hold `target` UTxOs, and each payment spends one and returns one.

## Using them well

**Parallel payments need separate UTxOs.** A draft holds its inputs from `build_*` until it ends. With 3 UTxOs, a fourth simultaneous payment may fail with `INSUFFICIENT_FREE_UTXOS`. Drafts never share an input, so you need no coordination. Wait for one to finish, or `cancel_draft` one you do not need. If the person wants more payments at once, suggest a higher `target_ada_only`.

**Drafts left around block funds.** `reserved` in the overview shows what they hold. A built draft keeps its UTxOs until it expires, 30 minutes by default.

**Check the change first.** `summary.inputs` lists what a draft spends, and `outputs` with `own: true` what returns. A fee is mostly size: more inputs and outputs cost more.

**Change can be spent early.** It is usable once the data source sees it in a block, before the parent is `confirmed`. If that block is rolled back, the child falls too. For a payment that must not depend on another, wait for `confirmed`.

**A payment can consolidate on its own.** Paying from a fragmented wallet uses several UTxOs near the average, and a dust sweep tidies as it goes. Often no consolidation is needed.

## Consolidating

`build_consolidation` spends every free UTxO back to the wallet, with change split as above. It is a draft like any other: it needs `authorize_draft` and it costs a fee.

- **Do it when `suggestion` is `consolidate`,** when the person asks, or after `TX_TOO_LARGE`.
- **Do not do it at or below `target`.** The change is split back to `target`: a wallet with 3 UTxOs and a target of 3 ends with 3, and paid the fee for nothing.
- **It may not reach `target`.** Parts stay at `min_split` or more, so a small balance ends in fewer UTxOs.
- **Too many for one transaction?** It takes the smallest that fit, dust first. Repeat after it confirms.
- **Over 10,000 UTxOs** the server stops reading the address and answers `TOO_MANY_UTXOS`. Do not retry; ask the person.

A consolidation holds every free UTxO while it runs, so avoid it while payments are under way.
