# mcpcardano

A non-custodial MCP server that lets AI agents operate on Cardano within limits set by a person.

The agent only prepares draft transactions. A separate, network-isolated wallet process re-checks every transaction against per-wallet policies and budgets before signing, and in mode A the person signs on their own hardware wallet.

**Status:** under construction. Milestone H-1 is done (read tools, payment and consolidation drafts, hardware-wallet signing on preprod); milestone H-2, the wallet of modes B and C, is in progress. Not ready for real funds; mainnet is disabled.

For AI agents: start at [docs/](docs/README.md).

## Build

```
make check   # format, vet, tests with -race, package boundary checks
```

Requires Go 1.26.8 or newer.

## Run (milestone H-1, preprod)

The server runs on its own and serves MCP on a Unix socket. An MCP client reaches it through `mcpcardano mcp`, a bridge it starts like any stdio server.

```
go build -trimpath -o bin/ ./cmd/...
bin/mcpcardano-server -new-wallet-id          # an id for each wallet in config.json
bin/mcpcardano-server -config config.json -check
bin/mcpcardano-server -config config.json
```

`-trimpath` keeps the paths of the build machine, and the user name in them, out of the binaries. `mcpcardano-server` still carries the path of the Go module cache in two strings: they come from assembly files of a dependency (gnark-crypto) that are `#include`d from another directory, and `-trimpath` does not rewrite those. Share only binaries built where that path names no one.

See [internal/server/testdata/config.json](internal/server/testdata/config.json) for the format. The wallets of H-1 are hardware wallets (mode A): the server only knows their address and policy, and every payment is confirmed on the device. Amounts are lovelace as decimal strings; a limit at zero forbids.

To add the server to Claude Code:

```
claude mcp add mcpcardano -- /path/to/bin/mcpcardano mcp -socket /path/to/mcp.sock
```

### Signing in mode A

The person signs every payment of a mode A wallet on a hardware wallet, through [cardano-hw-go](https://github.com/Liet-ada/cardano-hw-go), which takes the same commands as [cardano-hw-cli](https://github.com/vacuumlabs/cardano-hw-cli) and also speaks to the Trezor Safe 7. The agent calls `authorize_draft`; the signer takes the draft to the device, where the person checks destinations, amounts and fee, and confirms.

```
bin/mcpcardano signer init -hw-cli /path/to/cardano-hw-go   # once: exports the public keys, shows the address on the device
bin/mcpcardano signer -socket /path/to/mcp.sock -hw-cli /path/to/cardano-hw-go
bin/mcpcardano sign <draft_id> -socket ... -hw-cli ...        # by hand, when the signer is not running
```

`signer init` prints the wallet's address, to add to `config.json`. The signer keeps only cardano-hw-go's signing files, which hold public keys; the private keys never leave the device.

When it starts, the signer asks the hardware wallet for its version once, so that whatever the device needs, a confirmation or the code of a first pairing, is asked then, at the terminal, and not in the middle of a payment. If the device is not ready, the signer logs it and goes on: each draft tries the device again.

### The wallet (milestone H-2, in progress)

`mcpcardano-wallet` keeps the keys of the wallets of modes B and C and signs only what their policies and budgets allow. It runs as its own user, without network, and serves two Unix sockets: the service socket, for the server, and the admin socket, for the person's CLI. The person runs the wallet with `mcpcardano`, below. On Linux both run as services of systemd, each with its own user: `sudo mcpcardano install` sets them up and `mcpcardano doctor` checks them, as [deploy/README.md](deploy/README.md) explains.

```
printf '%s\n' "$PASSWORD" | bin/mcpcardano-wallet -config wallet.json init   # once: creates the key store
bin/mcpcardano-wallet -config wallet.json -check
bin/mcpcardano-wallet -config wallet.json
```

```json
{
  "network": "preprod",
  "data_dir": "/var/lib/mcpcardano-wallet",
  "service_socket": "/run/mcpcardano-wallet/service.sock",
  "admin_socket": "/run/mcpcardano-wallet/admin.sock",
  "service_uid": 990,
  "admin_uid": 1000
}
```

`service_uid` and `admin_uid` are the users the kernel must certify at the other end of each socket: the server's and the person's. The wallet starts locked, and refuses to start if it can reach the network; `"development": true` skips that check, and its audit log records it. `"argon2_memory_mib"` lowers the memory of Argon2id from 256 to as little as 64 on small machines, before `init`. The wallet refuses FIDO2 credentials that may be synced to a cloud unless `"allow_synced_keys": true`, and `"recovery_wait_hours"` sets how long a recovery without keys keeps the wallets frozen before it removes the keys: 72 by default.

The server talks to the wallet when its `config.json` names the service socket in `"wallet_socket"`. Its wallets then appear in `list_wallets` next to those of mode A, and the agent can create one with `create_wallet`, which gets the person's template. `authorize_draft` asks the wallet to sign: in mode C it signs within the policy and the budget and the server sends the transaction at once; in mode B, above the approval threshold, the draft waits in `pending_approval` until the person approves it. While the wallet is locked, `authorize_draft` answers `WALLET_UNAVAILABLE` and the draft waits for the agent to ask again.

### The person's commands

`mcpcardano` talks to the wallet's admin socket (`-admin`, or `MCPCARDANO_ADMIN_SOCKET`) on its network (`-network`, or `MCPCARDANO_NETWORK`; preprod by default). What lowers the risk needs nothing; what raises what can be spent shows the summary the wallet computed and asks for the password, without echo, or, once a FIDO2 security key is registered, for its touch.

```
mcpcardano unlock                                   # after each start of the wallet
mcpcardano status                                   # wallets, sessions, approvals waiting
mcpcardano approve <approval_id> | reject <approval_id>
mcpcardano freeze [-wallet id] | unfreeze -wallet id
mcpcardano session open -wallet id -for 1h -max 50000000 | session close -wallet id
mcpcardano policy show -wallet id > policy.json     # or -template
mcpcardano policy set -wallet id policy.json        # or -template; mode B or C
mcpcardano budget pending | budget release -wallet id [transaction ...]
mcpcardano wallet create -label name | wallet restore -label name | wallet backup -wallet id
mcpcardano audit show [-from seq] | audit verify
mcpcardano key add -name name | key remove -name name | key list
mcpcardano recover start | recover status | recover cancel
mcpcardano view                                     # the interactive view, in a terminal
```

`mcpcardano view` follows the wallet as it changes: the wallets, their sessions and the approvals waiting, refreshed every two seconds. Enter reads an approval with the summary the wallet computed, `a` approves it with a registered key's touch, or the password when there is none, and `r` rejects it; `f` freezes every wallet at once, and `q` quits. It talks only to the admin socket, like every other command, and opens no port.

A security key replaces the password for every authorization; changing policies, adding or removing keys and showing a recovery phrase also take its PIN. `key add` needs a key with a PIN set, and the password, or a registered key's touch once there is one: the CLI creates the credential on the new key, then asks for a registered one. Register a second key as a backup. With every key lost, `recover start` takes the password, freezes every wallet and, after 72 hours, removes the keys, so the password authorizes again; until then a registered key's touch cancels it, and every command warns of it. The CLI talks to the key over USB, through IOKit on macOS and hidraw on Linux, where the person's user needs access to the key's `/dev/hidraw*`.

`policy show` writes the policy in the JSON of the server's `config.json`, with the mode, `session_required` and `structure` besides; edit it and give it to `policy set`. Freezing is not in it: `freeze` and `unfreeze` change it. Amounts are lovelace. Exit codes: 0 done, 1 error, 2 wrong usage, 3 authorization refused, expired or declined, 4 the wallet does not answer or is locked.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
