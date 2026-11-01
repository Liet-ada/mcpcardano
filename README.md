# mcpcardano

An MCP server that lets an AI agent pay on Cardano without ever holding a key.

The agent prepares transactions. A separate process with no network holds the keys and signs only what your limits allow, or you sign on a hardware wallet. Anything above your limits waits for you. The agent cannot read a key, change a limit or unfreeze a wallet: those paths do not exist for it.

> [!WARNING]
> Under development. It runs on the Cardano test networks only: mainnet is disabled. It has had no professional security audit. Do not put real funds behind it.

## What you can do with it

- Tell your agent to pay someone, and it builds the transaction, checks it and sends it, within your limits.
- Give it a budget, per transaction, hour and day limits, and a list of addresses it may pay.
- Approve larger payments yourself, from a terminal, with a security key if you want.
- Freeze everything with one key, at any moment, without authorizing anything.
- Read every action in a hash-chained audit log.
- Let it read the chain: balances, tokens, transactions and network status.

## How it works

```
AI agent ──MCP──▶ mcpcardano-server ──Unix socket──▶ mcpcardano-wallet ◀── you (mcpcardano)
                  builds drafts,                     keeps the keys, re-checks every
                  reads the chain                    transaction, signs. No network.
```

Each wallet has a mode, which is how much it trusts the agent:

| Mode | Who signs | When to use it |
| --- | --- | --- |
| A | You, on a hardware wallet, every time | Funds that matter |
| B | The wallet process up to a threshold; above it, it asks you | Everyday payments |
| C | The wallet process, within a budget | Full autonomy for small amounts |

## Try it (no root, test network)

This runs everything as your user, in one directory. It skips the isolation of a real install, so use it only to try it out. You need [Go](https://go.dev/dl/) 1.27.1 or newer.

```sh
git clone https://github.com/Liet-ada/mcpcardano && cd mcpcardano
go build -trimpath -o bin/ ./cmd/mcpcardano ./cmd/mcpcardano-server
go build -trimpath -tags purego -o bin/ ./cmd/mcpcardano-wallet

mkdir -p try/run && chmod 700 try/run
mkdir -m 700 try/wallet try/server
```

Socket paths are limited to about 100 characters, so keep this directory's path short. Write the two configurations, from the same directory:

```sh
cat > try/wallet.json <<EOF
{"network": "preprod", "data_dir": "$PWD/try/wallet", "development": true,
 "service_socket": "$PWD/try/run/service.sock", "admin_socket": "$PWD/try/run/admin.sock",
 "service_uid": $(id -u), "admin_uid": $(id -u)}
EOF
cat > try/server.json <<EOF
{"network": "preprod", "data_dir": "$PWD/try/server", "socket": "$PWD/try/run/mcp.sock",
 "wallet_socket": "$PWD/try/run/service.sock", "datasource": {"kind": "koios"}, "wallets": []}
EOF
```

Create the key store, which asks for a new password of at least 8 characters, and start both processes:

```sh
read -rs PASSWORD; printf '%s\n' "$PASSWORD" | bin/mcpcardano-wallet -config try/wallet.json init; unset PASSWORD
bin/mcpcardano-wallet -config try/wallet.json & echo $! > try/wallet.pid
bin/mcpcardano-server -config try/server.json & echo $! > try/server.pid

export MCPCARDANO_ADMIN_SOCKET=$PWD/try/run/admin.sock MCPCARDANO_SOCKET=$PWD/try/run/mcp.sock
bin/mcpcardano unlock
```

Commands that need your password ask for it at the terminal, or read it from standard input. Then create a wallet and fund it from the [preprod faucet](https://docs.cardano.org/cardano-testnets/tools/faucet) with the address it prints:

```sh
bin/mcpcardano wallet create -label agent
bin/mcpcardano view                         # tab 2 shows its balance
```

The server spends your data source's quota while it runs, so stop both when you finish, from the same directory:

```sh
kill $(cat try/server.pid try/wallet.pid)
```

`mcpcardano doctor` checks a real install, so it fails here. `"wallets"` in the server's configuration is only for mode A.

## Connect your agent

The client starts `mcpcardano mcp`, a bridge to the server's socket. In Claude Code:

```sh
claude mcp add mcpcardano -- /path/to/bin/mcpcardano mcp -socket /path/to/try/run/mcp.sock
```

In any other client:

```json
{
  "mcpServers": {
    "mcpcardano": {
      "command": "/path/to/bin/mcpcardano",
      "args": ["mcp", "-socket", "/path/to/try/run/mcp.sock"]
    }
  }
}
```

After a real install, `mcpcardano mcp` needs no `-socket`. Then ask your agent something like *"What is the balance of my agent wallet?"* or *"Pay 5 ADA to addr_test1..."*. A wallet created by you starts with the template: mode C, up to 20 ADA per transaction, 40 per hour, 100 per day, and a budget of 100.

## Tools

What the MCP server offers an agent:

| Group | Tool | What it does |
| --- | --- | --- |
| Wallets | `list_wallets` | The wallets, with their mode and whether they are frozen |
| | `get_wallet_overview` | Balance, tokens, UTxO count and health |
| | `get_policy_status` | Limits, what was spent, budget left, open session |
| | `create_wallet` | A new wallet with your template; it starts empty |
| Payments | `build_payment` | A draft paying 1 to 50 recipients, with the policy's verdict. Moves nothing |
| | `build_consolidation` | A draft joining the wallet's UTxOs |
| | `list_drafts`, `get_draft` | Live drafts, and one in detail |
| | `cancel_draft` | Drops an unsigned draft and frees its UTxOs |
| | `authorize_draft` | Signs and sends a draft, or sends it to you for approval. Irreversible |
| | `submit_signed_transaction` | Takes a hardware wallet's signature; used by the mode A signer |
| Chain | `list_utxos` | The UTxOs of a wallet or any address |
| | `get_address_info` | Any address: balance, tokens, delegation |
| | `get_asset_info` | A native token: identity, supply, metadata |
| | `get_transaction` | A transaction on the chain, decoded |
| | `get_transaction_status` | Whether a transaction is in the mempool, confirmed or gone |
| | `decode_transaction` | Reads transaction CBOR, offline |
| Network | `get_network_status` | Chain tip and data sources |
| | `get_protocol_parameters` | Fees, sizes and deposits of this epoch |
| | `set_datasources` | Orders your data sources for the session |

No tool changes a limit, unfreezes a wallet, approves a payment or reveals a key. Those are yours, through `mcpcardano`.

## Stay in control

`mcpcardano view` opens a terminal interface for all of it: wallets, limits, approvals, keys, the audit log. Or use the commands:

```sh
mcpcardano status                               # wallets, sessions, approvals waiting
mcpcardano freeze                               # stop everything; no authorization
mcpcardano unfreeze -wallet <id>                # takes your password or security key
mcpcardano approve <approval_id>                # or reject
mcpcardano policy show -wallet <id> > p.json    # edit it, then:
mcpcardano policy set -wallet <id> p.json
mcpcardano key add -name yubikey                # a FIDO2 key replaces the password
mcpcardano audit show
```

`mcpcardano` with no arguments lists every command.

## Install for real

`sudo mcpcardano install` runs the wallet and the server as services, each with its own user, and the wallet with no network. It works on Linux with systemd and on macOS. See [deploy/README.md](deploy/README.md).

For mode A you also need [cardano-hw-go](https://github.com/Liet-ada/cardano-hw-go), which speaks to Ledger and Trezor devices. `mcpcardano signer init` prepares the device, and `mcpcardano signer` waits for payments to confirm on it.

## What protects your funds

- The agent reaches the server only. The keys are in another process, encrypted with your password, and it re-checks every transaction from its bytes.
- In a real install that process has no network, so a compromised server cannot pull keys out.
- Limits live in that same process. No MCP tool can change them.
- Text from the chain reaches the agent marked as data, never as instructions.

What it does not do: it cannot stop you from authorizing something you should not. Read what the wallet shows you before you confirm. A hostile server can also lie about a balance, because the wallet has no network to check it against.

## For AI agents

Start at [docs/](docs/README.md): how to use the tools, and how to handle UTxOs.

## Development

```sh
make check   # format, vet, tests with -race, package boundaries
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
