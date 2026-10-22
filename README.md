# mcpcardano

A non-custodial MCP server that lets AI agents operate on Cardano within limits set by a person.

The agent only prepares draft transactions. A separate, network-isolated wallet process re-checks every transaction against per-wallet policies and budgets before signing, and in mode A the person signs on their own hardware wallet.

**Status:** under construction, milestone H-1 (read tools, payment and consolidation drafts, hardware-wallet signing on preprod). Not ready for real funds; mainnet is disabled.

## Build

```
make check   # format, vet, tests with -race, package boundary checks
```

Requires Go 1.26.8 or newer.

## Run (milestone H-1, preprod)

The server runs on its own and serves MCP on a Unix socket. An MCP client reaches it through `mcpcardano mcp`, a bridge it starts like any stdio server.

```
go build -o bin/ ./cmd/...
bin/mcpcardano-server -new-wallet-id          # an id for each wallet in config.json
bin/mcpcardano-server -config config.json -check
bin/mcpcardano-server -config config.json
```

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

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
