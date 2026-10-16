# mcpcardano

A non-custodial MCP server that lets AI agents operate on Cardano within limits set by a person.

The agent only prepares draft transactions. A separate, network-isolated wallet process re-checks every transaction against per-wallet policies and budgets before signing, and in mode A the person signs on their own hardware wallet.

**Status:** under construction, milestone H-1 (read tools, payment and consolidation drafts, hardware-wallet signing on preprod). Not ready for real funds; mainnet is disabled.

## Build

```
make check   # format, vet, tests with -race, package boundary checks
```

Requires Go 1.26 or newer.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
