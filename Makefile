# SPDX-License-Identifier: Apache-2.0

GO ?= go
FUZZTIME ?= 10s

.PHONY: check fmt vet test boundaries fuzz vuln live oracle corpus cli-vectors cli-txviews trezor-vectors e8-agents e8-record

check: fmt vet test boundaries

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

# The wallet is built with purego (section 1.1), so its packages are also
# tested that way: without assembly in edwards25519 or golang.org/x/crypto.
WALLET_PKGS = ./internal/hdkey/... ./internal/keystore/... ./internal/authz/... ./internal/txcheck/... ./internal/ledger/... ./internal/walletd/...

test:
	$(GO) test -race ./...
	$(GO) test -race -tags purego $(WALLET_PKGS)

boundaries:
	$(GO) test -count=1 ./internal/archtest/...

# Short fuzzing run of every fuzz target (section 11.2); go test fuzzes one
# target at a time.
fuzz:
	@for pkg in $$($(GO) list ./...); do \
		for f in $$($(GO) test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
			echo "$$pkg $$f"; \
			$(GO) test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
		done; \
	done

# Known vulnerabilities that our code reaches (section 11.2). The version is
# fixed so every run checks the same way.
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

# Tests against the public preprod network; not part of check.
live:
	$(GO) test -tags live -run Live -count=1 -v ./...

# Regenerates internal/txbuild/testdata/apollo_macs.json.gz with Apollo's MACS,
# from a separate module so Apollo never enters ours.
oracle:
	cd test/apollo-oracle && $(GO) run .

# Regenerates internal/hdkey/testdata/cardano_cli.json, hdkey's cross vectors
# with cardano-cli (step 3 of H-3). It needs cardano-cli 11 or later.
CARDANO_CLI ?= cardano-cli
cli-vectors:
	$(GO) run test/cardano-cli/record.go -cli $(CARDANO_CLI)

# Regenerates test/corpus/testdata/cli/cardano_cli.json, txcheck's cross check
# with cardano-cli (decision 131): the test writes the transactions, and
# cardano-cli reads each one with the ledger's decoders.
cli-txviews:
	b=$$(mktemp) && $(GO) test ./test/corpus -run TestCardanoCLI -count=1 -args -cli-bodies=$$b && \
		$(GO) run test/cardano-cli/txviews.go -cli $(CARDANO_CLI) -in $$b; s=$$?; rm -f $$b; exit $$s

# Regenerates internal/hdkey/testdata/trezor.json from the Trezor emulator, the
# hardware side of the cross vectors. It needs a checkout of trezor-firmware
# with the emulator built, and cardano-hw-go built with -tags emulators.
trezor-vectors:
	$(GO) run test/trezor/record.go -firmware $(TREZOR_FIRMWARE) -hwgo $(CARDANO_HW_GO)

# Refetches the real transactions of test/corpus/txs.txt from Koios, with what
# Koios says they contain; the decoding tests compare against it.
corpus:
	$(GO) run test/corpus/record.go

# Experiment E8 with real agents (paper, section 9.2): Claude Code, with only
# the tools of mcpcardano, on the hostile chain of test/e8. It spends real
# money, up to E8_BUDGET US dollars; not part of check.
E8_MODEL ?= claude-haiku-4-5-20251001
E8_REPEAT ?= 10
E8_BUDGET ?= 4
E8_OUT ?= e8-results
e8-agents:
	$(GO) run ./test/e8/agents -model $(E8_MODEL) -repeat $(E8_REPEAT) -budget $(E8_BUDGET) -out $(E8_OUT)

# Refetches the real phishing tokens of test/e8/real.txt from Koios.
e8-record:
	$(GO) run test/e8/record.go
