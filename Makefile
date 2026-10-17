# SPDX-License-Identifier: Apache-2.0

GO ?= go
FUZZTIME ?= 10s

.PHONY: check fmt vet test boundaries fuzz live oracle corpus

check: fmt vet test boundaries

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

test:
	$(GO) test -race ./...

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

# Tests against the public preprod network; not part of check.
live:
	$(GO) test -tags live -run Live -count=1 -v ./...

# Regenerates internal/txbuild/testdata/apollo_macs.json.gz with Apollo's MACS,
# from a separate module so Apollo never enters ours.
oracle:
	cd test/apollo-oracle && $(GO) run .

# Refetches the real transactions of test/corpus/txs.txt from Koios, with what
# Koios says they contain; the decoding tests compare against it.
corpus:
	$(GO) run test/corpus/record.go
