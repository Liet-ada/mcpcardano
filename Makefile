# SPDX-License-Identifier: Apache-2.0

GO ?= go

.PHONY: check fmt vet test boundaries

check: fmt vet test boundaries

fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

test:
	$(GO) test -race ./...

boundaries:
	$(GO) test -count=1 ./internal/archtest/...
