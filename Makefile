# ObserveX Managed build and test entry points.
#
# Targets that need tools downloaded through the Go module proxy
# (lint, vuln, secrets, licenses, proto-lint) are run in CI and by Astra.
# They never bypass the module proxy or checksum database.

GO        ?= go
PKGS      := ./...
FUZZTIME  ?= 30s
COVERFILE := coverage.out

.PHONY: all build fmt-check vet test race cover fuzz ci-local ci lint vuln secrets licenses proto-lint clean

all: ci-local

build:
	$(GO) build $(PKGS)

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet $(PKGS)

test:
	$(GO) test -count=1 $(PKGS)

race:
	$(GO) test -count=1 -race $(PKGS)

cover:
	$(GO) test -count=1 -covermode=atomic -coverpkg=$(PKGS) -coverprofile=$(COVERFILE) $(PKGS)
	$(GO) tool cover -func=$(COVERFILE) | tail -n 1

# Each fuzz target runs for FUZZTIME. Go runs one fuzz target per invocation.
fuzz:
	$(GO) test -run='^$$' -fuzz='^FuzzRedactString$$' -fuzztime=$(FUZZTIME) ./internal/platform/logging
	$(GO) test -run='^$$' -fuzz='^FuzzDecode$$' -fuzztime=$(FUZZTIME) ./internal/platform/config
	$(GO) test -run='^$$' -fuzz='^FuzzVerifyToken$$' -fuzztime=$(FUZZTIME) ./internal/platform/tlsx
	$(GO) test -run='^$$' -fuzz='^FuzzParseTraceID$$' -fuzztime=$(FUZZTIME) ./internal/store

# Everything that needs only the Go toolchain.
ci-local: fmt-check vet build race cover

# Full CI, as run by GitHub Actions and by Astra.
ci: ci-local lint vuln secrets licenses proto-lint

lint:
	golangci-lint run $(PKGS)

vuln:
	govulncheck $(PKGS)

secrets:
	gitleaks detect --source . --config .gitleaks.toml --no-banner --redact

licenses:
	go-licenses check $(PKGS) --disallowed_types=forbidden,restricted,unknown

proto-lint:
	buf lint
	buf format --diff --exit-code

clean:
	rm -rf bin dist $(COVERFILE)
