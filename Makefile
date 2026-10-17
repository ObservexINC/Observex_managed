# ObserveX Managed build and test entry points.
#
# Targets that need tools downloaded through the Go module proxy
# (lint, vuln, secrets, licenses, proto-lint) are run in CI and by Astra.
# They never bypass the module proxy or checksum database.

GO        ?= go
PKGS      := ./...
FUZZTIME  ?= 30s
COVERFILE := coverage.out
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOARCH    ?= amd64
TARBALL   := dist/observex-managed-node-$(VERSION)-linux-$(GOARCH).tar.gz
SHELL_SCRIPTS := packaging/linux/install.sh packaging/linux/uninstall.sh packaging/linux/test-install.sh scripts/package.sh

.PHONY: all build fmt-check vet test race cover fuzz ci-local ci lint vuln secrets licenses proto-lint shell-check package install-test clean

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
	$(GO) test -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=$(FUZZTIME) ./internal/node
	$(GO) test -run='^$$' -fuzz='^FuzzParseFeatures$$' -fuzztime=$(FUZZTIME) ./internal/node/frontdoor
	$(GO) test -run='^$$' -fuzz='^FuzzCheck$$' -fuzztime=$(FUZZTIME) ./internal/node/firewall
	$(GO) test -run='^$$' -fuzz='^FuzzParseStat$$' -fuzztime=$(FUZZTIME) ./internal/node/selfmon
	$(GO) test -run='^$$' -fuzz='^FuzzWriteText$$' -fuzztime=$(FUZZTIME) ./internal/node/selfmon

# Shell scripts: syntax check everywhere; shellcheck where installed (CI).
shell-check:
	@for f in $(SHELL_SCRIPTS); do sh -n "$$f" || exit 1; done
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck $(SHELL_SCRIPTS); else echo "shellcheck not installed; syntax checked only"; fi

# The node tarball (packaging/linux/README.md).
package:
	VERSION=$(VERSION) GOARCH=$(GOARCH) scripts/package.sh

# Install test under a temporary root; no root needed. The live test
# (packaging/linux/test-install.sh live) needs a disposable machine.
install-test: package
	packaging/linux/test-install.sh layout $(TARBALL)

# Everything that needs only the Go toolchain.
ci-local: fmt-check vet build race cover shell-check

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
