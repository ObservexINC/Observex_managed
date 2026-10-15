# ObserveX Managed

ObserveX Managed is an AI-native, full-stack observability platform that
customers run on their own servers or cloud. It follows the architecture akash
approved as OD-25: one ObserveX Agent per host, a Unified Gateway, and a cluster
of three identical nodes, each with a Node Supervisor, an NGINX Front Door, one
modular ObserveX Server and the stores (MetricStore, SearchStore, TraceStore,
ConfigurationStore, EntityStore, BaselineStore).

## Status

Goal G00, architecture baseline. This repository holds the foundations that
every later module builds on:

| Path | What it is |
| --- | --- |
| `internal/platform/clock` | Valid time and record time on every change (ADR 0006) |
| `internal/platform/logging` | Logging that redacts secrets, with a leak test (ADR 0007) |
| `internal/platform/config` | Strict configuration loading and Ed25519 signatures |
| `internal/platform/tlsx` | TLS 1.3 mutual TLS with hybrid post-quantum key exchange, enrollment tokens (ADR 0008) |
| `internal/store` | The six store interfaces (ADR 0004) |
| `internal/store/storetest` | Contract test suites every store adapter must pass |
| `internal/store/fake` | In-memory stores that pass those suites |
| `proto/observex` | Wire schemas: common types, intake, enrollment, health |
| `docs/adr` | Architecture decision records (Proposed until akash accepts them) |
| `docs/security/threat-model.md` | Threat model |
| `docs/governance/drafts` | Drafts for akash's approval log; nothing there is approved |

No server, agent or gateway binary exists yet. They arrive in Phase 1 (G01 to
G05), each module tested on its own before integration.

## Build and test

Requires Go 1.24 or later; releases use Go 1.27. G00 uses only the standard
library, so nothing is downloaded.

Linux, macOS or WSL2:

```sh
make ci-local          # gofmt check, vet, build, race tests, coverage
make fuzz FUZZTIME=30s # each fuzz target for 30 seconds
make ci                # adds golangci-lint, govulncheck, gitleaks, go-licenses, buf
```

Windows PowerShell (no make):

```powershell
gofmt -l .
go vet ./...
go build ./...
go test -count=1 ./...
go test -count=1 -race ./...   # needs CGO_ENABLED=1 and gcc; otherwise run it in WSL2
```

`make ci` needs the tools listed in `.github/workflows/ci.yml`, installed
through the Go module proxy. The module proxy and checksum database are never
bypassed.

## Rules for contributors

- Every module ships with its tests in the same commit (ADR 0003).
- Never log, print or commit a secret. Log through `logging.New`; type secret
  values as `logging.Secret`.
- New dependencies must pass the licence policy (ADR 0005).
- Architecture changes need an ADR and akash's approval.

## Licence

Not chosen yet; akash decides. Until then all rights are reserved.
