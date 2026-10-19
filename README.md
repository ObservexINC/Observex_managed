# ObserveX Managed

ObserveX Managed is an AI-native, full-stack observability platform that
customers run on their own servers or cloud. It follows the architecture akash
approved as OD-25: one ObserveX Agent per host, a Unified Gateway, and a cluster
of three identical nodes, each with a Node Supervisor, an NGINX Front Door, one
modular ObserveX Server and the stores (MetricStore, SearchStore, TraceStore,
ConfigurationStore, EntityStore, BaselineStore).

## Status

Goals G00 (architecture baseline) and G01 (node platform) are built. G01's
node runs the Node Supervisor, the NGINX Front Door and self-monitoring, and
installs from a tarball (`packaging/linux/README.md`).

| Path | What it is |
| --- | --- |
| `cmd/observex-node` | The node command: `run`, `check`, `firewall`, `status`, `health`, `render-nginx`, `init`, `version` |
| `internal/node` | Node configuration and assembly (ADR 0010) |
| `internal/node/supervisor` | Node Supervisor: start order, readiness, restarts with backoff, crash loops, clean stop |
| `internal/node/frontdoor` | NGINX Front Door configuration: TLS 1.3, Console and Agents listeners, fixed routes |
| `internal/node/firewall` | Read-only firewall report; never changes the firewall |
| `internal/node/selfmon` | The node's own metrics on loopback `/metrics` (ADR 0009) |
| `internal/node/pki` | First-install cluster CA and node certificate (interim, ADR 0010) |
| `packaging/linux` | systemd unit, `install.sh`, `uninstall.sh`, install test |
| `internal/platform/clock` | Valid time and record time on every change (ADR 0006) |
| `internal/platform/logging` | Logging that redacts secrets, with a leak test (ADR 0007) |
| `internal/platform/config` | Strict configuration loading, durations, Ed25519 signatures |
| `internal/platform/tlsx` | TLS 1.3 mutual TLS with hybrid post-quantum key exchange, enrollment tokens (ADR 0008) |
| `internal/store` | The six store interfaces (ADR 0004) |
| `internal/store/storetest` | Contract test suites every store adapter must pass |
| `internal/store/fake` | In-memory stores that pass those suites |
| `internal/store/etcdstore` | ConfigurationStore: an embedded etcd member and a ConfigStore over it (G02) |
| `internal/store/tracestore` | TraceStore v0: write-ahead log, Parquet blocks, trace and service indexes (G02) |
| `internal/store/cassandra` | MetricStore on Cassandra 5.0 (G02) |
| `internal/store/opensearch` | SearchStore on OpenSearch 3 (G02) |
| `internal/store/enginetest` | Finds the real engines adapter tests run against |
| `proto/observex` | Wire schemas: common types, intake, enrollment, health |
| `docs/adr` | Architecture decision records (Proposed until akash accepts them) |
| `docs/security/threat-model.md` | Threat model |
| `docs/governance/drafts` | Drafts for akash's approval log; nothing there is approved |
| `docs/handoff` | Each goal's handoff to Astra |

The stores are being built in G02; the Server, Gateway and Agent come next
(G03 to G05), each module tested on its own before integration (G06).

## Build and test

Requires Go 1.27. Since G02 the store adapters use third-party modules (etcd,
Parquet, GoCQL, opensearch-go); they download through the Go module proxy
with checksum verification. The Front Door tests need NGINX
(`apt-get install nginx-core`); without it they skip.

Linux, macOS or WSL2:

```sh
make ci-local          # gofmt check, vet, build, race tests, coverage, shell syntax
make install-test      # build the node tarball and install it under a temporary root
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
