# ADR 0002: Technology choices T1 to T20

Status: Proposed. Taken from the development plan that akash approved for
implementation on 15 October 2026. The per-row decision fields in the plan
document are still akash's to set.

## Decision

| # | Area | Choice |
| --- | --- | --- |
| T1 | Data-path language | Go 1.27 for CI and releases; module proxy and checksum database always on |
| T2 | Agent | Go core with watchdog and modules; upstream OpenTelemetry language agents as code modules; eBPF through OBI after its 1.0 |
| T3 | Wire protocols | OTLP for telemetry; Protobuf and gRPC between components; Buf for linting and breaking-change checks |
| T4 | Public and Console API | ConnectRPC; v1 or v2 chosen when the first API handler is written (G10) |
| T5 | MetricStore | Apache Cassandra 5.0.x on Java 17; Apache GoCQL driver v2 |
| T6 | SearchStore | OpenSearch 3.x; opensearch-go v4 |
| T7 | TraceStore | Own Go subsystem with node-local Parquet blocks and trace-ID and service-time indexes; benchmarked in G02 against a simpler segment format |
| T8 | ConfigurationStore and coordination | Embedded etcd in every node |
| T9 | EntityStore, System History, BaselineStore | Cassandra tables, live graph in Server memory |
| T10 | Front Door | NGINX stable |
| T11 | Console | TypeScript, React, Vite, TanStack Query, uPlot, Cytoscape.js; Vitest and Playwright |
| T12 | Browser monitoring script | TypeScript, OpenTelemetry browser conventions |
| T13 | AI Investigator, Scorecard, log-parsing fallback | Go, calling models through an OpenAI-compatible API |
| T14 | Model serving | vLLM on GPUs; llama.cpp server on CPUs; or the customer's endpoint |
| T15 | Baselines, anomalies, forecasts | Go with gonum, deterministic |
| T16 | Offline AI evaluation tools | Python 3.12 or later, never shipped |
| T17 | Packaging | Linux hosts first (RPM, DEB, tarball, systemd); Kubernetes operator later |
| T18 | Build and CI | GitHub Actions and Make; golangci-lint, govulncheck, gitleaks, go-licenses, Buf; Syft SBOMs and cosign signing at release |
| T19 | Test tooling | Go testing with the race detector and fuzzing; Testcontainers-go; Toxiproxy; telemetrygen; Vitest and Playwright |
| T20 | Licence policy | See ADR 0005 |

## Language level and the development workspace

`go.mod` declares language level 1.24, not 1.27. Claude's development workspace
has Go 1.24.7 and cannot reach proxy.golang.org or sum.golang.org (the network
policy refuses them), so it cannot download the 1.27 toolchain or any module.
CI builds and tests with both 1.27 and 1.24. The `go` line moves to 1.27 when
the workspace can reach the module proxy, or when the first 1.25+ feature is
needed, whichever comes first. The module proxy and checksum database are never
bypassed to work around this.

## Consequences

- G00 code uses only the Go standard library, so it needs no downloads.
- Configuration documents are JSON (standard library) rather than YAML.
- Tool versions in CI are unpinned until the first green run; pinning them is a
  recorded follow-up.

## What would change this

A benchmark or an operational finding that contradicts a row, raised as a new
ADR for akash.
