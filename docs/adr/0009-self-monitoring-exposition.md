# ADR 0009: Node self-monitoring without the OpenTelemetry SDK at G01

Status: Proposed.

## Context

The development plan names the OpenTelemetry Go SDK for the self-monitoring
module (G01). Claude's development workspace cannot reach the Go module
proxy, so no third-party module can be added (ADR 0002), and the module
proxy is never bypassed.

## Decision

- `internal/node/selfmon` uses the standard library only. Collectors read
  their sources at every scrape (supervisor state, `/proc` for each
  component's process group, host load and memory, disk space, certificate
  expiry).
- The Node Supervisor serves the metrics on its loopback status listener at
  `/metrics` in the Prometheus text format 0.0.4. The Front Door never
  exposes it (tested).
- Metric names follow OpenTelemetry's naming guidance (`observex_node_*`,
  units in the name, `_total` for counters), so an OTLP exporter added later
  reads the same `Gather` output without renaming.
- Problems while collecting are themselves a metric
  (`observex_selfmon_errors{source}`), so a missing source is visible rather
  than silent.

## Consequences

- No dependency, nothing to download, and the module passes its tests in
  the workspace.
- Pushing the node's metrics into ObserveX itself (OTLP to the cluster)
  waits for the Server (G03/G06). Until then the metrics are scraped
  locally.

## What would change this

Access to the module proxy. Then the OTLP exporter is added behind the same
collectors, and this ADR is superseded.
