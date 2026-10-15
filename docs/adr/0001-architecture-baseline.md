# ADR 0001: Architecture baseline (OD-25)

Status: Proposed. The architecture itself was approved by akash as OD-25 on
5 October 2026; this record restates it for the new repository.

## Context

ObserveX Managed is built from scratch in this repository (akash's direction,
14 October 2026) and serves every sector (15 October 2026). OD-25 makes
Dynatrace Managed's architectural behaviour the reference; implementation
technology may differ where engineering evidence supports it, and any deviation
needs akash's approval.

## Decision

| Rule | Source |
| --- | --- |
| One ObserveX Agent per host: watchdog, core and modules | OD-25 policy 1 |
| One Gateway binary in three modes: environment, cluster, embedded | policy 2; directive of 12 Oct |
| Identical cluster nodes, three by default; no role-specialised nodes without an ADR | policy 3 |
| One modular ObserveX Server program per node | policy 4 |
| No message bus by default: no Kafka or similar | policy 5; directive of 12 Oct |
| MetricStore is Cassandra-class, Cassandra the baseline; ClickHouse not primary without an ADR, a benchmark and akash's approval | policy 6 |
| SearchStore is OpenSearch-class for logs, events, sessions, synthetic results and problems; 1 replica on 3 nodes | policy 7; D5 |
| TraceStore is a dedicated, node-local subsystem with one copy and no HA claim | policy 8; IMP-2 |
| Topology is first-class; Problems follow baselines, anomalies and topology deterministically; no language model in the core | policies 9 and 10; D7 |
| Cluster administration is local; Mission Control is vendor-run, outbound-only and never a runtime dependency | policies 11 and 12 |
| Bounded disk-backed buffers in Agent and Gateway; acknowledgement meanings written down before durable delivery is built | IMP-1; DR-07 and DR-08 open |
| TLS 1.3, mTLS, enrollment, per-agent identity, signed packages and configuration, SBOMs; quotas; remote support off by default; backup, upgrade and rollback | IMP-3 to IMP-6 |
| Remediation off by default; own API with PromQL and LogQL as adapters only; store interfaces kept; OpenTelemetry-first code modules, eBPF later | D1 to D4, D6 |
| NGINX Front Door on its own port; the Node Supervisor checks firewall needs and never changes them; agents may send straight to a node; injection through a Kubernetes operator | DEV-02 to DEV-04 |

The ConfigurationStore, EntityStore and BaselineStore engines are left open by
OD-25. ADR 0002 proposes them; their final choice needs prototypes in G02 and
G08.

## Consequences

- Three storage engines must be operated in every installation. Platform
  Autopilot (G16) exists to carry that load.
- Traces are lost for a failed node's share. Incident capsules (G09) keep the
  traces that matter.
- No code in this repository may assume a message bus or a role-specialised node.

## What would change this

Only akash, through a new OD entry.
