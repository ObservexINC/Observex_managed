# ADR 0011: The stores at G02: engines, layouts and limits

Status: Proposed.

## Context

G02 builds the four store adapters of Phase 1 (technology rows T5 to T8, ADR
0004): "Done when: each passes the contract suite on its fake and its real
engine; the TraceStore survives a crash test." Each adapter is a package of
its own under `internal/store`, with a README.

## Decision

### ConfigurationStore: embedded etcd (`internal/store/etcdstore`)

- etcd 3.7.2 runs inside the node process (`embed`), one member per node. The
  ConfigStore talks to its own member in process (`v3client`), or to any
  member through a normal etcd client.
- The contract maps onto etcd transactions: create-only compares the key's
  create revision with 0; a positive expected revision compares its
  modification revision; a failed delete reads the key in the same
  transaction to tell "missing" (`ErrNotFound`) from "changed"
  (`ErrConflict`). Revisions are etcd's cluster-wide revisions.
- Stores take a key prefix, so subsystems share a member without seeing each
  other's keys.
- Without a quorum, reads and writes fail when their context ends. There are
  no stale reads: every read is linearizable.
- Until G03 brings member TLS and membership changes, members use plain HTTP
  and the configuration accepts loopback addresses only.
- etcd's zap log records go through the node's slog logger, and so through
  the redacting handler (ADR 0007).
- Old revisions are compacted after an hour.

### Real engines in tests

The contract suite runs against each real engine through the same test
function as the fake. **Deviation from row T19 for akash to accept or
reject:** T19 names Testcontainers-go for real engines. The tests instead
take a running engine's address from an environment variable
(`OBSERVEX_TEST_CASSANDRA`, `OBSERVEX_TEST_OPENSEARCH`); `test/rig` starts the
engines in Docker or from signature-checked tarballs. Reasons: the same suite
then runs against Docker, a tarball install or the 3-node rig, and Claude's
workspace has no container registry access, so Testcontainers could not run
there. Without the variables the engine tests skip and say so;
`OBSERVEX_REQUIRE_ENGINES=1` turns a missing engine into a failure. etcd and
the TraceStore need no external engine and always run.

## Consequences

- Go language level 1.27 (ADR 0002): etcd 3.7 and opensearch-go 4.8 need Go
  1.26 or later.
- New third-party modules, all under licences ADR 0005 allows; `make
  licenses` checks them.

## What would change this decision

- Member TLS and membership changes (G03) replace the loopback-only rule.
