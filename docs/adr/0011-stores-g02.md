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

### TraceStore v0: our own node-local store (`internal/store/tracestore`)

- Writes go to a write-ahead log (one CRC-32C record per call, synced before
  the call returns) and an in-memory head. Full or old heads are written in
  the background as immutable blocks: written under a temporary name,
  synced, renamed into place, and only then are their log segments deleted.
- Each span carries the sequence number of its write; the highest wins
  across log, heads and blocks, which is how a rewrite replaces a span.
- A block holds its spans sorted by trace, start and span ID, and an index:
  a trace-ID bloom filter, a trace index (one entry per trace, so a lookup
  reads only that trace's rows) and a service-and-time index (per service,
  span starts sorted by time) for `FindTraces`.
- Block format: **Parquet** (Zstandard, nanosecond timestamps, readable by
  any Parquet tool), as row T7 says. The simpler segment format (the log's
  encoding, uncompressed) is implemented too and benchmarked against it on
  100,000 spans: Parquet is about four times smaller on disk (about 70 bytes
  per span against 270) and slower to read (a trace in about 0.5 ms against
  0.04 ms; a 6,000-trace query in about 0.4 s against 0.2 s). Disk is the
  larger cost of keeping traces, and half a millisecond per trace is well
  within what an interactive view needs, so v0 keeps Parquet; the segment
  format stays selectable for further comparison.
- Recovery cuts a torn record at the end of the log, removes unfinished
  blocks and replays only what no block holds. A crash test kills a writer
  process at random moments and checks that every acknowledged write
  survives and the write in flight is there whole or not at all.
- While too many heads wait for the flusher, writers wait; if the last flush
  failed, writes are refused rather than filling memory.

### MetricStore: Cassandra 5.0 (`internal/store/cassandra`)

- Three tables: `metric_series` (partition: metric and one of 16 shards;
  clustering: series key; the labels), `metric_series_days` (the UTC days a
  series has points on) and `metric_points` (partition: series key and day;
  clustering: time in Unix nanoseconds). Times are `bigint` nanoseconds
  rather than Cassandra's millisecond `timestamp`, so no precision is lost.
- Writes check every sample first, then write series, days and points as
  unlogged single-partition batches under the batch size limit. Every
  statement is idempotent, so a write that fails part way can be repeated;
  the contract's all-or-nothing applies to invalid input, which writes
  nothing.
- Queries list a metric's series from its shards, filter them by the
  matchers, and read only the days each series has data on.
- GoCQL v2 with PasswordAuthenticator; the password is a `logging.Secret`.
  The driver's warnings and errors go through the redacting handler. No TLS
  yet (G06).

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
- If trace queries over long ranges become the bottleneck, the TraceStore
  needs per-trace summaries in its index, or the segment format's faster
  reads; retention and compaction come with the goal that needs them.
