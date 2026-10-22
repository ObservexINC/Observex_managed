# tracestore: the TraceStore v0

The TraceStore (technology row T7, ADR 0004, ADR 0011): node-local span
storage written in our own Go code. It keeps one copy on one node (IMP-2):
it survives a crash of the process, not the loss of the disk.

## What it does

```text
WriteSpans ──> write-ahead log (synced) ──> head (memory)
                                              │ full (100,000 spans or 64 MiB) or 5 minutes old
                                              v
                                   frozen head ──> flusher ──> block (immutable)
                                                                 spans.parquet  sorted by trace, start, span
                                                                 index.bin      bloom filter, trace index,
                                                                                service-and-time index
```

- **Writes** are all-or-nothing: the whole call is validated, encoded as one
  log record (CRC-32C) and synced to disk before `WriteSpans` returns. Then
  the spans go to the in-memory head.
- **Flushes** run in the background. A full or old head is frozen, written as
  a block under a temporary name, synced, renamed into place, and only then
  are its log segments deleted. While too many heads wait, writers wait; if
  the last flush failed, writes are refused instead of filling memory.
- **Reads** merge heads and blocks. Each span keeps the sequence number of
  the write that stored it, and the highest wins, so a rewrite replaces a
  span wherever the older version lives.
- **`GetTrace`** checks each block's bloom filter, finds the trace in the
  block's trace index (one entry per trace, binary search on disk) and reads
  only that trace's rows.
- **`FindTraces`** takes candidates from the heads and from each block's
  service-and-time index (per service, span starts sorted by time), then
  checks and summarises every candidate from the latest version of all its
  spans.
- **Recovery** on `Open`: unfinished blocks (temporary directories) are
  removed, blocks are opened and checked (CRC of the index, row counts), and
  log records not yet in a block are replayed. A torn record at the end of the
  log is cut; a damaged record earlier is cut too, with everything after it in
  that segment, and logged as an error.

Block formats: `parquet` (the default; Zstandard-compressed, readable by any
Parquet tool: IDs as fixed-length byte arrays, times as nanosecond
timestamps, attributes as a key and value list) and `segment` (the log's own
encoding, uncompressed), kept for the comparison below.

## How to run it

```go
ts, err := tracestore.Open("/var/lib/observex/traces", tracestore.Options{Logger: logger})
defer ts.Close()
err = ts.WriteSpans(ctx, spans)
spans, err := ts.GetTrace(ctx, id)
sums, err := ts.FindTraces(ctx, store.TraceQuery{Service: "checkout", Range: r})
```

The store implements `selfmon.Collector` (spans and batches written, log
bytes, flushes and flush errors, bytes cut at recovery, blocks, spans in
blocks and in memory, frozen heads, last flush duration).

Tests: `go test -race ./internal/store/tracestore` runs the contract suite
six ways (both formats; in the head, flushed to blocks after every write,
and reopened after every write),
comparisons with the fake across rewrites, flushes and reopening, recovery
tests (torn tail cut at every length, damaged records, unfinished blocks, a
block and its log both present, damaged indexes), and the crash test: a
writer in a child process is killed at random moments (ten rounds per
format) and the recovered store must hold every acknowledged write, the
write in flight whole or not at all, and nothing else. Fuzz targets:
`FuzzWALRecords`, `FuzzBlockIndex`, `FuzzBlockReader`.

## Configuration

| Option | Default | Meaning |
| --- | --- | --- |
| `MaxHeadSpans`, `MaxHeadBytes`, `MaxHeadAge` | 100,000; 64 MiB; 5 min | When a head is frozen and written as a block |
| `GroupSpans` | 4,096 | Spans per Parquet row group or segment group (groups end at a trace boundary) |
| `Format` | `parquet` | `parquet` or `segment` |
| `MaxFrozenHeads` | 4 | Frozen heads that may wait before writers wait |
| `Logger` | none | Flush errors and recovery notes |

Directories are created owner-only (0700), files 0600: spans can hold
personal data.

## Format comparison (Claude's workspace)

100,000 spans (12,500 traces of 8 spans, 6 services, 5 or 6 attributes),
blocks of 25,000 spans; `go test -run '^$' -bench . ./internal/store/tracestore`
on a 2-vCPU cloud container (Intel Xeon 2.8 GHz, ext4). Figures vary between
runs by up to about a factor of two; the evidence of each goal has the raw
output.

| Measure | Parquet | Segment |
| --- | --- | --- |
| Disk per span | about 70 bytes | about 270 bytes |
| Block write | about 250,000 spans/s | about 400,000 spans/s |
| `GetTrace`, trace present | about 0.5 ms | about 0.04 ms |
| `GetTrace`, trace absent | about 1 µs | about 1 µs |
| `FindTraces`, 6,000 candidates, limit 100 | about 0.4 s | about 0.2 s |
| `Open` with 4 blocks | about 4 ms | about 2 ms |

Parquet is about four times smaller on disk and is an open format customers
can read; the segment format reads faster. v0 keeps Parquet (row T7); see
ADR 0011.

## Limits

- One copy per node; no replication (IMP-2), no retention or compaction yet:
  blocks stay until a later goal adds retention.
- `FindTraces` summarises every candidate trace before sorting, so a busy
  service over a long range costs time in proportion to its traces.
- Times must lie between 1678 and 2262 (Unix nanoseconds in an int64);
  others are `ErrInvalid`. A call may encode to at most 64 MiB.
- Every write is synced on its own (no group commit yet), which bounds
  write throughput by the disk's sync latency.
- The crash test kills the process; it does not cut power. Power-loss safety
  rests on the sync order described above.
