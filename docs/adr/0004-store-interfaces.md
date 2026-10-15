# ADR 0004: Store interfaces and contract suites (D1)

Status: Proposed. Implements decision D1 from OD-25.

## Decision

Modules read and write data only through six interfaces in `internal/store`:

| Interface | Store | Engine (ADR 0002) |
| --- | --- | --- |
| `MetricStore` | MetricStore | Cassandra |
| `SearchStore` | SearchStore | OpenSearch |
| `TraceStore` | TraceStore | Own node-local files |
| `ConfigStore` | ConfigurationStore | Embedded etcd |
| `HistoryStore` | EntityStore change log (System History) | Cassandra |
| `BaselineStore` | BaselineStore | Cassandra |

Each interface documents its contract in Go doc comments: all-or-nothing
writes, ordering of results, half-open time ranges, replace-on-repeat
semantics, `ErrNotFound`, `ErrConflict`, `ErrInvalid` and `ErrClosed`, copying
of values in and out, and behaviour on cancelled contexts.

`internal/store/storetest` holds one contract suite per interface.
`internal/store/fake` holds in-memory implementations that pass those suites.
A real adapter is accepted only when it passes the same suite, against a real
engine started by Testcontainers (G02 onward).

## Consequences

- Modules can be built and tested in Phase 1 without any database.
- Changing an engine later means writing one adapter and passing one suite.
- The interfaces are deliberately small. Engine-specific features (secondary
  indexes, aggregations) are added to an interface only when a module needs
  them, with a contract test in the same commit.

## Open

The ConfigurationStore and EntityStore engines are proposals pending prototypes
(OD-25 left them open). The HistoryStore interface states the knowledge graph's
needs: append-only writes, time-range scans and both clocks.
