# cassandra: the MetricStore on Apache Cassandra

The MetricStore adapter (technology row T5, ADR 0004, ADR 0011) on Apache
Cassandra 5.0 through the Apache GoCQL driver v2. The History and Baseline
tables (row T9) join this package in G08.

## What it does

Three tables in the store's keyspace:

| Table | Partition key | Clustering | Holds |
| --- | --- | --- | --- |
| `metric_series` | metric, shard (16) | series key | the series' labels |
| `metric_series_days` | series key | day | the UTC days a series has points on |
| `metric_points` | series key, day | `t` (Unix ns) | the value |

- A series is identified by `store.Series.Key()`, its canonical text, so
  label order never creates a second series. Points keep full nanosecond
  precision (`bigint`), which Cassandra's `timestamp` (milliseconds) would
  not.
- **Writes** check every sample first (nothing is written if one is
  invalid), then write new series and series-days, then the points, as
  unlogged batches within one partition and under Cassandra's batch size
  limit, with up to 8 requests in flight. Every statement is idempotent: a
  write that fails part way returns an error, and repeating it converges.
  Series and days already written are remembered (up to 100,000) and not
  rewritten.
- **Queries** list the metric's series from its 16 shards, apply the
  equality matchers (a missing label equals ""), find each matching series'
  days in the range, and read only those partitions. A range of a century
  therefore costs no more than the days that hold data.
- Points partitions use TimeWindowCompactionStrategy with one-day windows.

## How to run it

```go
m, err := cassandra.OpenMetricStore(ctx, cassandra.Config{
	Hosts: []string{"10.0.0.11:9042"}, Keyspace: "observex",
	Username: "observex", Password: logging.Secret(passwordFromFile),
	CreateSchema: true, Datacenter: "dc1", ReplicationFactor: 3,
})
```

The store implements `selfmon.Collector`: whether the session is open,
samples written, queries, and write and query errors.

Tests need a running Cassandra:

```sh
OBSERVEX_TEST_CASSANDRA=127.0.0.1:9042 \
OBSERVEX_TEST_CASSANDRA_USERNAME=... OBSERVEX_TEST_CASSANDRA_PASSWORD=... \
go test -race ./internal/store/cassandra
```

Each test works in a keyspace of its own and drops it afterwards. Without
`OBSERVEX_TEST_CASSANDRA` the engine tests skip (fail with
`OBSERVEX_REQUIRE_ENGINES=1`); configuration and logging tests always run.
`test/rig` starts Cassandra.

## Configuration

| Field | Default | Meaning |
| --- | --- | --- |
| `Hosts` | required | Contact points, `host` or `host:port` |
| `Keyspace` | required | A letter then up to 47 letters, digits or underscores |
| `Username`, `Password` | none | PasswordAuthenticator; the password is a `logging.Secret` and never prints |
| `CreateSchema` | false | Create the keyspace (NetworkTopologyStrategy) and tables if missing |
| `Datacenter`, `ReplicationFactor` | datacenter1, 1 | Replication when the keyspace is created |
| `Consistency` | LOCAL_QUORUM | Reads and writes |
| `Timeout` | 10 s | Per request and per connection attempt |
| `Logger` | none | The driver's warnings and errors, through the redacting handler |

## Limits

- No TLS to Cassandra yet; use loopback or a private network. TLS with the
  cluster's CA comes with node integration (G06).
- A write is all-or-nothing for invalid input, not for an engine failure in
  the middle of a call (see above).
- Times between 1678 and 2262 (Unix nanoseconds in an int64); others are
  `ErrInvalid`.
- Series of one metric share 16 partitions of `metric_series`; a metric with
  millions of series makes them large. Cardinality limits come with
  Adaptive Telemetry (G13).
- Empty label maps read back as nil.
