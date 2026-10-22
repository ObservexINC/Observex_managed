# opensearch: the SearchStore on OpenSearch

The SearchStore adapter (technology row T6, ADR 0004, ADR 0011) on
OpenSearch 3 through the opensearch-go v4 client.

## What it does

Each SearchStore index is an OpenSearch index named `<prefix>-n-<name>` when
the name is already a valid index name (lowercase letters, digits, dashes,
underscores, up to 128 characters), and `<prefix>-h-<SHA-256 of the name>`
otherwise, so any name works and the two kinds never collide. Indexes are
created on first use with a strict mapping:

| Field | Type | Holds |
| --- | --- | --- |
| `id` | keyword | the document ID, for ordering ties |
| `time` | date_nanos | the time, to the nanosecond |
| `body_lc` | wildcard | the body lowercased in Go, in chunks of up to 30,000 bytes that overlap by 2,048 bytes |
| `pairs` | keyword | a SHA-256 of each field's name and value |
| `doc` | object, not indexed | the body and fields exactly as given |

The OpenSearch `_id` is a SHA-256 of the document ID, so IDs of any length
and content work and re-indexing an ID replaces the document.

- **Text search** follows the contract exactly: every word of the query,
  lowercased, must appear in the lowercased body as a substring. Each word
  becomes a wildcard query on the body's chunks (a word longer than 128
  bytes is searched by its first 128 bytes, since OpenSearch refuses longer
  patterns), and every hit is checked against the whole body before it is
  returned, paging on with `search_after` when hits fail the check.
  Lowercasing is Go's on both sides, so results equal the fake's.
- **Filters** are exact: a term query on the hash narrows candidates, then
  every hit is checked against its original field names and values. This
  also handles names and values containing NUL without changing existing
  index data. Rejected candidates do not consume the result limit.
- **Order**: newest first, ties by ID ascending, at most the limit. Paging
  preserves the engine's raw sort values, including integer nanoseconds,
  without converting them to floating-point numbers.
- **Index** checks every document first, sends bulk requests of up to 8 MiB
  and returns once the documents are searchable (`refresh=wait_for`). A call
  that fails part way returns the error; repeating it converges.
- A search of an index that does not exist returns nothing.

## How to run it

```go
s, err := opensearch.Open(opensearch.Config{
	Addresses: []string{"https://10.0.0.11:9200"},
	Username: "observex", Password: logging.Secret(passwordFromFile),
	CACertFile: "/etc/observex/tls/opensearch-ca.pem", Replicas: 1,
})
```

The store implements `selfmon.Collector`: documents indexed, searches, and
index and search errors.

Tests need a running OpenSearch:

```sh
OBSERVEX_TEST_OPENSEARCH=https://127.0.0.1:9200 OBSERVEX_TEST_OPENSEARCH_CA=root-ca.pem \
OBSERVEX_TEST_OPENSEARCH_USERNAME=... OBSERVEX_TEST_OPENSEARCH_PASSWORD=... \
go test -race ./internal/store/opensearch
```

Each test uses an index prefix of its own and deletes its indexes
afterwards. Plain `http://` works too, for a node without the security
plugin. Without `OBSERVEX_TEST_OPENSEARCH` the engine tests skip (fail with
`OBSERVEX_REQUIRE_ENGINES=1`); configuration, logging, chunking and naming
tests always run.

## Configuration

| Field | Default | Meaning |
| --- | --- | --- |
| `Addresses` | required | Node URLs |
| `Username`, `Password` | none | Basic authentication; the password is a `logging.Secret` |
| `CACertFile` | system roots | PEM of the CA behind the nodes' HTTPS certificates |
| `IndexPrefix` | `observex` | Lowercase letters, digits, dashes, underscores; up to 32 |
| `Shards`, `Replicas` | 1, 0 | For indexes the store creates |
| `Timeout` | 30 s | Per request |

## Limits

- Text must be valid UTF-8 (IDs, bodies, field names and values, search
  text); otherwise `ErrInvalid`. The fake does not check this.
- Times from 1970 to 2262 (`date_nanos`); document IDs up to 32,766 bytes.
- Words shorter than three characters cannot use the wildcard field's
  n-gram index, so OpenSearch checks every document in the range for them.
- The lowercased body is kept a second time for search (in the wildcard
  field's doc values), so a document takes more space than its text.
- No index lifecycle (rollover, retention) yet; it comes with Adaptive
  Telemetry (G13).
