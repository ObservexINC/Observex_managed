# test/rig: real engines for the store adapter tests

The Cassandra and OpenSearch adapters pass the same contract suite as their
fakes, against real engines (ADR 0004, ADR 0011). The tests find the engines
through environment variables; this folder starts them. etcd and the
TraceStore need no engine: their tests always run.

| Variable | Example |
| --- | --- |
| `OBSERVEX_TEST_CASSANDRA` | `127.0.0.1:9042` (comma-separated for several) |
| `OBSERVEX_TEST_CASSANDRA_USERNAME`, `_PASSWORD` | only when Cassandra uses PasswordAuthenticator |
| `OBSERVEX_TEST_OPENSEARCH` | `https://127.0.0.1:9200` |
| `OBSERVEX_TEST_OPENSEARCH_CA` | PEM file of the CA behind OpenSearch's HTTPS certificate |
| `OBSERVEX_TEST_OPENSEARCH_USERNAME`, `_PASSWORD` | `admin` and the admin password |
| `OBSERVEX_REQUIRE_ENGINES` | `1` makes a missing engine fail the tests instead of skipping them |

Then `make test-engines` runs every store package with the race detector and
`OBSERVEX_REQUIRE_ENGINES=1`.

## Docker (Windows 11 with WSL2 and Docker Desktop, or Linux)

```sh
export OPENSEARCH_INITIAL_ADMIN_PASSWORD='<8+ characters: upper, lower, digit, symbol>'
docker compose -f test/rig/compose.yaml up -d
docker compose -f test/rig/compose.yaml ps        # wait until cassandra is healthy
docker compose -f test/rig/compose.yaml cp opensearch:/usr/share/opensearch/config/root-ca.pem /tmp/observex-os-ca.pem

export OBSERVEX_TEST_CASSANDRA=127.0.0.1:9042
export OBSERVEX_TEST_OPENSEARCH=https://127.0.0.1:9200
export OBSERVEX_TEST_OPENSEARCH_CA=/tmp/observex-os-ca.pem
export OBSERVEX_TEST_OPENSEARCH_USERNAME=admin
export OBSERVEX_TEST_OPENSEARCH_PASSWORD="$OPENSEARCH_INITIAL_ADMIN_PASSWORD"
make test-engines

docker compose -f test/rig/compose.yaml down -v
```

The images default to Docker Hub's `cassandra:5.0.9` and
`opensearchproject/opensearch:3.9.0`. Where they come from is akash's
decision (development plan, open items): set `CASSANDRA_IMAGE` and
`OPENSEARCH_IMAGE` to a mirror (for example Amazon ECR Public) or to images
loaded with `docker load`.

## Tarballs (Linux or WSL2, no Docker)

```sh
test/rig/engines-tarball.sh fetch ~/observex-engines   # download, check SHA and OpenPGP signatures
test/rig/engines-tarball.sh start ~/observex-engines   # Cassandra with a password, OpenSearch with HTTPS
eval "$(test/rig/engines-tarball.sh env ~/observex-engines)"
make test-engines
test/rig/engines-tarball.sh stop ~/observex-engines
```

`fetch` downloads Cassandra 5.0.9 from archive.apache.org and OpenSearch
3.9.0 from artifacts.opensearch.org, and refuses to go on unless each
tarball matches its published checksum and its OpenPGP signature verifies
against the project's key file. `start` needs Java 17 for Cassandra
(`apt-get install openjdk-17-jre-headless`; OpenSearch brings its own) and
runs OpenSearch as a user other than root (`OPENSEARCH_USER=...` when the
script runs as root). The OpenSearch admin password is generated into the
directory, owner-only, and never printed.

## Notes

- Both setups publish loopback ports only.
- On machines where the disk is mostly full, OpenSearch's default watermarks
  block index creation; both setups use absolute watermarks (2 GB, 1 GB,
  500 MB free) instead.
- `node.store.allow_mmap: false` lets OpenSearch run where
  `vm.max_map_count` cannot be raised (containers, WSL2 defaults).
