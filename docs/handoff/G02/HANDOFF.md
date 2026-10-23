# G02 handoff to Codex Astra

Goal: G02, the store adapters of Phase 1 (technology rows T5 to T8, ADR
0004, ADR 0011). Status: **implemented and tested in Claude's workspace;
awaiting Astra's validation and akash's approval.** G02 is not pushed.

Where GitHub stands (read on 22 October 2026): `main` is at `e282263`, the
G01 CI repair akash pushed on 20 October, and CI is green there. Pull
request #1 shows as merged.

| Run | Commit | Result |
| --- | --- | --- |
| #1 | `49b834e` (G00) | Lint failed; G01 fixed it in `72d467d` |
| #2 | `4e29c5d` (G01 boundaries II) | Fuzzing failed (Go 1.27); lint and every other job passed |
| #3 | `539d5d3` (pull request #1) | Every job passed |
| #4 | `f15eb8b` (Copilot) | Fuzzing failed on Go 1.27 and 1.24; lint and every other job passed |
| #5 | `e282263` (G01 CI repair) | Every job passed |

Run #5 warned that `actions/checkout@v4` and `actions/setup-go@v5` were
forced onto Node.js 24 and that `ubuntu-latest` is moving to Ubuntu 26.
akash chose on 22 October to answer both in G02 (`10283a1`).

> This is the third version of the G02 handoff. The first (`214f549`, on
> `4e29c5d`) had the redaction fix as its own commit `bb8095f`, which
> Astra's `539d5d3` now holds; the second (`5b3d309`, 20 October) had the
> same code as this one, which adds `10283a1`. Earlier bundles are
> superseded; do not apply them.

## Commits on main (on top of `4e29c5d`)

| Commit | Content |
| --- | --- |
| `f15eb8b` | On GitHub: Copilot's change to `config.go`, which panics when closing a configuration file fails |
| `6ccb81d` | On GitHub: revert of `f15eb8b`; the lint failure it targeted was G00's, fixed in G01 |
| `539d5d3` | On GitHub: Astra's G01 CI repair (pull request #1): the redaction fix from G02, the input GitHub's CI failed on (`920830b90e0a0575`), the fuzz minimization limit, failing fuzz inputs kept as a CI artifact |
| `e282263` | On GitHub: merge of `539d5d3`; its tree is `539d5d3`'s. **G02 starts after it** |
| `58a0447` | ConfigurationStore on embedded etcd 3.7.2; Go language level 1.27 |
| `36b0ee2` | TraceStore v0: write-ahead log, Parquet blocks, trace and service indexes; its three fuzz targets in `make fuzz` |
| `fccef02` | MetricStore on Cassandra 5.0 (GoCQL v2.1.2); `internal/store/enginetest` |
| `338b0f4` | SearchStore on OpenSearch 3 (opensearch-go v4.8.1); MetricStore rejects labels that are not UTF-8 |
| `0afea32` | Engine rig (`test/rig`), `make test-engines`, CI job on real engines |
| `5d6e79b` | klauspost/compress 1.18.0 to 1.18.7 (GO-2026-5841, an out-of-bounds read in a package parquet-go brings in; not called) |
| `10283a1` | CI: every job on `ubuntu-24.04` instead of `ubuntu-latest`; `actions/checkout`, `actions/setup-go` and `actions/upload-artifact` v7, which run on Node.js 24. Only `.github/workflows/ci.yml` changes |
| next commit | This handoff folder; a pointer at the top of `docs/handoff/G01/BOUNDARIES-II.md`; the TraceStore README said its contract suite runs nine ways, it runs six |

Every commit after `f15eb8b` builds, vets for Linux and Windows and passes
its tests on its own (`per-commit-checks.log`). `observe-G02.bundle` holds
every commit since G00 and applies to `e282263` (GitHub's and akash's
`main`), to `f15eb8b`, to `539d5d3`, to `4e29c5d` or to any earlier
handoff commit.

## G02 "done when" and where it stands

| Criterion | Claude's workspace | Still needed |
| --- | --- | --- |
| The MetricStore passes the contract suite on its fake and its real engine | Fake: yes. Cassandra 5.0.9 (signature-checked tarball, Java 17, PasswordAuthenticator): yes, plus a comparison with the fake and edge cases | Astra with Docker (step 5) |
| The SearchStore passes it on its fake and its real engine | Fake: yes. OpenSearch 3.9.0 (signature-checked tarball, security plugin, HTTPS, basic authentication): yes; also over plain HTTP without the plugin, as in CI | Astra with Docker (step 5) |
| The TraceStore passes it on its fake and its real engine | The TraceStore is its own engine: the suite runs six ways (Parquet and segment formats, each with data in the head, flushed to blocks, or reopened after every write) | Astra on Windows and WSL2 (steps 3, 4) |
| The ConfigurationStore passes it on its fake and its real engine | Embedded etcd 3.7.2: three ways (shared member, fresh member, network client), plus the quorum-loss test on three members | Astra on Windows and WSL2 |
| The TraceStore survives a crash test | A writer process killed at random moments, ten rounds per format: every acknowledged write survives, the write in flight is whole or absent, nothing else appears | Astra on WSL2, and on Windows, where the kill is TerminateProcess |

## What G02 delivers

- **ConfigurationStore** (`internal/store/etcdstore`): an etcd member
  embedded in the node process and a ConfigStore over it with etcd
  transactions; key prefixes per store; linearizable reads, so a member
  without quorum refuses rather than serving stale data; etcd's logs through
  the redacting handler; loopback addresses only until member TLS in G03.
- **TraceStore v0** (`internal/store/tracestore`): write-ahead log synced
  before `WriteSpans` returns; background flush to immutable blocks
  (temporary name, sync, rename, then delete the log); Parquet blocks with a
  trace-ID bloom filter, a trace index and a service-and-time index; latest
  write wins across log, heads and blocks; recovery that cuts torn records
  and removes unfinished blocks; write backpressure.
- **MetricStore** (`internal/store/cassandra`): series, series-days and
  points tables; nanosecond times; idempotent single-partition batches under
  the batch limit; queries that read only days holding data.
- **SearchStore** (`internal/store/opensearch`): one index per SearchStore
  index; the contract's substring search kept exactly with a `wildcard`
  field in overlapping chunks and a check of every hit; exact filters
  through hashes; `date_nanos`; HTTPS with a configured CA.
- Each store reports to self-monitoring, has a README, and takes passwords
  as `logging.Secret`.
- **Rig** (`test/rig`): Docker compose and a tarball script that verifies
  checksums and OpenPGP signatures before running anything; `make
  test-engines`; a CI job with engine service containers.

## Found in G01's redaction while verifying G02, and on GitHub

`make fuzz` in G02 limited input minimization to one second (the G01
boundaries II handoff explained why its counts stalled), so its 30-second
runs fuzz throughout. In the first G02 verification run, `FuzzRedactString`
failed after 10 seconds; longer runs then found two more inputs. Claude fixed
all three in `bb8095f`. Independently, GitHub's CI on `4e29c5d` failed on a
fourth input of the same family; Astra kept it, backported `bb8095f`'s
redaction code unchanged to G01 and added the same minimization limit
(`539d5d3`). All four broke **idempotence only**: the first pass hid the
value, a second pass hid more of the surrounding text. **No input disclosed
anything**: run on the code at `4e29c5d`, the generated tests below find 432,
486 and 324 idempotence failures and no leak, no broken JSON
(`generated-families-at-4e29c5d.log`).

| Input (kept in `testdata`) | Shape | Since |
| --- | --- | --- |
| `8e01a429a99efb2e` | `"\"\"CredentiAl:0"0`: the key=value rule hid `0` with a bare `[REDACTED]`; the structural pass then read that marker as an array whose end, at a string end in broken quoting, it could not trust, and stretched it to the end of the text | `3c9a057` (the T01 fix); passes at `11a5f04` |
| `04952a76895d42bc` | `"CredentiAl:""\bCredentiA":00`: the key=value rule replaced the quoted value `""` with its quotes, joining the strings around it into one whose text reads as a sensitive name | `23861f6` (G01 follow-up); passes at `f6a792b` |
| `1db91fde4b2f65bd` | `"CredentiAl:0\":0`: the unquoted value `0\` lost its backslash, which unescaped the quote after it, with the same effect | `23861f6`; passes at `f6a792b` |
| `920830b90e0a0575` (GitHub's CI, kept by Astra) | `0"token:"""":0`: as `04952a76895d42bc`; at `4e29c5d` one pass gives `0"token:[REDACTED]":0`, a second hides the `0` too; with the fix both give `0"token:"[REDACTED]"":0` | `23861f6`; passes at `f6a792b` |

The fix (`bb8095f`, now in `539d5d3`):

- A bare marker after an unquoted name is left as it is by the structural
  pass.
- The key=value rule keeps a double-quoted value's quotes
  (`password="[REDACTED]"`; an unclosed value keeps its opening quote) and an
  unquoted value's trailing backslashes, so the text's quotes pair up as
  before. **Visible change:** quoted values in key=value text now keep their
  quotes; ADR 0007 already said this of JSON-like text.
- `RedactString` repeats redaction until the text redacts to itself (at most
  four passes, then the whole text is replaced), so it is idempotent by
  construction. Text without secrets still takes one pass; the second pass
  only confirms in every case known. **Visible change:** a text that
  redaction makes longer than 8 MiB is replaced as a whole, as an 8 MiB text
  given directly already was.

Tests: three generated families (5,184, 2,592 and 864 cases) check that a
single pass already settles, so the rules do not lean on the repetition, and
that no value shows; `TestPairMarker`; `TestSettle`. Disabled, each fix fails
its tests (without the marker rule 432 cases fail, without quoted markers
486, without the backslashes 324). Astra's G01 fixtures pass unchanged.
Extended fuzzing on `bb8095f`, whose redaction code `539d5d3` holds byte for
byte: `FuzzRedactString` 3,464,187 executions and `FuzzRedactConfidential`
328,288 in four minutes each, both clean
(`logging-fuzz-extended-3-final.log`).

Astra's `539d5d3`, checked in Claude's workspace as GitHub's CI would run
it (`cifix/`): `make ci-local` and `make fuzz` (13 targets) pass with Go 1.27.2 and with Go 1.24.7; lint, vulnerabilities (source and tarball binary), secrets, licences, Buf and ShellCheck pass; `make install-test` 20 of 20; GitHub's run #3 also passed the live systemd install test.

## Decisions for akash

| # | Question | Claude's recommendation | Where it is recorded |
| --- | --- | --- | --- |
| 1 | Where the rig gets its engine images (open since the development plan) | Docker Hub's official images; the names are settings, so a mirror or loaded tarballs work too | `test/rig/README.md` |
| 2 | Go language level 1.27 (was 1.24) | Done as ADR 0002 planned: the workspace reaches the module proxy, and etcd 3.7 and opensearch-go 4.8 need Go 1.26 or later | ADR 0002 |
| 3 | Real-engine tests point at a running engine instead of starting it through Testcontainers (row T19) | Accept the deviation: the same suite runs against Docker, tarballs and the 3-node rig | ADR 0011 |
| 4 | TraceStore block format | Keep Parquet (row T7): about four times smaller on disk; reads are slower but well within interactive needs | ADR 0011 and the comparison below |
| 5 | CI runner image and action versions | Decided by akash on 22 October: pin `ubuntu-24.04` ("Pin ubuntu-24.04") and move the actions to their Node.js 24 versions in G02 ("Add to G02 now"); in `10283a1` | `.github/workflows/ci.yml` |

## Verification in Claude's workspace

A cloud Linux container (Ubuntu 24.04.5, kernel 6.18, amd64, 2 vCPUs),
Go 1.27.2, the engines started by `test/rig/engines-tarball.sh`: Cassandra
5.0.9 on OpenJDK 17.0.20.1 with PasswordAuthenticator, OpenSearch 3.9.0 on
its bundled JDK (25.0.4.1) with its security plugin and HTTPS. Not akash's
machine, not a VM, not native Windows, not Docker. Everything below ran at
`5d6e79b`, the last code commit, with `OBSERVEX_REQUIRE_ENGINES=1`, so no
engine test could skip. The workspace restarted during this round and
stopped the engines; a first `make test-engines` before they were started
again failed to connect to either
(`test-engines-engines-stopped.log`), and the run below followed it.
`10283a1`, after `5d6e79b`, changes only `.github/workflows/ci.yml`; its own
build, vet and tests with both engines pass (`per-commit-checks.log`), and
actionlint finds no problem in the workflow (`actionlint-ci.log`).

| Check | Result |
| --- | --- |
| `make test-engines` | Pass: the six store packages with tests, with `-race`, against both engines (`test-engines.log`) |
| `make ci-local` | Pass: gofmt, vet, build, race, coverage, ShellCheck (`ci-local.log`) |
| Race suite, `go test -count=1 -race ./...` | 263 tests pass and 1 skips by design (`TestCrashHelper`, the crash test's child entry point); 16 fuzz seed suites and 646 subtests pass; none fail (`race-tests-summary.txt`) |
| Coverage, `make cover` | 90.5% (`coverage-by-package.md`; G01 ended at 92.1%) |
| Astra's 15 G01 regression tests and 2 probes, unmodified, through `go test -overlay` | All pass: 17 tests, 94 subcases (`qa-regressions.log`) |
| `make fuzz FUZZTIME=30s` (16 targets, input minimization limited to 1 s) | All 16 pass (`fuzz-all.log`) |
| `make lint`; `GOOS=windows golangci-lint run ./...` | 0 issues; 0 issues |
| `make vuln` | No vulnerability in code the node calls or packages it imports; one module-level advisory, GO-2026-5932 (`golang.org/x/crypto/openpgp`, unmaintained, no fix), in a package nothing imports (`govulncheck-source-verbose.log`) |
| `make secrets` | gitleaks 8.30.1: no leaks (51 commits: the workspace repository also holds the earlier branches, more than the 38 of this history); a clone of the bundle, holding only this history, at the handoff commit: `gate-secrets-final.log` |
| `make licenses proto-lint shell-check` | Pass: every licence allowed (go-licenses notes it cannot read assembly files for imports, as before); Buf lint and format; ShellCheck |
| SearchStore over plain HTTP without the security plugin (the CI setup) | Pass (`opensearch-plain-http.log`) |
| Engine downloads | Cassandra: SHA-256 and signature by key `7464 AAD9 0682 41C5 0BA6 A262 32F3 5CB2 F546 D93E` (in Cassandra's KEYS); OpenSearch: SHA-512 and signature by the OpenSearch release key `A8B2 D9E0 4CD5 1FEF 6AA2 DB53 BA81 D999 8119 1457` |
| Windows | `GOOS=windows go vet ./...` and `go test -c` for every package compile; **not run natively** |

Coverage by package:

| Package | Coverage |
| --- | --- |
| cmd/observex-node | 81.2% |
| internal/node | 85.1% |
| internal/node/firewall | 97.0% |
| internal/node/frontdoor | 97.9% |
| internal/node/pki | 77.6% |
| internal/node/selfmon | 97.4% |
| internal/node/supervisor | 97.9% |
| internal/platform/clock | 100.0% |
| internal/platform/config | 96.7% |
| internal/platform/logging | 92.2% |
| internal/platform/tlsx | 93.1% |
| internal/platform/tlsx/tlstest | 86.0% |
| internal/store | 100.0% |
| internal/store/cassandra | 90.0% |
| internal/store/enginetest | 55.6% |
| internal/store/etcdstore | 92.6% |
| internal/store/fake | 97.1% |
| internal/store/opensearch | 83.6% |
| internal/store/storetest | 89.1% |
| internal/store/tracestore | 86.2% |
| **all** | **90.5%** |

Fuzz executions in 30 s (a fuzz run finds inputs; it does not prove all
inputs safe):

| Target | Package | Executions | Result |
| --- | --- | --- | --- |
| `FuzzRedactString` | platform/logging | 364,477 | Pass |
| `FuzzRedactConfidential` | platform/logging | 42,824 | Pass |
| `FuzzSensitiveShapes` | platform/logging | 1,858 | Pass |
| `FuzzPairsMatchExpression` | platform/logging | 295,177 | Pass |
| `FuzzDecode` | platform/config | 733,662 | Pass |
| `FuzzVerifyToken` | platform/tlsx | 433,670 | Pass |
| `FuzzParseTraceID` | store | 1,016,145 | Pass |
| `FuzzParse` | node | 170,524 | Pass |
| `FuzzParseFeatures` | node/frontdoor | 263,010 | Pass |
| `FuzzCheck` | node/firewall | 514,106 | Pass |
| `FuzzParseStat` | node/selfmon | 318,443 | Pass |
| `FuzzWriteText` | node/selfmon | 220,025 | Pass |
| `FuzzPrefixWriter` | node/supervisor | 110,017 | Pass |
| `FuzzWALRecords` | store/tracestore | 179,889 | Pass |
| `FuzzBlockIndex` | store/tracestore | 123,650 | Pass |
| `FuzzBlockReader` | store/tracestore | 6,061 | Pass |

The redaction targets ran fewer executions than in the G01 boundaries II
run (`FuzzRedactString` 364,477 against 450,838); every redaction now ends
with a confirming second pass.

### TraceStore formats compared

100,000 spans (12,500 traces of 8 spans over 6 services, 5 or 6 attributes
each). Disk size and block write: one block of all of them; the reads: a
store holding them in four blocks of 25,000. Three runs each
(`tracestore-bench.log`):

| Measure (median of three runs) | Parquet | Segment |
| --- | --- | --- |
| Disk per span | 69.5 bytes | 271.1 bytes |
| Block write | 268,102 spans/s | 440,878 spans/s |
| `GetTrace`, present (3,000 lookups) | 491.0 µs | 27.4 µs |
| `GetTrace`, absent (3,000 lookups) | 1.1 µs | 688 ns |
| `FindTraces`, 6,000 candidates, limit 100 | 456.3 ms | 199.8 ms |
| `Open`, 4 blocks | 4.4 ms | 3.0 ms |
| `WriteSpans`, 100 spans per call, each synced | 97,418 spans/s (Parquet store) | |

## Validation steps for Astra

### 1. Apply the bundle (PowerShell)

```powershell
cd C:\Users\91832\Documents\observex_managed
powershell -ExecutionPolicy Bypass -File .\_handoff\G02\apply-G02.ps1
```

The script checks the bundle's SHA-256, that the repository is clean, on
`main` and at `e282263`, `f15eb8b`, `539d5d3`, `4e29c5d` or an earlier
handoff commit, fast-forwards `main` and stops. It pushes only with
`-Push`, after checking that GitHub's `main` is part of the history, and
never forces. In a detached review checkout: `git fetch <bundle> main`, then
`git checkout --detach FETCH_HEAD`.

### 2. Verify every file (WSL2)

```sh
sha256sum -c docs/handoff/G02/files-g02.sha256      # every line OK
```

The earlier `files-*.sha256` lists in `docs/handoff/G01` describe their own
commits; files changed since (this round adds a pointer to `BOUNDARIES-II.md`)
no longer match them.

### 3. Native Windows (PowerShell, Go 1.27)

```powershell
go vet ./...
go build ./...
go test -count=1 ./...
```

Expected: everything passes; the Cassandra and OpenSearch engine tests skip
(no engine variables), as does `TestCrashHelper`, the crash test's child
entry point. This is the first native Windows run of etcd and the
TraceStore, including the crash test with TerminateProcess; report any
failure as found.

### 4. WSL2 (Ubuntu, Go 1.27)

```sh
sudo apt-get install -y nginx-core
make ci-local
make fuzz FUZZTIME=30s                   # 16 targets
```

### 5. Real engines in Docker: the G02 acceptance test (WSL2 with Docker)

```sh
export OPENSEARCH_INITIAL_ADMIN_PASSWORD='<8+ characters: upper, lower, digit, symbol>'
docker compose -f test/rig/compose.yaml up -d
docker compose -f test/rig/compose.yaml ps            # wait for cassandra: healthy
docker compose -f test/rig/compose.yaml cp opensearch:/usr/share/opensearch/config/root-ca.pem /tmp/observex-os-ca.pem
export OBSERVEX_TEST_CASSANDRA=127.0.0.1:9042
export OBSERVEX_TEST_OPENSEARCH=https://127.0.0.1:9200
export OBSERVEX_TEST_OPENSEARCH_CA=/tmp/observex-os-ca.pem
export OBSERVEX_TEST_OPENSEARCH_USERNAME=admin
export OBSERVEX_TEST_OPENSEARCH_PASSWORD="$OPENSEARCH_INITIAL_ADMIN_PASSWORD"
make test-engines
docker compose -f test/rig/compose.yaml down -v
```

Expected: every store package passes, with no skips. Images come from
Docker Hub unless `CASSANDRA_IMAGE` and `OPENSEARCH_IMAGE` say otherwise
(decision 1). Without Docker, `test/rig/engines-tarball.sh` does the same
from verified tarballs (`test/rig/README.md`).

### 6. G01 fixtures again (PowerShell)

`539d5d3` changes G01's redaction, so rerun `run-regressions.ps1`,
`run-repair-boundaries.ps1` and `run-boundaries-regressions.ps1` with your
fixtures unchanged, and replay the four new inputs:
`go test -count=1 -run '^FuzzRedactString/' -v ./internal/platform/logging`.

### 7. Gates (WSL2)

```sh
make tools
make lint vuln secrets licenses proto-lint shell-check
GOOS=windows golangci-lint run ./...
```

### 8. Benchmarks (optional)

```sh
go test -run '^$' -bench . -benchtime 5x ./internal/store/tracestore
```

## Known limits

1. No native Windows run, no Docker run, and no run on akash's machine in
   Claude's workspace; the engines ran from tarballs in a container.
2. No TLS between etcd members or to Cassandra yet (G03 and G06); OpenSearch
   HTTPS is supported and tested.
3. The quorum-loss test runs three members in one process on loopback; the
   3-node test on separate machines belongs to G07's rig.
4. Engine failures in the middle of a Cassandra or OpenSearch write leave a
   partial write that a retry completes; the contract's all-or-nothing
   covers invalid input. The TraceStore and etcd are all-or-nothing.
5. TraceStore: one copy per node, no retention or compaction yet, and
   `FindTraces` cost grows with the candidate traces (ADR 0011).
6. Adapter-specific limits beyond the fakes (valid UTF-8; times from 1678
   or 1970 to 2262; ID and value sizes) are listed in each package's README.
7. The crash test kills the process; it does not cut power.
8. CI stays on Ubuntu 24.04 (NGINX 1.24, OpenSSL 3.0). Ubuntu 26, whose
   OpenSSL could cover the post-quantum TLS tests, is a later step of its
   own. `10283a1` is checked by actionlint and against each action's
   metadata; only GitHub's run on the push exercises it.

## Rollback

G02 is not pushed. On akash's PC, `git reset --hard e282263` returns `main`
to where it and GitHub are today, while nothing new has been committed
there. The rig leaves nothing behind after `docker compose ... down -v` or
`engines-tarball.sh stop` and removing its directory.
