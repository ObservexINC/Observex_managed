# G02 test manifest

Code commit: `5d6e79b`, on the G01 CI repair `e282263`; `10283a1` after it
changes only the CI workflow. Results are in [HANDOFF.md](HANDOFF.md); this
file says what each new test shows. Every store runs `storetest`, the
contract suite its fake in `internal/store/fake` also passes.

## ConfigurationStore: `internal/store/etcdstore` (embedded etcd 3.7.2)

| Test | Shows |
| --- | --- |
| `TestContractSharedMemberPrefixPerSubtest`, `TestContractFreshMemberPerSubtest`, `TestContractOverTheNetwork` | The contract suite on one shared member, on a fresh member per case, and through a network client |
| `TestPrefixesKeepStoresApart` | Two stores on one member never see each other's keys |
| `TestDataSurvivesRestart` | Values written before a member stops are there after it starts again |
| `TestLargeValueIsInvalid` | A 2 MiB value is refused as invalid input |
| `TestQuorumLoss` | Three members; with two stopped, the third refuses reads and writes instead of serving stale or split data; with them back, nothing committed is lost |
| `TestNewClusterWaitsForQuorum` | A member of a new cluster does not report ready before quorum |
| `TestConfigValidation`, `TestSelfMonitoring`, `TestEtcdLogsGoThroughTheNodeLogger` | Settings checks; the self-monitoring metrics; etcd's logs pass through the redacting handler |

## TraceStore v0: `internal/store/tracestore`

| Test | Shows |
| --- | --- |
| `TestContract` | The contract suite six ways: Parquet and segment blocks, each with data left in the head, flushed to blocks after every write, or reopened after every write |
| `TestMatchesFakeAcrossHeadsAndBlocks` | Random writes and queries give the fake's answers while data moves from log to heads to blocks |
| `TestCrashRecovery` | A writer process (`TestCrashHelper`, which skips in normal runs) killed at random moments, ten rounds per format: every acknowledged write survives, the write in flight is whole or absent, nothing else appears |
| `TestTornLogTailIsCut`, `TestDamagedLogRecordKeepsWhatCameBefore` | Recovery cuts a torn or damaged log record and keeps every record before it |
| `TestUnfinishedBlockIsRemovedAndLogReplayed`, `TestBlockAndLogBothPresent` | A block left half-written is removed and its spans replayed from the log; a finished block and its log are not counted twice |
| `TestDamagedBlockFailsOpenWithoutPanic` | A damaged block index makes `Open` fail with a corruption error, in both formats |
| `TestWritesRefusedWhileFlushesFail`, `TestBackgroundFlushByAge` | Backpressure refuses writes only while flushing fails; heads flush on age as well as size |
| `TestInvalidInput`, `TestExtremeTimesRoundTrip`, `TestSelfMonitoring`, `TestBenchmarkDataIsSane` | Input checks; times at the representable limits; metrics; the benchmark data set |
| `FuzzWALRecords`, `FuzzBlockIndex`, `FuzzBlockReader` | Arbitrary log, index and block bytes give errors, never panics or wrong data |

## MetricStore: `internal/store/cassandra` (Cassandra 5.0)

| Test | Shows |
| --- | --- |
| `TestContract`, `TestMatchesFake` | The contract suite on the engine; random writes and queries match the fake |
| `TestLargeLabelsAndBatches` | 2,000 points of a series with a 30,000-byte label: writes split into batches under Cassandra's limit and read back whole |
| `TestExtremeTimesAndPrecision`, `TestDays` | Nanosecond times from 1678 to 2262 round-trip exactly; day buckets for negative and extreme times; stable series shards |
| `TestConcurrentWriters`, `TestCancelledQuery` | Eight concurrent writers of one metric; a query with a cancelled context returns the context's error |
| `TestConfigValidation`, `TestSelfMonitoring`, `TestPasswordNeverLogged` | Settings checks; metrics; the password never reaches a log |

## SearchStore: `internal/store/opensearch` (OpenSearch 3)

| Test | Shows |
| --- | --- |
| `TestContract`, `TestMatchesFake` | The contract suite on the engine; random documents and queries match the fake |
| `TestLongBodies`, `TestChunks` | Substring search across chunk borders, including a term longer than the chunks' overlap; chunks stay valid UTF-8 and within size |
| `TestPostFilterKeepsPaging` | 1,200 decoys that match a long term's first part but not the term: the store pages past them to the real hit |
| `TestUnusualIDsAndNames`, `TestIndexNames`, `TestTimesAndInvalidInput` | 5,000-byte, Unicode and punctuated IDs and index names work and map to distinct valid engine names; nanosecond times at the limits; invalid input |
| `TestConcurrentFirstWrites`, `TestConfigValidation`, `TestSelfMonitoring`, `TestPasswordNeverLogged` | Six writers creating one index at once; settings; metrics; the password never reaches a log |

The Cassandra and OpenSearch tests skip without their engine variables and
fail without them when `OBSERVEX_REQUIRE_ENGINES=1` (`test/rig/README.md`).

## Redaction (G01 code, changed in `539d5d3`, from G02's first branch)

| Test | Shows |
| --- | --- |
| `TestTextRuleMarkersAtStringEnds` (5,184 cases), `TestPairValuesKeepQuoteStructure` (2,592), `TestPairValuesEndingInBackslashes` (864) | The shapes fuzzing found: no value shows, and one pass already settles |
| `TestPairMarker`, `TestSettle` | The key=value marker keeps the value's quotes and trailing backslashes; redaction repeats at most four passes, then replaces the whole text |
| `FuzzRedactString` seeds `8e01a429a99efb2e`, `04952a76895d42bc`, `1db91fde4b2f65bd`, `920830b90e0a0575` | The three inputs G02's fuzzing found and the one GitHub's CI found, replayed on every `go test` |
