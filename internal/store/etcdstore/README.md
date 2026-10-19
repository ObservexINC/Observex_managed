# etcdstore: the ConfigurationStore

The ConfigurationStore (technology row T8, ADR 0004, ADR 0011): an etcd 3.7
member embedded in the node process, and a `store.ConfigStore` over it.

## What it does

- `Start(ctx, Config)` starts a member and returns when it can serve, which
  for a new three-member cluster means once a second member is up.
- `Node.Store(prefix)` returns a ConfigStore over the member, in process (no
  network hop). Each store keeps its keys under its prefix.
- `New(client, prefix)` returns a ConfigStore over any etcd client, for
  example from another process.
- `Node.Status()` and the `selfmon.Collector` methods report whether the
  member runs, sees a leader, is the leader, how many members it sees, and the
  size of its database file.

The store implements the whole ConfigStore contract with etcd transactions:
create-only puts compare the key's create revision with 0, conditional puts
and deletes compare its modification revision, and a delete that fails tells
"missing" from "changed" by reading the key in the same transaction.
Revisions are etcd's, so they rise across the whole cluster and across
stores; a store sees gaps where other stores wrote.

## How to run it

```go
n, err := etcdstore.Start(ctx, etcdstore.Config{
	Name:      "node-1",
	Dir:       "/var/lib/observex/config",
	ClientURL: "http://127.0.0.1:2379",
	PeerURL:   "http://127.0.0.1:2380",
	Cluster: []etcdstore.Member{
		{Name: "node-1", PeerURL: "http://127.0.0.1:2380"},
		{Name: "node-2", PeerURL: "http://127.0.0.1:2480"},
		{Name: "node-3", PeerURL: "http://127.0.0.1:2580"},
	},
	Logger: logger, LogLevel: slog.LevelWarn,
})
cfg := n.Store("config/")
```

Tests: `go test -race ./internal/store/etcdstore` runs the contract suite three
ways (one member with a prefix per subtest, a fresh member per subtest, and a
network client), a restart test, and the quorum-loss test on three members.

## Configuration

| Field | Meaning |
| --- | --- |
| `Name` | Member name, unique in the cluster |
| `Dir` | Data directory, created owner-only (0700); a directory that already holds a member is reopened and `Cluster` is ignored |
| `ClientURL`, `PeerURL` | Listen addresses; **loopback only** until member TLS arrives in G03 |
| `Cluster` | Every member when the cluster is first formed; empty means this member alone |
| `ClusterToken` | Keeps clusters apart; default `observex` |
| `Logger`, `LogLevel` | etcd's own log records, sent through the given slog logger (and so through the redacting handler) at this level and above |
| `TickMs`, `ElectionMs` | Raft timings; default 100 ms and 1000 ms |

Old revisions are compacted after one hour.

## Limits

- No TLS and no authentication between members or clients yet: addresses
  must be loopback (G03 adds member TLS with the cluster's CA).
- Without a quorum, reads and writes fail when their context ends; there are
  no stale reads. The contract has no "unavailable" error, so callers see a
  wrapped context or etcd error.
- A write that times out while the cluster loses its quorum can still be
  applied later, once a quorum returns; callers that retry should use the
  revision checks.
- Values up to etcd's request limit (1.5 MiB by default); larger is
  `ErrInvalid`. Large items (capsules, packs) belong elsewhere (row T8).
- Membership changes (adding or removing members of a running cluster) are
  G03 work.
