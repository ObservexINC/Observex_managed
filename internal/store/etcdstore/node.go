// Package etcdstore is the ConfigurationStore (technology row T8, ADR 0004):
// an etcd member embedded in the node process (Node) and a store.ConfigStore
// over it (Store).
//
// Every node runs one member; three members make a cluster that keeps working
// while one is lost and stops accepting reads and writes, rather than serving
// stale or split data, when two are lost. Until cluster membership and member
// TLS arrive in G03, members talk plain HTTP and Config accepts loopback
// addresses only.
package etcdstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
	"go.etcd.io/etcd/server/v3/etcdserver/api/v3client"
	"go.uber.org/zap"

	"github.com/ObservexINC/Observex_managed/internal/node/selfmon"
	"github.com/ObservexINC/Observex_managed/internal/store"
)

// Member names one member of the cluster and the URL its peers reach it on.
type Member struct {
	Name    string
	PeerURL string
}

// Config describes the embedded member.
type Config struct {
	// Name is the member's name, unique in the cluster: letters, digits,
	// dots, dashes and underscores.
	Name string
	// Dir is the data directory. It is created with mode 0700. A directory
	// that already holds a member is reopened and Cluster is ignored, as etcd
	// does on restart.
	Dir string
	// ClientURL and PeerURL are where the member listens, for example
	// http://127.0.0.1:2379 and http://127.0.0.1:2380. Loopback only until
	// G03.
	ClientURL string
	PeerURL   string
	// Cluster lists every member, this one included, when a cluster is first
	// formed. Empty means a cluster of this member alone.
	Cluster []Member
	// ClusterToken keeps members of different clusters apart. Empty means
	// "observex".
	ClusterToken string
	// Logger receives etcd's own log records at LogLevel and above. Nil
	// discards them.
	Logger   *slog.Logger
	LogLevel slog.Level
	// TickMs and ElectionMs are Raft's heartbeat interval and election
	// timeout. Zero means etcd's defaults (100 ms and 1000 ms).
	TickMs     uint
	ElectionMs uint
}

var memberNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// loopbackURL parses an http URL whose host is a loopback address.
func loopbackURL(what, raw string) (url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return url.URL{}, store.Invalid("%s %q is not a URL", what, raw)
	}
	if u.Scheme != "http" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return url.URL{}, store.Invalid("%s %q must be http://host:port with no path, query or user", what, raw)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || port == "" || port == "0" {
		return url.URL{}, store.Invalid("%s %q needs an explicit port", what, raw)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return url.URL{}, store.Invalid("%s %q is not a loopback address; members use plain HTTP until member TLS arrives in G03", what, raw)
	}
	return *u, nil
}

func (c Config) validate() (client, peer url.URL, initial string, err error) {
	if !memberNameRE.MatchString(c.Name) {
		return client, peer, "", store.Invalid("member name %q must be 1 to 63 letters, digits, dots, dashes or underscores", c.Name)
	}
	if c.Dir == "" {
		return client, peer, "", store.Invalid("member %s needs a data directory", c.Name)
	}
	if client, err = loopbackURL("client URL", c.ClientURL); err != nil {
		return client, peer, "", err
	}
	if peer, err = loopbackURL("peer URL", c.PeerURL); err != nil {
		return client, peer, "", err
	}
	members := c.Cluster
	if len(members) == 0 {
		members = []Member{{Name: c.Name, PeerURL: c.PeerURL}}
	}
	seen := map[string]bool{}
	self := false
	parts := make([]string, 0, len(members))
	for _, m := range members {
		if !memberNameRE.MatchString(m.Name) || seen[m.Name] {
			return client, peer, "", store.Invalid("cluster member name %q is not valid or appears twice", m.Name)
		}
		seen[m.Name] = true
		if _, err := loopbackURL("peer URL of "+m.Name, m.PeerURL); err != nil {
			return client, peer, "", err
		}
		if m.Name == c.Name {
			if m.PeerURL != c.PeerURL {
				return client, peer, "", store.Invalid("cluster lists %s at %s, but its peer URL is %s", m.Name, m.PeerURL, c.PeerURL)
			}
			self = true
		}
		parts = append(parts, m.Name+"="+m.PeerURL)
	}
	if !self {
		return client, peer, "", store.Invalid("cluster does not list this member (%s)", c.Name)
	}
	sort.Strings(parts)
	return client, peer, strings.Join(parts, ","), nil
}

// Node is a running embedded etcd member.
type Node struct {
	name   string
	etcd   *embed.Etcd
	client *clientv3.Client

	mu     sync.Mutex
	closed bool
}

// Start starts the member and waits until it has joined its cluster and can
// serve requests, or until ctx ends. A member of a new three-member cluster is
// ready only once a second member is up, since it needs a quorum.
func Start(ctx context.Context, c Config) (*Node, error) {
	client, peer, initial, err := c.validate()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("etcdstore: data directory: %w", err)
	}
	// A directory that already existed may be wider than etcd wants; the data
	// directory must be owner-only (it holds every configuration value).
	if err := os.Chmod(c.Dir, 0o700); err != nil { //nolint:gosec // G302: a directory needs the execute bit; 0700 is owner-only
		return nil, fmt.Errorf("etcdstore: data directory: %w", err)
	}
	cfg := embed.NewConfig()
	cfg.Name = c.Name
	cfg.Dir = c.Dir
	cfg.ListenClientUrls = []url.URL{client}
	cfg.AdvertiseClientUrls = []url.URL{client}
	cfg.ListenPeerUrls = []url.URL{peer}
	cfg.AdvertisePeerUrls = []url.URL{peer}
	cfg.InitialCluster = initial
	cfg.InitialClusterToken = c.ClusterToken
	if cfg.InitialClusterToken == "" {
		cfg.InitialClusterToken = "observex"
	}
	cfg.ClusterState = embed.ClusterStateFlagNew // ignored when Dir already holds a member
	if c.TickMs > 0 {
		cfg.TickMs = c.TickMs
	}
	if c.ElectionMs > 0 {
		cfg.ElectionMs = c.ElectionMs
	}
	// Old revisions are kept for an hour, then compacted, so the database
	// does not grow with every change ever made.
	cfg.AutoCompactionMode = "periodic"
	cfg.AutoCompactionRetention = "1h"
	cfg.Logger = "zap"
	cfg.ZapLoggerBuilder = embed.NewZapLoggerBuilder(zap.New(newSlogCore(c.Logger, c.LogLevel, c.Name)))

	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return nil, fmt.Errorf("etcdstore: start member %s: %w", c.Name, err)
	}
	select {
	case <-e.Server.ReadyNotify():
	case err := <-e.Err():
		e.Close()
		return nil, fmt.Errorf("etcdstore: member %s stopped while starting: %w", c.Name, err)
	case <-ctx.Done():
		e.Server.Stop()
		e.Close()
		return nil, fmt.Errorf("etcdstore: member %s not ready: %w", c.Name, ctx.Err())
	}
	return &Node{name: c.Name, etcd: e, client: v3client.New(e.Server)}, nil
}

// Store returns a ConfigStore over this member. Keys are stored under prefix,
// so stores with different prefixes never see each other's keys. Closing the
// store does not stop the member.
func (n *Node) Store(prefix string) *Store {
	return newStore(n.client, prefix, nil)
}

// Close stops the member. Stores over it fail from then on.
func (n *Node) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	err := n.client.Close()
	n.etcd.Close()
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

// Status is a member's view of its cluster.
type Status struct {
	Name      string
	Members   int
	HasLeader bool
	IsLeader  bool
	DBBytes   int64
}

// Status reports the member's view of the cluster.
func (n *Node) Status() Status {
	s := n.etcd.Server
	lead := s.Leader()
	return Status{
		Name:      n.name,
		Members:   len(s.Cluster().Members()),
		HasLeader: lead != 0,
		IsLeader:  lead != 0 && lead == s.MemberID(),
		DBBytes:   s.Backend().Size(),
	}
}

// Name implements selfmon.Collector.
func (n *Node) Name() string { return "configstore" }

// Collect implements selfmon.Collector.
func (n *Node) Collect(b *selfmon.Batch) {
	n.mu.Lock()
	closed := n.closed
	n.mu.Unlock()
	if closed {
		b.Gauge("observex_configstore_up", "1 while the embedded etcd member runs.", 0)
		return
	}
	st := n.Status()
	b.Gauge("observex_configstore_up", "1 while the embedded etcd member runs.", 1)
	b.Gauge("observex_configstore_has_leader", "1 while the member sees a cluster leader; 0 means no quorum.", boolGauge(st.HasLeader))
	b.Gauge("observex_configstore_is_leader", "1 while this member is the cluster leader.", boolGauge(st.IsLeader))
	b.Gauge("observex_configstore_members", "Members in the cluster, as this member sees it.", float64(st.Members))
	b.Gauge("observex_configstore_db_bytes", "Size of the member's database file.", float64(st.DBBytes))
}

func boolGauge(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
