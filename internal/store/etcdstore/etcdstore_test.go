package etcdstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/ObservexINC/Observex_managed/internal/node/selfmon"
	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
	"github.com/ObservexINC/Observex_managed/internal/store"
	"github.com/ObservexINC/Observex_managed/internal/store/storetest"
)

// freePorts returns n loopback ports that were free a moment ago.
func freePorts(t *testing.T, n int) []int {
	t.Helper()
	ports := make([]int, 0, n)
	var ls []net.Listener
	var lc net.ListenConfig
	for i := 0; i < n; i++ {
		l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("free port: %v", err)
		}
		ls = append(ls, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	for _, l := range ls {
		_ = l.Close()
	}
	return ports
}

func memberConfig(t *testing.T, dir, name string, client, peer int) Config {
	t.Helper()
	return Config{
		Name:       name,
		Dir:        filepath.Join(dir, name),
		ClientURL:  fmt.Sprintf("http://127.0.0.1:%d", client),
		PeerURL:    fmt.Sprintf("http://127.0.0.1:%d", peer),
		TickMs:     50,
		ElectionMs: 500,
	}
}

func startCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// startOne starts a single-member cluster that is closed when the test ends.
func startOne(t *testing.T) *Node {
	t.Helper()
	p := freePorts(t, 2)
	n, err := Start(startCtx(t), memberConfig(t, t.TempDir(), "m1", p[0], p[1]))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = n.Close() })
	return n
}

func TestContractSharedMemberPrefixPerSubtest(t *testing.T) {
	n := startOne(t)
	var i atomic.Int64
	storetest.ConfigStore(t, func(t *testing.T) store.ConfigStore {
		s := n.Store(fmt.Sprintf("contract/%d/", i.Add(1)))
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}

func TestContractFreshMemberPerSubtest(t *testing.T) {
	storetest.ConfigStore(t, func(t *testing.T) store.ConfigStore {
		s := startOne(t).Store("")
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}

func TestContractOverTheNetwork(t *testing.T) {
	p := freePorts(t, 2)
	n, err := Start(startCtx(t), memberConfig(t, t.TempDir(), "m1", p[0], p[1]))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = n.Close() })
	var i atomic.Int64
	storetest.ConfigStore(t, func(t *testing.T) store.ConfigStore {
		c, err := clientv3.New(clientv3.Config{Endpoints: []string{fmt.Sprintf("http://127.0.0.1:%d", p[0])}, DialTimeout: 10 * time.Second})
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		s := New(c, fmt.Sprintf("net/%d/", i.Add(1)))
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}

func TestPrefixesKeepStoresApart(t *testing.T) {
	n := startOne(t)
	a, b := n.Store("a/"), n.Store("b/")
	ctx := startCtx(t)
	if _, err := a.Put(ctx, "k", []byte("from a"), store.MustNotExist); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(ctx, "k"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("store b sees store a's key: %v", err)
	}
	if _, err := b.Put(ctx, "k", []byte("from b"), store.MustNotExist); err != nil {
		t.Fatalf("store b cannot create its own k: %v", err)
	}
	all, err := n.Store("").List(ctx, "")
	if err != nil || len(all) != 2 || all[0].Key != "a/k" || all[1].Key != "b/k" {
		t.Fatalf("unprefixed list = %+v, %v", all, err)
	}
	got, err := a.List(ctx, "")
	if err != nil || len(got) != 1 || got[0].Key != "k" || string(got[0].Value) != "from a" {
		t.Fatalf("store a lists %+v, %v", got, err)
	}
}

func TestDataSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	p := freePorts(t, 2)
	cfg := memberConfig(t, dir, "m1", p[0], p[1])
	n, err := Start(startCtx(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := n.Store("").Put(startCtx(t), "users/akash", []byte("owner"), store.MustNotExist)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	n, err = Start(startCtx(t), cfg)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer func() { _ = n.Close() }()
	kv, err := n.Store("").Get(startCtx(t), "users/akash")
	if err != nil || string(kv.Value) != "owner" || kv.Revision != rev {
		t.Fatalf("after restart: %+v, %v (want revision %d)", kv, err, rev)
	}
}

func TestLargeValueIsInvalid(t *testing.T) {
	s := startOne(t).Store("")
	_, err := s.Put(startCtx(t), "big", bytes.Repeat([]byte("x"), 2<<20), store.AnyRevision)
	if !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("2 MiB value: err = %v, want ErrInvalid", err)
	}
}

func TestConfigValidation(t *testing.T) {
	good := Config{Name: "m1", Dir: t.TempDir(), ClientURL: "http://127.0.0.1:2379", PeerURL: "http://127.0.0.1:2380"}
	cases := map[string]func(c *Config){
		"empty name":            func(c *Config) { c.Name = "" },
		"name with a slash":     func(c *Config) { c.Name = "a/b" },
		"no data directory":     func(c *Config) { c.Dir = "" },
		"public client address": func(c *Config) { c.ClientURL = "http://10.0.0.5:2379" },
		"public peer address":   func(c *Config) { c.PeerURL = "http://0.0.0.0:2380" },
		"https before G03":      func(c *Config) { c.ClientURL = "https://127.0.0.1:2379" },
		"no port":               func(c *Config) { c.PeerURL = "http://127.0.0.1" },
		"port zero":             func(c *Config) { c.PeerURL = "http://127.0.0.1:0" },
		"a path":                func(c *Config) { c.ClientURL = "http://127.0.0.1:2379/x" },
		"user in URL":           func(c *Config) { c.ClientURL = "http://u:p@127.0.0.1:2379" },
		"cluster without self":  func(c *Config) { c.Cluster = []Member{{Name: "m2", PeerURL: "http://127.0.0.1:2480"}} },
		"self at another URL":   func(c *Config) { c.Cluster = []Member{{Name: "m1", PeerURL: "http://127.0.0.1:9999"}} },
		"duplicate member": func(c *Config) {
			c.Cluster = []Member{{Name: "m1", PeerURL: c.PeerURL}, {Name: "m1", PeerURL: c.PeerURL}}
		},
		"public peer of another member": func(c *Config) {
			c.Cluster = []Member{{Name: "m1", PeerURL: c.PeerURL}, {Name: "m2", PeerURL: "http://192.168.1.2:2380"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := good
			mutate(&c)
			_, err := Start(startCtx(t), c)
			if !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
	if _, _, _, err := good.validate(); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}
	ipv6 := good
	ipv6.ClientURL, ipv6.PeerURL = "http://[::1]:2379", "http://localhost:2380"
	if _, _, _, err := ipv6.validate(); err != nil {
		t.Fatalf("::1 and localhost rejected: %v", err)
	}
}

func TestSelfMonitoring(t *testing.T) {
	n := startOne(t)
	var r selfmon.Registry
	r.Register(n)
	var out strings.Builder
	if err := selfmon.WriteText(&out, r.Gather()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"observex_configstore_up 1", "observex_configstore_has_leader 1",
		"observex_configstore_is_leader 1", "observex_configstore_members 1",
		"observex_configstore_db_bytes ",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("metrics lack %q:\n%s", want, out.String())
		}
	}
	_ = n.Close()
	out.Reset()
	if err := selfmon.WriteText(&out, r.Gather()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "observex_configstore_up 0") {
		t.Fatalf("closed member still up:\n%s", out.String())
	}
}

func TestEtcdLogsGoThroughTheNodeLogger(t *testing.T) {
	var buf syncBuffer
	logger := logging.New(&buf, slog.LevelInfo)
	p := freePorts(t, 2)
	c := memberConfig(t, t.TempDir(), "logged", p[0], p[1])
	c.Logger, c.LogLevel = logger, slog.LevelInfo
	n, err := Start(startCtx(t), c)
	if err != nil {
		t.Fatal(err)
	}
	_ = n.Close()
	got := buf.String()
	if !strings.Contains(got, `"component":"etcd"`) || !strings.Contains(got, `"member":"logged"`) {
		t.Fatalf("no etcd records in the node log:\n%.2000s", got)
	}

	// Below the chosen level nothing is written.
	var quiet syncBuffer
	p2 := freePorts(t, 2)
	c2 := memberConfig(t, t.TempDir(), "quiet", p2[0], p2[1])
	c2.Logger, c2.LogLevel = logging.New(&quiet, slog.LevelDebug), slog.LevelError+4
	n2, err := Start(startCtx(t), c2)
	if err != nil {
		t.Fatal(err)
	}
	_ = n2.Close()
	if quiet.Len() != 0 {
		t.Fatalf("records below the level were written:\n%.500s", quiet.String())
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}
