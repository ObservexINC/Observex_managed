//go:build !windows

package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/node/pki"
	"github.com/ObservexINC/Observex_managed/internal/node/supervisor"
	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
	"github.com/ObservexINC/Observex_managed/internal/platform/tlsx/tlstest"
)

// syncBuffer is a goroutine-safe buffer for component output and logs.
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

func nginxPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("nginx")
	if err != nil {
		for _, c := range []string{"/usr/sbin/nginx", "/usr/local/sbin/nginx"} {
			if _, e := os.Stat(c); e == nil {
				return c
			}
		}
		t.Skip("nginx is not installed; the Front Door integration tests need it")
	}
	return p
}

type runningNode struct {
	cfg     Config
	sup     *supervisor.Supervisor
	status  string
	done    chan error
	cancel  context.CancelFunc
	logs    *syncBuffer
	out     *syncBuffer
	tlsFile pki.Files
}

// startNode runs a node with TLS on loopback ports until the test ends.
func startNode(t *testing.T, plaintext bool) *runningNode {
	t.Helper()
	nginx := nginxPath(t)
	dir := t.TempDir()
	addrs := freeAddrs(t, 6)
	files := pki.Files{}
	fd := map[string]any{
		"nginx":        nginx,
		"console":      map[string]any{"listen": addrs[0]},
		"agents":       map[string]any{"listen": addrs[1]},
		"probe_listen": addrs[2],
		"stop_timeout": "5s",
	}
	if plaintext {
		fd["plaintext"] = true
	} else {
		var err error
		files, err = pki.Init(filepath.Join(dir, "tls"), pki.Options{NodeName: "it-node", Hosts: []string{"127.0.0.1", "localhost"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	doc := map[string]any{
		"node_id":  "it-node",
		"run_dir":  filepath.Join(dir, "run"),
		"data_dir": dir,
		"tls_dir":  filepath.Join(dir, "tls"),
		"supervisor": map[string]any{
			"listen":          addrs[3],
			"initial_backoff": "100ms",
			"max_backoff":     "500ms",
			"probe_interval":  "100ms",
			"start_timeout":   "15s",
		},
		"front_door": fd,
		"upstreams":  map[string]any{"server": addrs[4], "gateway": addrs[5]},
	}
	raw, _ := json.Marshal(doc)
	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	n := &runningNode{cfg: cfg, done: make(chan error, 1), logs: &syncBuffer{}, out: &syncBuffer{}, tlsFile: files}
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	started := make(chan struct{})
	go func() {
		n.done <- Run(ctx, cfg, Options{
			Logger:  logging.New(n.logs, nil),
			Out:     n.out,
			Version: "test",
			Started: func(addr string, sup *supervisor.Supervisor) {
				n.status, n.sup = addr, sup
				close(started)
			},
		})
	}()
	select {
	case <-started:
	case err := <-n.done:
		t.Fatalf("node did not start: %v\nlogs:\n%s", err, n.logs.String())
	case <-time.After(30 * time.Second):
		t.Fatal("node did not start within 30s")
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-n.done:
		case <-time.After(30 * time.Second):
			t.Error("node did not stop within 30s")
		}
	})
	if !n.sup.WaitTimeout(func(s supervisor.Status) bool { return s.Ready }, 20*time.Second, 50*time.Millisecond) {
		t.Fatalf("node not ready: %+v\nlogs:\n%s\noutput:\n%s", n.sup.Status(), n.logs.String(), n.out.String())
	}
	return n
}

func (n *runningNode) client(t *testing.T) *http.Client {
	t.Helper()
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	if n.tlsFile.CACert != "" {
		caPEM, err := os.ReadFile(n.tlsFile.CACert)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(caPEM)
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13}
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func (n *runningNode) consoleURL(p string) string {
	scheme := "https://"
	if n.cfg.FrontDoor.Plaintext {
		scheme = "http://"
	}
	return scheme + n.cfg.FrontDoor.Console.Listen + p
}

func get(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func frontDoorPID(t *testing.T, sup *supervisor.Supervisor) (pid, restarts int) {
	t.Helper()
	for _, c := range sup.Status().Components {
		if c.Name == "front-door" {
			return c.PID, c.Restarts
		}
	}
	t.Fatal("no front-door component")
	return 0, 0
}

// TestKilledFrontDoorIsRestarted is G01's "a killed process is restarted"
// against a real NGINX with TLS: kill -9 the NGINX master, and the node
// serves /node/health through the Front Door again.
func TestKilledFrontDoorIsRestarted(t *testing.T) {
	n := startNode(t, false)
	c := n.client(t)
	if code, body := get(t, c, n.consoleURL("/node/health")); code != 200 || !strings.Contains(body, `"ready"`) {
		t.Fatalf("health through the Front Door: %d %s", code, body)
	}

	pid, restarts := frontDoorPID(t, n.sup)
	if pid <= 0 || restarts != 0 {
		t.Fatalf("pid %d restarts %d", pid, restarts)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	ok := n.sup.WaitTimeout(func(s supervisor.Status) bool {
		for _, cs := range s.Components {
			if cs.Name == "front-door" {
				return cs.Restarts == 1 && cs.State == supervisor.StateReady && cs.PID != pid
			}
		}
		return false
	}, 20*time.Second, 50*time.Millisecond)
	if !ok {
		t.Fatalf("front door not restarted: %+v\noutput:\n%s", n.sup.Status(), n.out.String())
	}
	if code, body := get(t, c, n.consoleURL("/node/health")); code != 200 {
		t.Fatalf("health after restart: %d %s", code, body)
	}
	// The killed master's workers must not survive: the supervisor kills
	// the whole process group before restarting. (They may linger as
	// zombies when PID 1 does not reap, as in some containers; zombies hold
	// no sockets and are not counted.)
	if live := liveInGroup(t, pid); len(live) > 0 {
		t.Fatalf("processes of the killed NGINX (group %d) are still running: %v", pid, live)
	}
}

// liveInGroup lists the processes in a process group that are not zombies.
// It reads /proc, so it checks only on Linux.
func liveInGroup(t *testing.T, pgid int) []string {
	t.Helper()
	if runtime.GOOS != "linux" {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var live []string
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		line := string(raw)
		i := strings.LastIndexByte(line, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(line[i+1:]) // state ppid pgrp ...
		if len(f) < 3 || f[2] != strconv.Itoa(pgid) || f[0] == "Z" || f[0] == "X" {
			continue
		}
		live = append(live, e.Name()+" "+f[0])
	}
	return live
}

func TestStatusAndMetrics(t *testing.T) {
	n := startNode(t, false)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}

	code, body := get(t, c, "http://"+n.status+"/readyz")
	if code != 200 || !strings.Contains(body, `"node_id":"it-node"`) || !strings.Contains(body, `"front-door"`) {
		t.Fatalf("readyz: %d %s", code, body)
	}
	code, body = get(t, c, "http://"+n.status+"/metrics")
	if code != 200 {
		t.Fatalf("metrics: %d", code)
	}
	for _, want := range []string{
		"observex_node_ready 1",
		`observex_node_component_ready{component="front-door"} 1`,
		`observex_node_info{node_id="it-node",version="test"} 1`,
		`observex_node_front_door_info{`,
		`tls="on"`,
		`observex_node_tls_certificate_expiry_seconds{listener="agents"}`,
		`observex_node_component_processes{component="front-door"}`,
		"observex_node_host_memory_total_bytes",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	// The supervisor's full status is local only: the Front Door exposes
	// /node/health and nothing else of the supervisor.
	fc := n.client(t)
	if code, _ := get(t, fc, n.consoleURL("/node/status")); code == 200 {
		t.Fatal("the Front Door exposes the supervisor's status")
	}
	if code, _ := get(t, fc, n.consoleURL("/metrics")); code == 200 {
		t.Fatal("the Front Door exposes /metrics")
	}
}

func TestAgentsListenerNeedsAClientCertificate(t *testing.T) {
	n := startNode(t, false)
	caPEM, err := os.ReadFile(n.tlsFile.CACert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	url := "https://" + n.cfg.FrontDoor.Agents.Listen + "/v1/metrics"
	post := func(certs []tls.Certificate) int {
		tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{
			RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, Certificates: certs,
		}}
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Post(url, "application/x-protobuf", strings.NewReader("x"))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// No certificate: refused by the Front Door itself.
	if code := post(nil); code != http.StatusForbidden && code != 496 {
		t.Fatalf("without a client certificate: %d", code)
	}
	// A certificate from another CA: refused too.
	other := tlstest.NewCA(t, "rogue CA")
	if code := post([]tls.Certificate{other.Client(t, "rogue-agent")}); code != http.StatusForbidden && code != 495 && code != 400 {
		t.Fatalf("certificate from another CA: %d", code)
	}
}

func TestCleanStopReport(t *testing.T) {
	n := startNode(t, true)
	n.cancel()
	select {
	case err := <-n.done:
		if err != nil {
			t.Fatalf("stop: %v\nlogs:\n%s", err, n.logs.String())
		}
		n.done <- nil // let the cleanup see the node as stopped
	case <-time.After(30 * time.Second):
		t.Fatal("node did not stop")
	}
	reports := n.sup.StopReports()
	if len(reports) != 1 || reports[0].Outcome != supervisor.OutcomeStopped {
		t.Fatalf("stop reports: %+v", reports)
	}
	if !strings.Contains(n.logs.String(), "node stopped cleanly") {
		t.Fatalf("logs:\n%s", n.logs.String())
	}
	// Every line the node logged is JSON (it goes to the journal and to
	// log shippers).
	sc := bufio.NewScanner(strings.NewReader(n.logs.String()))
	for sc.Scan() {
		if !json.Valid(sc.Bytes()) {
			t.Fatalf("log line is not JSON: %s", sc.Text())
		}
	}
}
