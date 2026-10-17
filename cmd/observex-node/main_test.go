package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/node"
)

func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func needNginx(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"nginx", "/usr/sbin/nginx"} {
		if lp, err := exec.LookPath(p); err == nil {
			return lp
		}
	}
	t.Skip("nginx is not installed")
	return ""
}

func freePorts(t *testing.T, n int) []string {
	t.Helper()
	var out []string
	var lns []net.Listener
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
		out = append(out, ln.Addr().String())
	}
	for _, ln := range lns {
		ln.Close()
	}
	return out
}

// devConfig writes a plaintext configuration on free loopback ports.
func devConfig(t *testing.T, nginx string) (string, node.Config) {
	t.Helper()
	dir := t.TempDir()
	a := freePorts(t, 6)
	doc := map[string]any{
		"node_id": "cmd-test", "run_dir": filepath.Join(dir, "run"), "data_dir": dir,
		"supervisor": map[string]any{"listen": a[0], "probe_interval": "100ms"},
		"front_door": map[string]any{"nginx": nginx, "plaintext": true, "stop_timeout": "5s",
			"console": map[string]any{"listen": a[1]}, "agents": map[string]any{"listen": a[2]}, "probe_listen": a[3]},
		"upstreams": map[string]any{"server": a[4], "gateway": a[5]},
	}
	raw, _ := json.Marshal(doc)
	p := filepath.Join(dir, "node.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := node.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p, cfg
}

func TestVersionAndUsage(t *testing.T) {
	if code, out, _ := runCmd(t, "version"); code != exitOK || !strings.HasPrefix(out, "observex-node ") {
		t.Fatalf("version: %d %q", code, out)
	}
	if code, _, errs := runCmd(t, "frobnicate"); code != exitUsage || !strings.Contains(errs, "unknown command") {
		t.Fatalf("unknown command: %d %q", code, errs)
	}
	if code, _, errs := runCmd(t, "check", "-config", filepath.Join(t.TempDir(), "none.json")); code != exitUsage || !strings.Contains(errs, "node configuration") {
		t.Fatalf("missing config: %d %q", code, errs)
	}
	if code, _, _ := runCmd(t, "status", "-config", "x", "extra"); code != exitUsage {
		t.Fatalf("extra arguments: %d", code)
	}
	if code, _, _ := runCmd(t, "run", "-log-level", "loud", "-config", filepath.Join(t.TempDir(), "none.json")); code != exitUsage {
		t.Fatalf("bad log level / missing config: %d", code)
	}
}

func TestInitWritesConfigAndTLSOnce(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "etc", "node.json")
	tlsDir := filepath.Join(dir, "etc", "tls")
	code, out, errs := runCmd(t, "init", "-config", cfgPath, "-tls-dir", tlsDir, "-node-id", "node-a", "-host", "localhost", "-host", "127.0.0.1", "-peer", "node-b.internal")
	if code != exitOK {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	if !strings.Contains(out, "wrote "+cfgPath) || !strings.Contains(out, "readable by root only") {
		t.Fatalf("init output: %s", out)
	}
	cfg, err := node.Load(cfgPath)
	if err != nil || cfg.NodeID != "node-a" || cfg.TLSDir != tlsDir || len(cfg.Peers) != 1 {
		t.Fatalf("written config: %+v %v", cfg, err)
	}
	for _, f := range []string{"cluster-ca.crt", "cluster-ca.key", "node.crt", "node.key"} {
		if _, err := os.Stat(filepath.Join(tlsDir, f)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	before, _ := os.ReadFile(filepath.Join(tlsDir, "cluster-ca.key"))
	code, out, _ = runCmd(t, "init", "-config", cfgPath, "-tls-dir", tlsDir, "-node-id", "other")
	if code != exitOK || !strings.Contains(out, "exists; kept") || strings.Count(out, "kept") != 2 {
		t.Fatalf("second init: %d %s", code, out)
	}
	after, _ := os.ReadFile(filepath.Join(tlsDir, "cluster-ca.key"))
	if !bytes.Equal(before, after) {
		t.Fatal("second init replaced the CA key")
	}
	if cfg2, _ := node.Load(cfgPath); cfg2.NodeID != "node-a" {
		t.Fatal("second init replaced the configuration")
	}
	if code, _, _ := runCmd(t, "init", "-config", filepath.Join(dir, "x.json"), "-group", "no-such-group-observex"); code != exitUsage {
		t.Fatalf("unknown group: %d", code)
	}
	if code, _, _ := runCmd(t, "init", "-config", filepath.Join(dir, "y.json"), "-node-id", "Bad_ID"); code != exitUsage {
		t.Fatalf("bad node id: %d", code)
	}
}

func TestInitPlaintext(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "node.json")
	code, out, _ := runCmd(t, "init", "-config", p, "-node-id", "dev", "-plaintext", "-tls-dir", filepath.Join(dir, "tls"))
	if code != exitOK || !strings.Contains(out, "tls: skipped") {
		t.Fatalf("%d %s", code, out)
	}
	cfg, err := node.Load(p)
	if err != nil || !cfg.FrontDoor.Plaintext || cfg.FrontDoor.Console.Listen != "127.0.0.1:8080" {
		t.Fatalf("%+v %v", cfg.FrontDoor, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls")); !os.IsNotExist(err) {
		t.Fatal("plaintext init created TLS files")
	}
}

func TestSanitizeID(t *testing.T) {
	for in, want := range map[string]string{
		"Node-1.example.com":    "node-1",
		"WEB_01":                "web-01",
		"--x--":                 "x",
		"":                      "node",
		strings.Repeat("a", 80): strings.Repeat("a", 63),
	} {
		if got := sanitizeID(in); got != want {
			t.Errorf("sanitizeID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckRenderAndFirewall(t *testing.T) {
	nginx := needNginx(t)
	p, cfg := devConfig(t, nginx)
	code, out, errs := runCmd(t, "check", "-config", p)
	if code != exitOK || !strings.Contains(out, "configuration: ok") || !strings.Contains(out, "ports: free") {
		t.Fatalf("check: %d %s %s", code, out, errs)
	}
	// check prepares in a temporary directory, never in the node's run dir.
	if _, err := os.Stat(cfg.RunDir); !os.IsNotExist(err) {
		t.Fatal("check wrote into the node's run directory")
	}
	ln, err := net.Listen("tcp", cfg.FrontDoor.Console.Listen)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errs = runCmd(t, "check", "-config", p)
	ln.Close()
	if code != exitUsage || !strings.Contains(errs, "Console and API") {
		t.Fatalf("check with a busy port: %d %s", code, errs)
	}

	code, out, _ = runCmd(t, "render-nginx", "-config", p)
	if code != exitOK || !strings.Contains(out, "daemon off;") {
		t.Fatalf("render-nginx: %d", code)
	}

	code, out, errs = runCmd(t, "firewall", "-config", p, "-json", "-skip-peers")
	if code == exitUsage {
		t.Fatalf("firewall: %s", errs)
	}
	var rep struct {
		Ports    []json.RawMessage `json:"ports"`
		Firewall string            `json:"firewall"`
		Note     string            `json:"note"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Ports) == 0 || !strings.Contains(rep.Note, "changed nothing") {
		t.Fatalf("firewall JSON: %v %s", err, out)
	}
}

func TestStatusAndHealthWhenNotRunning(t *testing.T) {
	p, _ := devConfig(t, "/usr/sbin/nginx")
	if code, _, errs := runCmd(t, "status", "-config", p); code != exitFailure || !strings.Contains(errs, "not running") {
		t.Fatalf("status: %d %s", code, errs)
	}
	if code, out, _ := runCmd(t, "health", "-config", p); code != exitFailure || strings.TrimSpace(out) != "not ready" {
		t.Fatalf("health: %d %s", code, out)
	}
}

func TestRunServesHealthThenStopsCleanly(t *testing.T) {
	nginx := needNginx(t)
	p, cfg := devConfig(t, nginx)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, errb safeBuffer
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"run", "-config", p}, &out, &errb) }()

	deadline := time.Now().Add(20 * time.Second)
	for {
		code, _, _ := runCmd(t, "health", "-config", p)
		if code == exitOK {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("never healthy\nstderr:\n%s", errb.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	code, status, _ := runCmd(t, "status", "-config", p)
	if code != exitOK || !strings.Contains(status, `"front-door"`) {
		t.Fatalf("status: %d %s", code, status)
	}
	if code, out, _ := runCmd(t, "check", "-config", p, "-running"); code != exitOK || !strings.Contains(out, "not checked") {
		t.Fatalf("check -running: %d %s", code, out)
	}
	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("run exit %d\nstderr:\n%s", code, errb.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("run did not stop")
	}
	if !strings.Contains(errb.String(), "node stopped cleanly") {
		t.Fatalf("stderr:\n%s", errb.String())
	}
	_ = cfg
}
