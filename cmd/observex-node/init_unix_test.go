//go:build !windows

package main

// observex-node init writes a node configuration whose tls_dir is both a
// node (Linux) path recorded in the configuration and the host directory
// the TLS files are written to. The two agree only where host paths are
// slash-separated, so these tests run on Linux and other Unix systems, not
// on Windows. init on Windows refuses before writing anything
// (init_windows_test.go).

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/node"
)

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
