//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Managed nodes run on Linux. On Windows, init refuses a native path as the
// node's tls_dir and writes nothing (init_unix_test.go covers init itself).
func TestInitRefusesWindowsPathsAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "etc", "node.json")
	code, _, errs := runCmd(t, "init", "-config", cfgPath, "-tls-dir", filepath.Join(dir, "tls"), "-node-id", "node-a")
	if code != exitUsage || !strings.Contains(errs, "tls_dir must be a clean absolute path") {
		t.Fatalf("init: %d %q", code, errs)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("init wrote %d entries (%v)", len(entries), err)
	}
}
