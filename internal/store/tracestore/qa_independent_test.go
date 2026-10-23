package tracestore

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

func TestQATraceExclusiveDirectory(t *testing.T) {
	for _, format := range []string{FormatParquet, FormatSegment} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			s := openT(t, dir, Options{Format: format})
			second, err := Open(dir, Options{Format: format})
			if err == nil {
				_ = second.Close()
				t.Error("second store opened the active directory; recovery can remove the first writer's WAL")
			}
			spans := genSpans(808, 1, 1)
			if err := s.WriteSpans(testCtx(t), spans); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened := openT(t, dir, Options{Format: format})
			got, err := reopened.GetTrace(testCtx(t), spans[0].TraceID)
			if err != nil || len(got) != 1 {
				t.Fatalf("acknowledged write lost after duplicate open: spans=%d error=%v", len(got), err)
			}
		})
	}
}

func TestQATraceExclusivePopulatedDirectory(t *testing.T) {
	for _, format := range []string{FormatParquet, FormatSegment} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			s := openT(t, dir, Options{Format: format})
			if err := s.WriteSpans(testCtx(t), genSpans(811, 1, 1)); err != nil {
				t.Fatal(err)
			}
			second, err := Open(dir, Options{Format: format})
			if err == nil {
				_ = second.Close()
				t.Fatal("second store opened a directory with a live writer and acknowledged records")
			}
		})
	}
}

func TestQATraceLockOtherProcess(t *testing.T) {
	if dir := os.Getenv("OBSERVEX_QA_LOCK_DIR"); dir != "" {
		second, err := Open(dir, Options{})
		if err == nil {
			_ = second.Close()
			t.Fatal("child process acquired a live store directory")
		}
		return
	}
	dir := t.TempDir()
	s := openT(t, dir, Options{})
	if err := s.WriteSpans(testCtx(t), genSpans(812, 1, 1)); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(testCtx(t), os.Args[0], "-test.run=^TestQATraceLockOtherProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "OBSERVEX_QA_LOCK_DIR="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-process exclusion failed: %v\n%s", err, out)
	}
}

func TestQATraceFailedOpenReleasesDirectory(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "blocks", "broken")
	if err := os.MkdirAll(broken, 0o700); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(dir, Options{}); err == nil {
		_ = s.Close()
		t.Fatal("expected corrupt block to fail Open")
	}
	if err := os.Remove(broken); err != nil {
		t.Fatal(err)
	}
	_ = openT(t, dir, Options{})
}

func TestQATraceFlushRotationFailure(t *testing.T) {
	s := openT(t, t.TempDir(), Options{})
	spans := genSpans(809, 1, 1)
	if err := s.WriteSpans(testCtx(t), spans); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(s.walDir, segmentName(s.nextSeg))
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(testCtx(t)); err == nil {
		t.Error("Flush returned success although creation of the next WAL segment failed")
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(testCtx(t)); err != nil {
		t.Fatalf("flush after recovery: %v", err)
	}
	if got, err := s.GetTrace(testCtx(t), spans[0].TraceID); err != nil || len(got) != 1 {
		t.Fatalf("trace after recovery: %v, %v", got, err)
	}
}

func TestQATraceTinyHeadAge(t *testing.T) {
	if os.Getenv("OBSERVEX_QA_TINY_AGE") == "1" {
		s := openT(t, t.TempDir(), Options{MaxHeadAge: time.Nanosecond})
		spans := genSpans(810, 1, 1)
		if err := s.WriteSpans(testCtx(t), spans); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for s.stats.flushes.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if s.stats.flushes.Load() == 0 {
			t.Fatal("tiny-age head never flushed")
		}
		return
	}
	ctx := testCtx(t)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestQATraceTinyHeadAge$", "-test.v")
	cmd.Env = append(os.Environ(), "OBSERVEX_QA_TINY_AGE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tiny positive MaxHeadAge crashed process: %v\n%s", err, out)
	}
}

// The public contract types must remain the types exercised by the fixture.
var _ store.TraceStore = (*Store)(nil)
