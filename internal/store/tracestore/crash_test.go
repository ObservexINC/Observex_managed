package tracestore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/store"
	"github.com/ObservexINC/Observex_managed/internal/store/fake"
	"github.com/ObservexINC/Observex_managed/internal/store/storetest"
)

// The crash test runs a writer in a child process, kills it (SIGKILL on
// Unix, TerminateProcess on Windows) at a random moment, and checks the
// recovered store against a model built from the writes the child
// acknowledged. Flushes are frequent, so kills land while blocks are being
// written as well as while the log is appended to.

const crashEnv = "OBSERVEX_TRACESTORE_CRASH_DIR"

// crashBatch is batch i of the writer: a new trace of 1 to 4 spans, and from
// time to time a rewrite of a span of an earlier trace in another service,
// at another time, with the error flag flipped.
func crashBatch(i int) []store.Span {
	r := rand.New(rand.NewSource(int64(i))) //nolint:gosec // G404: test data, not security
	var tid store.TraceID
	copy(tid[:], fmt.Sprintf("crash-%010d", i))
	n := 1 + r.Intn(4)
	var out []store.Span
	for j := 0; j < n; j++ {
		var sid store.SpanID
		copy(sid[:], fmt.Sprintf("span%04d", j))
		start := storetest.T0.Add(time.Duration(i)*time.Second + time.Duration(j)*time.Millisecond)
		out = append(out, store.Span{
			TraceID: tid, SpanID: sid, Service: fmt.Sprintf("svc-%d", r.Intn(4)), Name: "op",
			Start: start, End: start.Add(time.Duration(r.Intn(1000)) * time.Millisecond),
			Error: r.Intn(10) == 0, Attributes: map[string]string{"i": strconv.Itoa(i)},
		})
	}
	if i > 5 && i%4 == 0 {
		prev := crashBatch(i - 5)[0]
		prev.Service = "svc-rewritten"
		prev.Start = prev.Start.Add(30 * time.Minute)
		prev.End = prev.Start.Add(time.Second)
		prev.Error = !prev.Error
		out = append(out, prev)
	}
	return out
}

var crashOptions = Options{MaxHeadSpans: 40, GroupSpans: 8, MaxHeadAge: time.Hour}

// TestCrashHelper is the child process's writer. It does nothing in a normal
// test run.
func TestCrashHelper(t *testing.T) {
	dir := os.Getenv(crashEnv)
	if dir == "" {
		t.Skip("child process of TestCrashRecovery")
	}
	from, _ := strconv.Atoi(os.Getenv(crashEnv + "_FROM"))
	format := os.Getenv(crashEnv + "_FORMAT")
	opts := crashOptions
	opts.Format = format
	s, err := Open(dir, opts)
	if err != nil {
		fmt.Printf("open-error %v\n", err)
		os.Exit(3)
	}
	for i := from; ; i++ {
		if err := s.WriteSpans(context.Background(), crashBatch(i)); err != nil {
			fmt.Printf("write-error %d %v\n", i, err)
			os.Exit(4)
		}
		// Unbuffered: the parent sees the acknowledgement as soon as the
		// write has returned.
		fmt.Printf("ack %d\n", i)
	}
}

func TestCrashRecovery(t *testing.T) {
	if os.Getenv(crashEnv) != "" {
		t.Skip("in the child process")
	}
	rounds := 10
	if testing.Short() {
		rounds = 2
	}
	for _, format := range []string{FormatParquet, FormatSegment} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			rng := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // G404: test timing, not security
			model := fake.NewTraceStore()
			next := 0 // first batch the next child writes
			totalKills := 0
			for round := 0; round < rounds; round++ {
				killAfter := 20 + rng.Intn(150)
				last, inflightErr := runAndKill(t, dir, format, next, killAfter, rng)
				if inflightErr != nil {
					t.Fatal(inflightErr)
				}
				totalKills++
				ctx := testCtx(t)
				for i := next; i <= last; i++ {
					if err := model.WriteSpans(ctx, crashBatch(i)); err != nil {
						t.Fatal(err)
					}
				}
				// The batch after the last acknowledged one may or may not
				// have reached the log; it must be there whole or not at all.
				s, err := Open(dir, Options{Format: format})
				if err != nil {
					t.Fatalf("round %d: recovery failed: %v", round, err)
				}
				pending := crashBatch(last + 1)
				ids := idsUpTo(last + 1)
				if present(t, s, pending) {
					if err := model.WriteSpans(ctx, pending); err != nil {
						t.Fatal(err)
					}
					last++
				}
				sameAs(t, s, model, ids)
				checkNothingAfter(t, s, last+1)
				t.Logf("round %d: killed after ack %d (%d blocks, %d recovered batches, %d bytes cut, %d unfinished blocks removed)",
					round, last, len(s.blocks), s.stats.recoveredBatches.Load(), s.stats.truncated.Load(), s.stats.tmpRemovedAt.Load())
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				next = last + 1
			}
			if totalKills != rounds {
				t.Fatalf("%d kills, want %d", totalKills, rounds)
			}
		})
	}
}

// runAndKill starts the writer at batch from, kills it after at least
// killAfter acknowledgements (plus a random short delay), and returns the
// last acknowledged batch.
func runAndKill(t *testing.T, dir, format string, from, killAfter int, rng *rand.Rand) (int, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelper$", "-test.count=1") //nolint:gosec,noctx // G204: the test binary itself; killed below
	cmd.Env = append(os.Environ(), crashEnv+"="+dir, crashEnv+"_FROM="+strconv.Itoa(from), crashEnv+"_FORMAT="+format)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	sc := bufio.NewScanner(out)
	last, acks := from-1, 0
	killed := false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "ack "):
			n, _ := strconv.Atoi(strings.TrimPrefix(line, "ack "))
			if n != last+1 {
				_ = cmd.Process.Kill()
				return 0, fmt.Errorf("acknowledgement %d after %d", n, last)
			}
			last = n
			acks++
			if acks == killAfter && !killed {
				time.Sleep(time.Duration(rng.Intn(3000)) * time.Microsecond)
				if err := cmd.Process.Kill(); err != nil {
					return 0, err
				}
				killed = true
			}
		case strings.HasPrefix(line, "open-error"), strings.HasPrefix(line, "write-error"):
			_ = cmd.Process.Kill()
			return 0, errors.New("child: " + line)
		}
	}
	_ = cmd.Wait()
	if !killed {
		return 0, fmt.Errorf("child exited after %d acknowledgements without being killed", acks)
	}
	return last, nil
}

func idsUpTo(last int) []store.TraceID {
	var ids []store.TraceID
	for i := 0; i <= last; i++ {
		ids = append(ids, crashBatch(i)[0].TraceID)
	}
	return ids
}

// present reports whether batch b is in the store, failing if only part of
// it is.
func present(t *testing.T, s *Store, b []store.Span) bool {
	t.Helper()
	ctx := testCtx(t)
	found, missing := 0, 0
	for _, sp := range b {
		got, err := s.GetTrace(ctx, sp.TraceID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		hit := false
		for _, g := range got {
			if g.SpanID == sp.SpanID && reflect.DeepEqual(g, normalised(sp)) {
				hit = true
			}
		}
		if hit {
			found++
		} else {
			missing++
		}
	}
	if found > 0 && missing > 0 {
		t.Fatalf("a batch is partly present: %d spans found, %d missing", found, missing)
	}
	return found > 0
}

func normalised(sp store.Span) store.Span {
	sp.Start, sp.End = sp.Start.UTC(), sp.End.UTC()
	return sp
}

// checkNothingAfter checks that no batch after the last one was stored.
func checkNothingAfter(t *testing.T, s *Store, first int) {
	t.Helper()
	ctx := testCtx(t)
	for i := first; i < first+3; i++ {
		if _, err := s.GetTrace(ctx, crashBatch(i)[0].TraceID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("batch %d, never acknowledged or written, is present: %v", i, err)
		}
	}
}
