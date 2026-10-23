package tracestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/node/selfmon"
	"github.com/ObservexINC/Observex_managed/internal/store"
	"github.com/ObservexINC/Observex_managed/internal/store/fake"
	"github.com/ObservexINC/Observex_managed/internal/store/storetest"
)

func testCtx(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func openT(t testing.TB, dir string, opts Options) *Store {
	t.Helper()
	s, err := Open(dir, opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// flushing writes every call straight into a block, so the contract runs
// against blocks rather than the head.
type flushing struct{ *Store }

func (f flushing) WriteSpans(ctx context.Context, spans []store.Span) error {
	if err := f.Store.WriteSpans(ctx, spans); err != nil {
		return err
	}
	return f.Flush(ctx)
}

// reopening closes and reopens the store after every write, so the contract
// runs against what recovery rebuilds.
type reopening struct {
	t    *testing.T
	dir  string
	opts Options
	s    *Store
}

func (r *reopening) WriteSpans(ctx context.Context, spans []store.Span) error {
	if err := r.s.WriteSpans(ctx, spans); err != nil {
		return err
	}
	if err := r.s.Close(); err != nil {
		return err
	}
	s, err := Open(r.dir, r.opts)
	if err != nil {
		r.t.Fatalf("reopen: %v", err)
	}
	r.s = s
	return nil
}

func (r *reopening) GetTrace(ctx context.Context, id store.TraceID) ([]store.Span, error) {
	return r.s.GetTrace(ctx, id)
}

func (r *reopening) FindTraces(ctx context.Context, q store.TraceQuery) ([]store.TraceSummary, error) {
	return r.s.FindTraces(ctx, q)
}

func (r *reopening) Close() error { return r.s.Close() }

func TestContract(t *testing.T) {
	for _, format := range []string{FormatParquet, FormatSegment} {
		t.Run(format+"/head", func(t *testing.T) {
			storetest.TraceStore(t, func(t *testing.T) store.TraceStore {
				return openT(t, t.TempDir(), Options{Format: format})
			})
		})
		t.Run(format+"/blocks", func(t *testing.T) {
			storetest.TraceStore(t, func(t *testing.T) store.TraceStore {
				return flushing{openT(t, t.TempDir(), Options{Format: format, GroupSpans: 2})}
			})
		})
		t.Run(format+"/reopened", func(t *testing.T) {
			storetest.TraceStore(t, func(t *testing.T) store.TraceStore {
				r := &reopening{t: t, dir: t.TempDir(), opts: Options{Format: format, MaxHeadSpans: 3, GroupSpans: 2}}
				r.s = openT(t, r.dir, r.opts)
				t.Cleanup(func() { _ = r.s.Close() })
				return r
			})
		})
	}
}

// genSpans returns n traces of k spans each, over several services, with
// attributes, some errors and a nil attribute map now and then.
func genSpans(seed, traces, k int) []store.Span {
	var out []store.Span
	t0 := storetest.T0
	for i := 0; i < traces; i++ {
		var tid store.TraceID
		copy(tid[:], fmt.Sprintf("t%05d-%09d", seed, i))
		for j := 0; j < k; j++ {
			var sid, parent store.SpanID
			copy(sid[:], fmt.Sprintf("s%07d", j))
			if j > 0 {
				copy(parent[:], fmt.Sprintf("s%07d", j-1))
			}
			start := t0.Add(time.Duration(i)*time.Second + time.Duration(j)*time.Millisecond)
			sp := store.Span{
				TraceID: tid, SpanID: sid, ParentID: parent,
				Service: fmt.Sprintf("svc-%d", (i+j)%5), Name: fmt.Sprintf("op %d", j),
				Start: start, End: start.Add(time.Duration(10+j) * time.Millisecond),
				Error: (i+j)%7 == 0,
			}
			if (i+j)%11 != 0 {
				sp.Attributes = map[string]string{"http.route": fmt.Sprintf("/r/%d", j), "k8s.pod": "pod-" + fmt.Sprint(i%3)}
			}
			if (i+j)%13 == 0 {
				sp.Attributes = map[string]string{}
			}
			out = append(out, sp)
		}
	}
	return out
}

// sameAs compares a store with the fake on every trace and some queries.
func sameAs(t *testing.T, got store.TraceStore, want *fake.TraceStore, ids []store.TraceID) {
	t.Helper()
	ctx := testCtx(t)
	for _, id := range ids {
		g, gerr := got.GetTrace(ctx, id)
		w, werr := want.GetTrace(ctx, id)
		if !errors.Is(gerr, werr) && (gerr != nil || werr != nil) {
			t.Fatalf("trace %s: err %v, fake %v", id, gerr, werr)
		}
		if !reflect.DeepEqual(g, w) {
			t.Fatalf("trace %s differs from the fake:\n got %+v\nwant %+v", id, g, w)
		}
	}
	for _, q := range []store.TraceQuery{
		{Service: "svc-1", Range: store.TimeRange{Start: storetest.T0, End: storetest.T0.Add(24 * time.Hour)}, Limit: store.MaxLimit},
		{Service: "svc-3", Range: store.TimeRange{Start: storetest.T0.Add(30 * time.Second), End: storetest.T0.Add(90 * time.Second)}},
		{Service: "svc-0", Range: store.TimeRange{Start: storetest.T0, End: storetest.T0.Add(time.Hour)}, ErrorsOnly: true, Limit: 7},
	} {
		g, err := got.FindTraces(ctx, q)
		if err != nil {
			t.Fatalf("find %+v: %v", q, err)
		}
		w, _ := want.FindTraces(ctx, q)
		if !reflect.DeepEqual(g, w) {
			t.Fatalf("find %+v differs from the fake:\n got %d %+v\nwant %d %+v", q, len(g), g, len(w), w)
		}
	}
}

func traceIDs(spans []store.Span) []store.TraceID {
	seen := map[store.TraceID]bool{}
	var out []store.TraceID
	for _, s := range spans {
		if !seen[s.TraceID] {
			seen[s.TraceID] = true
			out = append(out, s.TraceID)
		}
	}
	return out
}

// TestMatchesFakeAcrossHeadsAndBlocks writes the same data, with rewrites
// that move spans between services and times, to the store and the fake,
// with flushes in between, and compares them.
func TestMatchesFakeAcrossHeadsAndBlocks(t *testing.T) {
	for _, format := range []string{FormatParquet, FormatSegment} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			opts := Options{Format: format, MaxHeadSpans: 500, GroupSpans: 64}
			s := openT(t, dir, opts)
			f := fake.NewTraceStore()
			ctx := testCtx(t)
			all := genSpans(1, 300, 6)
			for i := 0; i < len(all); i += 37 {
				end := i + 37
				if end > len(all) {
					end = len(all)
				}
				for _, st := range []store.TraceStore{s, f} {
					if err := st.WriteSpans(ctx, all[i:end]); err != nil {
						t.Fatal(err)
					}
				}
			}
			// Rewrites: change service, start and error of every 9th span.
			var rw []store.Span
			for i := 0; i < len(all); i += 9 {
				sp := all[i]
				sp.Service = "svc-1"
				sp.Start = sp.Start.Add(-time.Hour)
				sp.Error = !sp.Error
				sp.Attributes = map[string]string{"rewritten": "yes"}
				rw = append(rw, sp)
			}
			for _, st := range []store.TraceStore{s, f} {
				if err := st.WriteSpans(ctx, rw); err != nil {
					t.Fatal(err)
				}
			}
			ids := append(traceIDs(all), store.TraceID{0xff, 1})
			sameAs(t, s, f, ids)
			if err := s.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			sameAs(t, s, f, ids)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s2 := openT(t, dir, opts)
			sameAs(t, s2, f, ids)
			if len(s2.blocks) < 2 {
				t.Fatalf("expected several blocks, got %d", len(s2.blocks))
			}
		})
	}
}

func TestTornLogTailIsCut(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir, Options{})
	ctx := testCtx(t)
	spans := genSpans(2, 10, 3)
	if err := s.WriteSpans(ctx, spans[:15]); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteSpans(ctx, spans[15:]); err != nil {
		t.Fatal(err)
	}
	seg := s.wal.path
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	full, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	// A third record, cut at every possible length, must vanish whole.
	third, err := encodeBatch(99, genSpans(3, 1, 2))
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut < len(third); cut += 7 {
		if err := os.WriteFile(seg, append(append([]byte{}, full...), third[:cut]...), 0o600); err != nil {
			t.Fatal(err)
		}
		s2, err := Open(dir, Options{})
		if err != nil {
			t.Fatalf("cut %d: open: %v", cut, err)
		}
		f := fake.NewTraceStore()
		_ = f.WriteSpans(ctx, spans)
		sameAs(t, s2, f, append(traceIDs(spans), genSpans(3, 1, 2)[0].TraceID))
		if s2.stats.truncated.Load() != uint64(cut) {
			t.Fatalf("cut %d: %d bytes cut", cut, s2.stats.truncated.Load())
		}
		if err := s2.Close(); err != nil {
			t.Fatal(err)
		}
		// Recovery wrote a fresh segment; remove it so the next round starts
		// from the same files.
		nums, _ := listSegments(filepath.Join(dir, "wal"))
		for _, n := range nums {
			if p := filepath.Join(dir, "wal", segmentName(n)); p != seg {
				_ = os.Remove(p)
			}
		}
	}
}

func TestDamagedLogRecordKeepsWhatCameBefore(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir, Options{})
	ctx := testCtx(t)
	a, b := genSpans(4, 2, 2), genSpans(5, 2, 2)
	_ = s.WriteSpans(ctx, a)
	size := s.wal.size
	_ = s.WriteSpans(ctx, b)
	seg := s.wal.path
	_ = s.Close()
	data, _ := os.ReadFile(seg)
	data[size+walHeaderSize+3] ^= 0xff // damage the second record's payload
	_ = os.WriteFile(seg, data, 0o600)
	s2 := openT(t, dir, Options{})
	if _, err := s2.GetTrace(ctx, a[0].TraceID); err != nil {
		t.Fatalf("record before the damage lost: %v", err)
	}
	if _, err := s2.GetTrace(ctx, b[0].TraceID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("damaged record served: %v", err)
	}
}

func TestUnfinishedBlockIsRemovedAndLogReplayed(t *testing.T) {
	dir := t.TempDir()
	ctx := testCtx(t)
	s := openT(t, dir, Options{})
	spans := genSpans(6, 20, 3)
	_ = s.WriteSpans(ctx, spans)
	_ = s.Close()
	// A crash while writing a block leaves a temporary directory behind.
	tmp := filepath.Join(dir, "blocks", ".tmp-0000000000000001-0000000000000001")
	_ = os.MkdirAll(tmp, 0o700)
	_ = os.WriteFile(filepath.Join(tmp, "spans.parquet"), []byte("half a file"), 0o600)
	s2 := openT(t, dir, Options{})
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("unfinished block not removed: %v", err)
	}
	f := fake.NewTraceStore()
	_ = f.WriteSpans(ctx, spans)
	sameAs(t, s2, f, traceIDs(spans))
}

func TestBlockAndLogBothPresent(t *testing.T) {
	// A crash after a block is renamed into place but before its log
	// segments are removed: recovery must not count the spans twice.
	dir := t.TempDir()
	ctx := testCtx(t)
	s := openT(t, dir, Options{})
	spans := genSpans(7, 30, 2)
	_ = s.WriteSpans(ctx, spans)
	seg := s.wal.path
	saved, _ := os.ReadFile(seg)
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := os.WriteFile(seg, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := openT(t, dir, Options{})
	if s2.active.spans != 0 {
		t.Fatalf("%d spans replayed into the head; they are already in a block", s2.active.spans)
	}
	if _, err := os.Stat(seg); !os.IsNotExist(err) {
		t.Fatal("applied log segment not removed")
	}
	f := fake.NewTraceStore()
	_ = f.WriteSpans(ctx, spans)
	sameAs(t, s2, f, traceIDs(spans))
	got, _ := s2.FindTraces(ctx, store.TraceQuery{Service: "svc-1", Range: store.TimeRange{Start: storetest.T0, End: storetest.T0.Add(time.Hour)}, Limit: store.MaxLimit})
	for _, sum := range got {
		if sum.SpanCount != 2 {
			t.Fatalf("trace %s counted %d spans", sum.TraceID, sum.SpanCount)
		}
	}
}

func TestDamagedBlockFailsOpenWithoutPanic(t *testing.T) {
	for _, format := range []string{FormatParquet, FormatSegment} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			ctx := testCtx(t)
			s := openT(t, dir, Options{Format: format})
			_ = s.WriteSpans(ctx, genSpans(8, 10, 2))
			if err := s.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			blk := s.blocks[0].dir
			_ = s.Close()
			idx := filepath.Join(blk, "index.bin")
			data, _ := os.ReadFile(idx)
			data[len(data)/2] ^= 1
			_ = os.WriteFile(idx, data, 0o600)
			_, err := Open(dir, Options{Format: format})
			if !errors.Is(err, errCorrupt) {
				t.Fatalf("open with a damaged index: %v", err)
			}
		})
	}
}

func TestInvalidInput(t *testing.T) {
	s := openT(t, t.TempDir(), Options{})
	ctx := testCtx(t)
	ok := genSpans(9, 1, 1)[0]
	old := ok
	old.Start, old.End = time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1600, 1, 1, 0, 0, 1, 0, time.UTC)
	if err := s.WriteSpans(ctx, []store.Span{ok, old}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("time before 1678: %v", err)
	}
	if _, err := s.GetTrace(ctx, ok.TraceID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("partial write: %v", err)
	}
	big := ok
	big.Attributes = map[string]string{"blob": strings.Repeat("x", maxBatchBytes)}
	if err := s.WriteSpans(ctx, []store.Span{big}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("batch over the limit: %v", err)
	}
	if _, err := Open(t.TempDir(), Options{Format: "csv"}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("unknown format: %v", err)
	}
	if err := s.WriteSpans(ctx, nil); err != nil {
		t.Fatalf("empty write: %v", err)
	}
}

func TestExtremeTimesRoundTrip(t *testing.T) {
	s := openT(t, t.TempDir(), Options{GroupSpans: 1})
	ctx := testCtx(t)
	sp := genSpans(10, 1, 1)[0]
	sp.Start, sp.End = minTime, maxTime
	if err := s.WriteSpans(ctx, []store.Span{sp}); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"head", "block"} {
		got, err := s.GetTrace(ctx, sp.TraceID)
		if err != nil || !got[0].Start.Equal(minTime) || !got[0].End.Equal(maxTime) {
			t.Fatalf("%s: %+v, %v", phase, got, err)
		}
		if err := s.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBackgroundFlushByAge(t *testing.T) {
	s := openT(t, t.TempDir(), Options{MaxHeadAge: 40 * time.Millisecond})
	ctx := testCtx(t)
	_ = s.WriteSpans(ctx, genSpans(11, 3, 2))
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.mu.RLock()
		n := len(s.blocks)
		s.mu.RUnlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("old head was not flushed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	nums, _ := listSegments(filepath.Join(s.dir, "wal"))
	if len(nums) != 1 {
		t.Fatalf("%d log segments after the flush, want only the new one", len(nums))
	}
}

func TestSelfMonitoring(t *testing.T) {
	s := openT(t, t.TempDir(), Options{})
	ctx := testCtx(t)
	_ = s.WriteSpans(ctx, genSpans(12, 4, 2))
	_ = s.Flush(ctx)
	var r selfmon.Registry
	r.Register(s)
	var out bytes.Buffer
	if err := selfmon.WriteText(&out, r.Gather()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"observex_tracestore_spans_written_total 8", "observex_tracestore_batches_total 1",
		"observex_tracestore_blocks 1", "observex_tracestore_block_spans 8", "observex_tracestore_head_spans 0",
		"observex_tracestore_flushes_total 1",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("metrics lack %q:\n%s", want, out.String())
		}
	}
}

func TestWritesRefusedWhileFlushesFail(t *testing.T) {
	dir := t.TempDir()
	s := openT(t, dir, Options{MaxHeadSpans: 1, MaxFrozenHeads: 2})
	ctx := testCtx(t)
	// Make the blocks directory unwritable by replacing it with a file.
	if err := os.RemoveAll(filepath.Join(dir, "blocks")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blocks"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	for i := 0; i < 50 && err == nil; i++ {
		err = s.WriteSpans(ctx, genSpans(13+i, 1, 1))
		time.Sleep(5 * time.Millisecond)
	}
	if err == nil || !strings.Contains(err.Error(), "waiting to be written") {
		t.Fatalf("writes not refused while flushes fail: %v", err)
	}
	// Everything accepted is still readable from memory.
	if _, gerr := s.GetTrace(ctx, genSpans(13, 1, 1)[0].TraceID); gerr != nil {
		t.Fatalf("accepted span lost: %v", gerr)
	}
}
