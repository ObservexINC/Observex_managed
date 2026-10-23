package tracestore

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/store"
	"github.com/ObservexINC/Observex_managed/internal/store/storetest"
)

// The benchmarks compare the Parquet block format with the plain segment
// format (technology row T7) on the same spans:
//
//	go test -run '^$' -bench . -benchtime 3x ./internal/store/tracestore
//
// benchSpans builds traces of 8 spans over 6 services, with the attributes
// a typical HTTP and database call carries.
func benchSpans(traces int) []store.Span {
	r := rand.New(rand.NewSource(42)) //nolint:gosec // G404: benchmark data
	services := []string{"frontend", "checkout", "payments", "cart", "orders-db", "inventory"}
	routes := []string{"/api/cart", "/api/checkout", "/api/pay", "/api/items/{id}", "/healthz"}
	out := make([]store.Span, 0, traces*8)
	for i := 0; i < traces; i++ {
		var tid store.TraceID
		r.Read(tid[:])
		start := storetest.T0.Add(time.Duration(i) * 10 * time.Millisecond)
		var parent store.SpanID
		for j := 0; j < 8; j++ {
			var sid store.SpanID
			r.Read(sid[:])
			svc := services[(i+j)%len(services)]
			attrs := map[string]string{
				"http.request.method":       "GET",
				"http.route":                routes[r.Intn(len(routes))],
				"http.response.status_code": fmt.Sprint([]int{200, 200, 200, 404, 500}[r.Intn(5)]),
				"k8s.pod.name":              fmt.Sprintf("%s-%d", svc, r.Intn(20)),
				"server.address":            svc + ".shop.svc.cluster.local",
			}
			if svc == "orders-db" {
				attrs["db.query.text"] = "SELECT id, status, total FROM orders WHERE customer_id = $1 AND created_at > $2 ORDER BY created_at DESC LIMIT 50"
			}
			s := start.Add(time.Duration(j) * time.Millisecond)
			out = append(out, store.Span{
				TraceID: tid, SpanID: sid, ParentID: parent, Service: svc,
				Name: "GET " + attrs["http.route"], Start: s, End: s.Add(time.Duration(1+r.Intn(200)) * time.Millisecond),
				Error: r.Intn(50) == 0, Attributes: attrs,
			})
			parent = sid
		}
	}
	return out
}

const benchTraces = 12_500 // 100,000 spans

func benchRecs(spans []store.Span) []spanRec {
	recs := make([]spanRec, len(spans))
	for i, s := range spans {
		recs[i] = spanRec{span: s, seq: uint64(i/100 + 1)}
	}
	sortRecs(recs)
	return recs
}

func dirSize(dir string) int64 {
	var n int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			n += info.Size()
		}
		return nil
	})
	return n
}

func BenchmarkBlockWrite(b *testing.B) {
	recs := benchRecs(benchSpans(benchTraces))
	for _, name := range []string{FormatParquet, FormatSegment} {
		format, _ := formatByName(name)
		b.Run(name, func(b *testing.B) {
			var size int64
			for i := 0; i < b.N; i++ {
				dir := b.TempDir()
				blk, err := writeBlock(dir, format, recs, defaultGroupSpans)
				if err != nil {
					b.Fatal(err)
				}
				size = dirSize(blk.dir)
				_ = blk.close()
			}
			b.ReportMetric(float64(size)/float64(len(recs)), "disk-B/span")
			b.ReportMetric(float64(len(recs))*float64(b.N)/b.Elapsed().Seconds(), "spans/s")
		})
	}
}

// benchStore returns a store holding the benchmark spans in blocks of
// 25,000 spans, and the trace IDs.
func benchStore(b *testing.B, format string) (*Store, []store.TraceID) {
	b.Helper()
	spans := benchSpans(benchTraces)
	s := openT(b, b.TempDir(), Options{Format: format, MaxHeadSpans: 25_000})
	ctx := context.Background()
	for i := 0; i < len(spans); i += 1000 {
		if err := s.WriteSpans(ctx, spans[i:i+1000]); err != nil {
			b.Fatal(err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		b.Fatal(err)
	}
	return s, traceIDs(spans)
}

func BenchmarkGetTrace(b *testing.B) {
	for _, name := range []string{FormatParquet, FormatSegment} {
		b.Run(name, func(b *testing.B) {
			s, ids := benchStore(b, name)
			ctx := context.Background()
			r := rand.New(rand.NewSource(1)) //nolint:gosec // G404: benchmark data
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got, err := s.GetTrace(ctx, ids[r.Intn(len(ids))])
				if err != nil || len(got) != 8 {
					b.Fatalf("got %d spans, %v", len(got), err)
				}
			}
		})
	}
}

func BenchmarkGetTraceMissing(b *testing.B) {
	for _, name := range []string{FormatParquet, FormatSegment} {
		b.Run(name, func(b *testing.B) {
			s, _ := benchStore(b, name)
			ctx := context.Background()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var id store.TraceID
				copy(id[:], fmt.Sprintf("missing-%08d", i))
				if _, err := s.GetTrace(ctx, id); err == nil {
					b.Fatal("found a missing trace")
				}
			}
		})
	}
}

func BenchmarkFindTraces(b *testing.B) {
	for _, name := range []string{FormatParquet, FormatSegment} {
		b.Run(name, func(b *testing.B) {
			s, _ := benchStore(b, name)
			ctx := context.Background()
			// One minute holds 6,000 traces, and every trace has a checkout
			// span, so each query summarises 6,000 traces to return 100.
			q := store.TraceQuery{Service: "checkout", Range: store.TimeRange{Start: storetest.T0.Add(30 * time.Second), End: storetest.T0.Add(90 * time.Second)}}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got, err := s.FindTraces(ctx, q)
				if err != nil || len(got) != store.DefaultLimit {
					b.Fatalf("got %d, %v", len(got), err)
				}
			}
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	for _, name := range []string{FormatParquet, FormatSegment} {
		b.Run(name, func(b *testing.B) {
			s, _ := benchStore(b, name)
			dir := s.dir
			_ = s.Close()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s2, err := Open(dir, Options{Format: name})
				if err != nil {
					b.Fatal(err)
				}
				_ = s2.Close()
			}
		})
	}
}

// BenchmarkWriteSpans measures accepted spans per second, each call synced to
// the log, in batches of 100 spans.
func BenchmarkWriteSpans(b *testing.B) {
	spans := benchSpans(1250)
	s := openT(b, b.TempDir(), Options{})
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := (i * 100) % len(spans)
		if err := s.WriteSpans(ctx, spans[j:j+100]); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N*100)/b.Elapsed().Seconds(), "spans/s")
}

// TestBenchmarkDataIsSane keeps the benchmark data honest in normal runs.
func TestBenchmarkDataIsSane(t *testing.T) {
	spans := benchSpans(10)
	if len(spans) != 80 || len(traceIDs(spans)) != 10 {
		t.Fatalf("%d spans in %d traces", len(spans), len(traceIDs(spans)))
	}
	for _, sp := range spans {
		if err := validate(sp); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(sp.Name, "GET /") {
			t.Fatalf("name %q", sp.Name)
		}
	}
}
