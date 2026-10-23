package cassandra

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	mrand "math/rand"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	gocql "github.com/apache/cassandra-gocql-driver/v2"

	"github.com/ObservexINC/Observex_managed/internal/node/selfmon"
	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
	"github.com/ObservexINC/Observex_managed/internal/store"
	"github.com/ObservexINC/Observex_managed/internal/store/enginetest"
	"github.com/ObservexINC/Observex_managed/internal/store/fake"
	"github.com/ObservexINC/Observex_managed/internal/store/storetest"
)

func testCtx(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// openReal opens a MetricStore in a new keyspace on the test engine and
// drops the keyspace when the test ends.
func openReal(t testing.TB) *MetricStore {
	t.Helper()
	hosts := strings.Split(enginetest.Address(t, enginetest.Cassandra), ",")
	user, password := enginetest.Credentials(enginetest.CassandraUsername, enginetest.CassandraPassword)
	var b [6]byte
	_, _ = rand.Read(b[:])
	m, err := OpenMetricStore(testCtx(t), Config{
		Hosts: hosts, Keyspace: "oxtest_" + hex.EncodeToString(b[:]),
		Username: user, Password: password, CreateSchema: true,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		// The contract suite closes stores itself; drop through a fresh one.
		cleanup, err := OpenMetricStore(context.Background(), Config{Hosts: hosts, Keyspace: m.ks, Username: user, Password: password})
		if err == nil {
			_ = cleanup.DropKeyspace(context.Background())
			_ = cleanup.Close()
		}
		_ = m.Close()
	})
	return m
}

func TestContract(t *testing.T) {
	enginetest.Address(t, enginetest.Cassandra)
	storetest.MetricStore(t, func(t *testing.T) store.MetricStore { return openReal(t) })
}

func at(d time.Duration) time.Time { return storetest.T0.Add(d) }

// TestMatchesFake writes the same random samples to Cassandra and the fake,
// over several days, with label values that need escaping, and compares
// queries.
func TestMatchesFake(t *testing.T) {
	m := openReal(t)
	f := fake.NewMetricStore()
	ctx := testCtx(t)
	r := mrand.New(mrand.NewSource(7)) //nolint:gosec // G404: test data
	var samples []store.Sample
	for i := 0; i < 3000; i++ {
		s := store.Series{Name: fmt.Sprintf("m%d", r.Intn(3)), Labels: store.Labels{
			"host": fmt.Sprintf("node-%d", r.Intn(4)), "path": []string{`/a"b`, `c\d`, "e\nf", "plain", "ü"}[r.Intn(5)],
		}}
		if r.Intn(5) == 0 {
			delete(s.Labels, "path")
		}
		samples = append(samples, store.Sample{Series: s, Point: store.Point{
			Time:  at(time.Duration(r.Int63n(int64(72 * time.Hour)))).Add(time.Duration(r.Intn(1000))), // nanoseconds matter
			Value: r.NormFloat64(),
		}})
	}
	for i := 0; i < len(samples); i += 500 {
		for _, st := range []store.MetricStore{m, f} {
			if err := st.WriteSamples(ctx, samples[i:i+500]); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, q := range []store.MetricQuery{
		{Name: "m0", Range: store.TimeRange{Start: storetest.T0, End: at(72 * time.Hour)}},
		{Name: "m1", Range: store.TimeRange{Start: at(20 * time.Hour), End: at(50 * time.Hour)}, Matchers: []store.Matcher{{Label: "host", Value: "node-2"}}},
		{Name: "m2", Range: store.TimeRange{Start: storetest.T0, End: at(100 * 365 * 24 * time.Hour)}, Matchers: []store.Matcher{{Label: "path", Value: ""}}},
		{Name: "m2", Range: store.TimeRange{Start: storetest.T0, End: at(time.Hour)}, Matchers: []store.Matcher{{Label: "path", Value: `/a"b`}}},
		{Name: "none", Range: store.TimeRange{Start: storetest.T0, End: at(time.Hour)}},
	} {
		got, err := m.QuerySeries(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := f.QuerySeries(ctx, q)
		if len(got) != len(want) {
			t.Fatalf("query %+v: %d series, fake %d", q, len(got), len(want))
		}
		for i := range got {
			if got[i].Series.Key() != want[i].Series.Key() || !reflect.DeepEqual(got[i].Points, want[i].Points) {
				t.Fatalf("query %+v series %d differs:\n got %s %d points\nwant %s %d points", q, i, got[i].Series.Key(), len(got[i].Points), want[i].Series.Key(), len(want[i].Points))
			}
		}
	}
}

func TestLargeLabelsAndBatches(t *testing.T) {
	m := openReal(t)
	ctx := testCtx(t)
	long := strings.Repeat("x", 30_000) // one point per batch for this series
	s := store.Series{Name: "big", Labels: store.Labels{"blob": long}}
	var samples []store.Sample
	for i := 0; i < 2000; i++ {
		samples = append(samples, store.Sample{Series: s, Point: store.Point{Time: at(time.Duration(i) * time.Second), Value: float64(i)}})
	}
	if err := m.WriteSamples(ctx, samples); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := m.QuerySeries(ctx, store.MetricQuery{Name: "big", Range: store.TimeRange{Start: storetest.T0, End: at(time.Hour)}})
	if err != nil || len(got) != 1 || len(got[0].Points) != 2000 || got[0].Series.Labels["blob"] != long {
		t.Fatalf("got %d series, err %v", len(got), err)
	}
}

func TestExtremeTimesAndPrecision(t *testing.T) {
	m := openReal(t)
	ctx := testCtx(t)
	s := store.Series{Name: "edge"}
	times := []time.Time{minTime, time.Date(1900, 1, 1, 0, 0, 0, 1, time.UTC), time.Unix(0, -1).UTC(), time.Unix(0, 0).UTC(), at(1), at(2), maxTime}
	var samples []store.Sample
	for i, tm := range times {
		samples = append(samples, store.Sample{Series: s, Point: store.Point{Time: tm, Value: float64(i)}})
	}
	if err := m.WriteSamples(ctx, samples); err != nil {
		t.Fatal(err)
	}
	all := store.TimeRange{Start: time.Date(1, 1, 2, 0, 0, 0, 0, time.UTC), End: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)} // year 1, day 1 is the zero time
	got, err := m.QuerySeries(ctx, store.MetricQuery{Name: "edge", Range: all})
	if err != nil || len(got) != 1 || len(got[0].Points) != len(times) {
		t.Fatalf("got %+v, %v", got, err)
	}
	for i, p := range got[0].Points {
		if !p.Time.Equal(times[i]) || p.Value != float64(i) {
			t.Fatalf("point %d = %+v, want %v", i, p, times[i])
		}
	}
	bad := store.Sample{Series: s, Point: store.Point{Time: time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC), Value: 1}}
	if err := m.WriteSamples(ctx, []store.Sample{bad}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("time before 1678: %v", err)
	}
	badLabel := store.Sample{Series: store.Series{Name: "edge", Labels: store.Labels{"k": "\xff"}}, Point: store.Point{Time: at(1), Value: 1}}
	if err := m.WriteSamples(ctx, []store.Sample{samples[0], badLabel}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("label that is not UTF-8: %v", err)
	}
}

func TestConcurrentWriters(t *testing.T) {
	m := openReal(t)
	ctx := testCtx(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			var samples []store.Sample
			for i := 0; i < 250; i++ {
				samples = append(samples, store.Sample{
					Series: store.Series{Name: "conc", Labels: store.Labels{"writer": fmt.Sprint(w)}},
					Point:  store.Point{Time: at(time.Duration(i) * time.Millisecond), Value: float64(i)},
				})
			}
			errs <- m.WriteSamples(ctx, samples)
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := m.QuerySeries(ctx, store.MetricQuery{Name: "conc", Range: store.TimeRange{Start: storetest.T0, End: at(time.Hour)}})
	if err != nil || len(got) != 8 {
		t.Fatalf("got %d series, %v", len(got), err)
	}
	for _, s := range got {
		if len(s.Points) != 250 {
			t.Fatalf("series %s has %d points", s.Series.Key(), len(s.Points))
		}
	}
}

func TestCancelledQuery(t *testing.T) {
	m := openReal(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.QuerySeries(ctx, store.MetricQuery{Name: "x", Range: store.TimeRange{Start: storetest.T0, End: at(time.Hour)}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled query: %v", err)
	}
}

func TestSelfMonitoring(t *testing.T) {
	m := openReal(t)
	ctx := testCtx(t)
	_ = m.WriteSamples(ctx, []store.Sample{{Series: store.Series{Name: "x"}, Point: store.Point{Time: at(0), Value: 1}}})
	_, _ = m.QuerySeries(ctx, store.MetricQuery{Name: "x", Range: store.TimeRange{Start: storetest.T0, End: at(time.Hour)}})
	var r selfmon.Registry
	r.Register(m)
	var out bytes.Buffer
	if err := selfmon.WriteText(&out, r.Gather()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"observex_metricstore_up 1", "observex_metricstore_samples_written_total 1", "observex_metricstore_queries_total 1", "observex_metricstore_write_errors_total 0"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("metrics lack %q:\n%s", want, out.String())
		}
	}
}

// --- No engine needed below. -------------------------------------------

func TestConfigValidation(t *testing.T) {
	ctx := testCtx(t)
	if _, err := OpenMetricStore(ctx, Config{Keyspace: "ok"}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("no hosts: %v", err)
	}
	for _, ks := range []string{"", "1abc", "a-b", "a b", strings.Repeat("a", 49), "x;DROP"} {
		if _, err := OpenMetricStore(ctx, Config{Hosts: []string{"127.0.0.1"}, Keyspace: ks}); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("keyspace %q: %v", ks, err)
		}
	}
}

func TestPasswordNeverLogged(t *testing.T) {
	const pw = "ZZcassandraPWmarkerZZ"
	var buf bytes.Buffer
	l := logging.New(&buf, slog.LevelDebug)
	c := Config{Hosts: []string{"db-1:9042"}, Keyspace: "observex", Username: "observex", Password: logging.Secret(pw)}
	l.Info("connecting", "config", c)
	l.Info("connecting", slog.Any("cfg", c), "password", c.Password)
	slogLogger{l: l}.Error("driver says", gocqlField("password", pw))
	fmt.Fprintf(&buf, "%v %+v", c, c)
	if strings.Contains(buf.String(), pw) || strings.Contains(buf.String(), pw[:12]) {
		t.Fatalf("password reached the output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "db-1:9042") {
		t.Fatalf("configuration not logged:\n%s", buf.String())
	}
}

func TestDays(t *testing.T) {
	for _, c := range []struct {
		t    int64
		want int
	}{{0, 0}, {nanosPerDay - 1, 0}, {nanosPerDay, 1}, {-1, -1}, {-nanosPerDay, -1}, {-nanosPerDay - 1, -2}, {math.MinInt64, int(math.MinInt64/nanosPerDay) - 1}, {math.MaxInt64, int(math.MaxInt64 / nanosPerDay)}} {
		if got := dayOf(c.t); got != c.want {
			t.Fatalf("dayOf(%d) = %d, want %d", c.t, got, c.want)
		}
	}
	first, again := shardOf("a"), shardOf("a")
	if first != again || first < 0 || first >= seriesShards {
		t.Fatal("shardOf is not a stable shard")
	}
}

func gocqlField(name, value string) gocql.LogField { return gocql.NewLogFieldString(name, value) }
