package cassandra

import (
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

func TestQAMetricOutsideStoredTimeRange(t *testing.T) {
	m := openReal(t)
	ctx := testCtx(t)
	sample := store.Sample{Series: store.Series{Name: "qa_range"}, Point: store.Point{Time: at(0), Value: 42}}
	if err := m.WriteSamples(ctx, []store.Sample{sample}); err != nil {
		t.Fatal(err)
	}
	for _, year := range []int{1500, 2400} {
		start := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
		got, err := m.QuerySeries(ctx, store.MetricQuery{Name: "qa_range", Range: store.TimeRange{Start: start, End: start.Add(time.Hour)}})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Errorf("range entirely in %d returned samples outside the requested range: %+v", year, got)
		}
	}
}

func TestQAMetricNULLabelValue(t *testing.T) {
	m := openReal(t)
	ctx := testCtx(t)
	sample := store.Sample{Series: store.Series{Name: "qa_nul", Labels: store.Labels{"path": "a\x00b"}}, Point: store.Point{Time: at(0), Value: 42}}
	if err := m.WriteSamples(ctx, []store.Sample{sample}); err != nil {
		t.Fatalf("valid UTF-8 label rejected: %v", err)
	}
	got, err := m.QuerySeries(ctx, store.MetricQuery{Name: "qa_nul", Matchers: []store.Matcher{{Label: "path", Value: "a\x00b"}}, Range: store.TimeRange{Start: at(-time.Second), End: at(time.Second)}})
	if err != nil || len(got) != 1 || len(got[0].Points) != 1 {
		t.Fatalf("round trip with NUL label: %+v, %v", got, err)
	}
}
