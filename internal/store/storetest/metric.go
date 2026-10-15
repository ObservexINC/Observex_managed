package storetest

import (
	"math"
	"testing"
	"time"

	"github.com/Voxmatic/observe/internal/store"
)

// MetricStore runs the MetricStore contract against stores from open.
func MetricStore(t *testing.T, open func(t *testing.T) store.MetricStore) {
	checkout := store.Series{Name: "http_requests_total", Labels: store.Labels{"service": "checkout", "code": "200"}}
	errs := store.Series{Name: "http_requests_total", Labels: store.Labels{"service": "checkout", "code": "500"}}
	cart := store.Series{Name: "http_requests_total", Labels: store.Labels{"service": "cart", "code": "200"}}
	cpu := store.Series{Name: "cpu_utilisation", Labels: store.Labels{"host": "node-1"}}
	at := func(min int) time.Time { return T0.Add(time.Duration(min) * time.Minute) }
	sample := func(s store.Series, min int, v float64) store.Sample {
		return store.Sample{Series: s, Point: store.Point{Time: at(min), Value: v}}
	}

	t.Run("write then query returns sorted series and points", func(t *testing.T) {
		m := open(t)
		noErr(t, "write", m.WriteSamples(ctx(t), []store.Sample{
			sample(errs, 3, 2), sample(checkout, 2, 20), sample(checkout, 1, 10), sample(cart, 1, 5), sample(cpu, 1, 0.5),
		}))
		got, err := m.QuerySeries(ctx(t), store.MetricQuery{Name: "http_requests_total", Range: hour()})
		noErr(t, "query", err)
		if len(got) != 3 {
			t.Fatalf("got %d series, want 3", len(got))
		}
		for i := 1; i < len(got); i++ {
			if got[i-1].Series.Key() >= got[i].Series.Key() {
				t.Fatalf("series not sorted by key: %s then %s", got[i-1].Series.Key(), got[i].Series.Key())
			}
		}
		var cs store.SeriesPoints
		for _, s := range got {
			if s.Series.Key() == checkout.Key() {
				cs = s
			}
		}
		if len(cs.Points) != 2 || !cs.Points[0].Time.Equal(at(1)) || cs.Points[1].Value != 20 {
			t.Fatalf("checkout points = %+v", cs.Points)
		}
	})

	t.Run("matchers select by label equality", func(t *testing.T) {
		m := open(t)
		noErr(t, "write", m.WriteSamples(ctx(t), []store.Sample{sample(checkout, 1, 1), sample(errs, 1, 1), sample(cart, 1, 1)}))
		got, err := m.QuerySeries(ctx(t), store.MetricQuery{
			Name: "http_requests_total", Range: hour(),
			Matchers: []store.Matcher{{Label: "service", Value: "checkout"}, {Label: "code", Value: "500"}},
		})
		noErr(t, "query", err)
		if len(got) != 1 || got[0].Series.Key() != errs.Key() {
			t.Fatalf("got %+v, want only the 500 series", got)
		}
	})

	t.Run("range is half-open", func(t *testing.T) {
		m := open(t)
		noErr(t, "write", m.WriteSamples(ctx(t), []store.Sample{sample(cpu, 0, 1), sample(cpu, 59, 2), sample(cpu, 60, 3), sample(cpu, -1, 4)}))
		got, err := m.QuerySeries(ctx(t), store.MetricQuery{Name: "cpu_utilisation", Range: hour()})
		noErr(t, "query", err)
		if len(got) != 1 || len(got[0].Points) != 2 || got[0].Points[0].Value != 1 || got[0].Points[1].Value != 2 {
			t.Fatalf("got %+v, want points at minute 0 and 59 only", got)
		}
	})

	t.Run("same series and time replaces the value", func(t *testing.T) {
		m := open(t)
		noErr(t, "write 1", m.WriteSamples(ctx(t), []store.Sample{sample(cpu, 5, 1)}))
		noErr(t, "write 2", m.WriteSamples(ctx(t), []store.Sample{sample(cpu, 5, 9)}))
		got, err := m.QuerySeries(ctx(t), store.MetricQuery{Name: "cpu_utilisation", Range: hour()})
		noErr(t, "query", err)
		if len(got) != 1 || len(got[0].Points) != 1 || got[0].Points[0].Value != 9 {
			t.Fatalf("got %+v, want one point with value 9", got)
		}
	})

	t.Run("label order does not create a second series", func(t *testing.T) {
		m := open(t)
		a := store.Series{Name: "q", Labels: store.Labels{"a": "1", "b": "2"}}
		b := store.Series{Name: "q", Labels: store.Labels{"b": "2", "a": "1"}}
		noErr(t, "write", m.WriteSamples(ctx(t), []store.Sample{sample(a, 1, 1), sample(b, 2, 2)}))
		got, err := m.QuerySeries(ctx(t), store.MetricQuery{Name: "q", Range: hour()})
		noErr(t, "query", err)
		if len(got) != 1 || len(got[0].Points) != 2 {
			t.Fatalf("got %+v, want one series with two points", got)
		}
	})

	t.Run("invalid batch writes nothing", func(t *testing.T) {
		m := open(t)
		err := m.WriteSamples(ctx(t), []store.Sample{sample(cpu, 1, 1), sample(cpu, 2, math.NaN())})
		wantErr(t, "write", err, store.ErrInvalid)
		got, err := m.QuerySeries(ctx(t), store.MetricQuery{Name: "cpu_utilisation", Range: hour()})
		noErr(t, "query", err)
		if len(got) != 0 {
			t.Fatalf("partial write happened: %+v", got)
		}
	})

	t.Run("no match is empty, not an error", func(t *testing.T) {
		m := open(t)
		got, err := m.QuerySeries(ctx(t), store.MetricQuery{Name: "nothing", Range: hour()})
		noErr(t, "query", err)
		if got == nil || len(got) != 0 {
			t.Fatalf("got %#v, want empty non-nil slice", got)
		}
	})

	t.Run("invalid queries are rejected", func(t *testing.T) {
		m := open(t)
		_, err := m.QuerySeries(ctx(t), store.MetricQuery{Name: "cpu_utilisation"})
		wantErr(t, "no range", err, store.ErrInvalid)
		_, err = m.QuerySeries(ctx(t), store.MetricQuery{Range: hour()})
		wantErr(t, "no name", err, store.ErrInvalid)
	})

	t.Run("returned data is a copy", func(t *testing.T) {
		m := open(t)
		labels := store.Labels{"host": "node-1"}
		noErr(t, "write", m.WriteSamples(ctx(t), []store.Sample{{Series: store.Series{Name: "mem", Labels: labels}, Point: store.Point{Time: at(1), Value: 1}}}))
		labels["host"] = "changed-after-write"
		got, err := m.QuerySeries(ctx(t), store.MetricQuery{Name: "mem", Range: hour()})
		noErr(t, "query", err)
		got[0].Series.Labels["host"] = "changed-after-read"
		again, err := m.QuerySeries(ctx(t), store.MetricQuery{Name: "mem", Range: hour()})
		noErr(t, "query again", err)
		if again[0].Series.Labels["host"] != "node-1" {
			t.Fatalf("store data was changed through a caller's map: %v", again[0].Series.Labels)
		}
	})

	t.Run("cancelled context and closed store", func(t *testing.T) {
		m := open(t)
		if err := m.WriteSamples(cancelled(), []store.Sample{sample(cpu, 1, 1)}); err == nil {
			t.Fatal("write with cancelled context succeeded")
		}
		noErr(t, "close", m.Close())
		wantErr(t, "write after close", m.WriteSamples(ctx(t), []store.Sample{sample(cpu, 1, 1)}), store.ErrClosed)
		_, err := m.QuerySeries(ctx(t), store.MetricQuery{Name: "cpu_utilisation", Range: hour()})
		wantErr(t, "query after close", err, store.ErrClosed)
	})
}
