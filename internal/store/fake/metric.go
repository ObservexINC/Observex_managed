package fake

import (
	"context"
	"sort"
	"time"

	"github.com/Voxmatic/observe/internal/store"
)

type metricSeries struct {
	series store.Series
	points map[int64]float64 // unix nanoseconds -> value
}

// MetricStore is an in-memory store.MetricStore.
type MetricStore struct {
	lifecycle
	series map[string]*metricSeries
}

var _ store.MetricStore = (*MetricStore)(nil)

// NewMetricStore returns an empty MetricStore.
func NewMetricStore() *MetricStore {
	return &MetricStore{series: map[string]*metricSeries{}}
}

// WriteSamples implements store.MetricStore.
func (m *MetricStore) WriteSamples(ctx context.Context, samples []store.Sample) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check(ctx); err != nil {
		return err
	}
	for _, s := range samples {
		if err := s.Validate(); err != nil {
			return err
		}
	}
	for _, s := range samples {
		key := s.Series.Key()
		ser, ok := m.series[key]
		if !ok {
			ser = &metricSeries{
				series: store.Series{Name: s.Series.Name, Labels: copyMap(s.Series.Labels)},
				points: map[int64]float64{},
			}
			m.series[key] = ser
		}
		ser.points[s.Point.Time.UnixNano()] = s.Point.Value
	}
	return nil
}

// QuerySeries implements store.MetricStore.
func (m *MetricStore) QuerySeries(ctx context.Context, q store.MetricQuery) ([]store.SeriesPoints, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.check(ctx); err != nil {
		return nil, err
	}
	if q.Name == "" {
		return nil, store.Invalid("metric query needs a name")
	}
	if err := q.Range.Validate(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(m.series))
	for k := range m.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []store.SeriesPoints{}
	for _, k := range keys {
		ser := m.series[k]
		if ser.series.Name != q.Name || !matches(ser.series.Labels, q.Matchers) {
			continue
		}
		var pts []store.Point
		for ns, v := range ser.points {
			t := time.Unix(0, ns).UTC()
			if q.Range.Contains(t) {
				pts = append(pts, store.Point{Time: t, Value: v})
			}
		}
		if len(pts) == 0 {
			continue
		}
		sort.Slice(pts, func(i, j int) bool { return pts[i].Time.Before(pts[j].Time) })
		out = append(out, store.SeriesPoints{
			Series: store.Series{Name: ser.series.Name, Labels: copyMap(ser.series.Labels)},
			Points: pts,
		})
	}
	return out, nil
}

func matches(labels store.Labels, ms []store.Matcher) bool {
	for _, m := range ms {
		if labels[m.Label] != m.Value {
			return false
		}
	}
	return true
}

// Close implements store.MetricStore.
func (m *MetricStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.close()
	return nil
}
