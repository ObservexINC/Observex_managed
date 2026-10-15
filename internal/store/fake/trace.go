package fake

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// TraceStore is an in-memory store.TraceStore.
type TraceStore struct {
	lifecycle
	traces map[store.TraceID]map[store.SpanID]store.Span
}

var _ store.TraceStore = (*TraceStore)(nil)

// NewTraceStore returns an empty TraceStore.
func NewTraceStore() *TraceStore {
	return &TraceStore{traces: map[store.TraceID]map[store.SpanID]store.Span{}}
}

func copySpan(s store.Span) store.Span {
	s.Start = s.Start.UTC()
	s.End = s.End.UTC()
	s.Attributes = copyMap(s.Attributes)
	return s
}

// WriteSpans implements store.TraceStore.
func (t *TraceStore) WriteSpans(ctx context.Context, spans []store.Span) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.check(ctx); err != nil {
		return err
	}
	for _, s := range spans {
		if err := s.Validate(); err != nil {
			return err
		}
	}
	for _, s := range spans {
		tr, ok := t.traces[s.TraceID]
		if !ok {
			tr = map[store.SpanID]store.Span{}
			t.traces[s.TraceID] = tr
		}
		tr[s.SpanID] = copySpan(s)
	}
	return nil
}

func sortedSpans(tr map[store.SpanID]store.Span) []store.Span {
	out := make([]store.Span, 0, len(tr))
	for _, s := range tr {
		out = append(out, copySpan(s))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Start.Equal(out[j].Start) {
			return out[i].Start.Before(out[j].Start)
		}
		return bytes.Compare(out[i].SpanID[:], out[j].SpanID[:]) < 0
	})
	return out
}

// GetTrace implements store.TraceStore.
func (t *TraceStore) GetTrace(ctx context.Context, id store.TraceID) ([]store.Span, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if err := t.check(ctx); err != nil {
		return nil, err
	}
	tr, ok := t.traces[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return sortedSpans(tr), nil
}

// FindTraces implements store.TraceStore.
func (t *TraceStore) FindTraces(ctx context.Context, q store.TraceQuery) ([]store.TraceSummary, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if err := t.check(ctx); err != nil {
		return nil, err
	}
	if q.Service == "" {
		return nil, store.Invalid("trace query needs a service")
	}
	if err := q.Range.Validate(); err != nil {
		return nil, err
	}
	limit, err := store.NormaliseLimit(q.Limit)
	if err != nil {
		return nil, err
	}
	out := []store.TraceSummary{}
	for id, tr := range t.traces {
		hit := false
		for _, s := range tr {
			if s.Service == q.Service && q.Range.Contains(s.Start) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		sum := summarise(id, sortedSpans(tr))
		if q.ErrorsOnly && !sum.Error {
			continue
		}
		out = append(out, sum)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Start.Equal(out[j].Start) {
			return out[i].Start.After(out[j].Start)
		}
		return bytes.Compare(out[i].TraceID[:], out[j].TraceID[:]) < 0
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func summarise(id store.TraceID, spans []store.Span) store.TraceSummary {
	sum := store.TraceSummary{TraceID: id, SpanCount: len(spans)}
	var end time.Time
	services := map[string]bool{}
	for i, s := range spans {
		if i == 0 || s.Start.Before(sum.Start) {
			sum.Start = s.Start
		}
		if s.End.After(end) {
			end = s.End
		}
		if s.Error {
			sum.Error = true
		}
		services[s.Service] = true
	}
	sum.Duration = end.Sub(sum.Start)
	for svc := range services {
		sum.Services = append(sum.Services, svc)
	}
	sort.Strings(sum.Services)
	return sum
}

// Close implements store.TraceStore.
func (t *TraceStore) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.close()
	return nil
}
