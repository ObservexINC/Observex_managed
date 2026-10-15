package fake

import (
	"context"
	"sort"
	"strings"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// SearchStore is an in-memory store.SearchStore.
type SearchStore struct {
	lifecycle
	indexes map[string]map[string]store.Document
}

var _ store.SearchStore = (*SearchStore)(nil)

// NewSearchStore returns an empty SearchStore.
func NewSearchStore() *SearchStore {
	return &SearchStore{indexes: map[string]map[string]store.Document{}}
}

func copyDoc(d store.Document) store.Document {
	d.Time = d.Time.UTC()
	d.Fields = copyMap(d.Fields)
	return d
}

// Index implements store.SearchStore.
func (s *SearchStore) Index(ctx context.Context, index string, docs []store.Document) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx); err != nil {
		return err
	}
	if index == "" {
		return store.Invalid("index name is empty")
	}
	for _, d := range docs {
		if err := d.Validate(); err != nil {
			return err
		}
	}
	idx, ok := s.indexes[index]
	if !ok {
		idx = map[string]store.Document{}
		s.indexes[index] = idx
	}
	for _, d := range docs {
		idx[d.ID] = copyDoc(d)
	}
	return nil
}

// Search implements store.SearchStore.
func (s *SearchStore) Search(ctx context.Context, q store.SearchQuery) ([]store.Document, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	if q.Index == "" {
		return nil, store.Invalid("search needs an index")
	}
	if err := q.Range.Validate(); err != nil {
		return nil, err
	}
	limit, err := store.NormaliseLimit(q.Limit)
	if err != nil {
		return nil, err
	}
	terms := strings.Fields(strings.ToLower(q.Text))
	out := []store.Document{}
	for _, d := range s.indexes[q.Index] {
		if !q.Range.Contains(d.Time) || !hasFields(d.Fields, q.Filters) || !hasTerms(d.Body, terms) {
			continue
		}
		out = append(out, copyDoc(d))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Time.Equal(out[j].Time) {
			return out[i].Time.After(out[j].Time)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func hasFields(fields, want map[string]string) bool {
	for k, v := range want {
		if got, ok := fields[k]; !ok || got != v {
			return false
		}
	}
	return true
}

func hasTerms(body string, terms []string) bool {
	if len(terms) == 0 {
		return true
	}
	lower := strings.ToLower(body)
	for _, t := range terms {
		if !strings.Contains(lower, t) {
			return false
		}
	}
	return true
}

// Close implements store.SearchStore.
func (s *SearchStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.close()
	return nil
}
