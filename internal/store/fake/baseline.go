package fake

import (
	"bytes"
	"context"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// BaselineStore is an in-memory store.BaselineStore.
type BaselineStore struct {
	lifecycle
	latest map[string]store.Baseline
}

var _ store.BaselineStore = (*BaselineStore)(nil)

// NewBaselineStore returns an empty BaselineStore.
func NewBaselineStore() *BaselineStore {
	return &BaselineStore{latest: map[string]store.Baseline{}}
}

func copyBaseline(b store.Baseline) store.Baseline {
	b.Data = bytes.Clone(b.Data)
	b.Computed = b.Computed.UTC()
	return b
}

// PutBaseline implements store.BaselineStore.
func (s *BaselineStore) PutBaseline(ctx context.Context, b store.Baseline) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx); err != nil {
		return err
	}
	if err := b.Validate(); err != nil {
		return err
	}
	if cur, ok := s.latest[b.SeriesKey]; ok && b.Version <= cur.Version {
		return store.ErrConflict
	}
	s.latest[b.SeriesKey] = copyBaseline(b)
	return nil
}

// GetBaseline implements store.BaselineStore.
func (s *BaselineStore) GetBaseline(ctx context.Context, seriesKey string) (store.Baseline, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.check(ctx); err != nil {
		return store.Baseline{}, err
	}
	b, ok := s.latest[seriesKey]
	if !ok {
		return store.Baseline{}, store.ErrNotFound
	}
	return copyBaseline(b), nil
}

// Close implements store.BaselineStore.
func (s *BaselineStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.close()
	return nil
}
