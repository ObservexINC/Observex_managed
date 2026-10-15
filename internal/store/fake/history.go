package fake

import (
	"context"
	"sort"

	"github.com/Voxmatic/observe/internal/platform/clock"
	"github.com/Voxmatic/observe/internal/store"
)

// HistoryStore is an in-memory, append-only store.HistoryStore.
type HistoryStore struct {
	lifecycle
	changes map[store.EntityID][]store.Change
}

var _ store.HistoryStore = (*HistoryStore)(nil)

// NewHistoryStore returns an empty HistoryStore.
func NewHistoryStore() *HistoryStore {
	return &HistoryStore{changes: map[store.EntityID][]store.Change{}}
}

func copyChange(c store.Change) store.Change {
	c.Attributes = copyMap(c.Attributes)
	c.Stamp = clock.Stamp{Valid: c.Stamp.Valid.UTC(), Record: c.Stamp.Record.UTC()}
	return c
}

// AppendChanges implements store.HistoryStore.
func (h *HistoryStore) AppendChanges(ctx context.Context, changes []store.Change) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.check(ctx); err != nil {
		return err
	}
	for _, c := range changes {
		if err := c.Validate(); err != nil {
			return err
		}
	}
	for _, c := range changes {
		h.changes[c.Entity] = append(h.changes[c.Entity], copyChange(c))
	}
	return nil
}

// Changes implements store.HistoryStore.
func (h *HistoryStore) Changes(ctx context.Context, q store.HistoryQuery) ([]store.Change, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if err := h.check(ctx); err != nil {
		return nil, err
	}
	if q.Entity == "" {
		return nil, store.Invalid("history query needs an entity")
	}
	if err := q.Range.Validate(); err != nil {
		return nil, err
	}
	switch q.View {
	case clock.AsItWas:
	case clock.AsKnownThen:
		if q.KnownAt.IsZero() {
			return nil, store.Invalid("as-known-then query needs KnownAt")
		}
	default:
		return nil, store.Invalid("unknown view %v", q.View)
	}
	out := []store.Change{}
	for _, c := range h.changes[q.Entity] {
		if !q.Range.Contains(c.Stamp.Valid) {
			continue
		}
		if q.View == clock.AsKnownThen && !c.Stamp.KnownAt(q.KnownAt) {
			continue
		}
		out = append(out, copyChange(c))
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Stamp, out[j].Stamp
		if !a.Valid.Equal(b.Valid) {
			return a.Valid.Before(b.Valid)
		}
		if !a.Record.Equal(b.Record) {
			return a.Record.Before(b.Record)
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}

// Close implements store.HistoryStore.
func (h *HistoryStore) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.close()
	return nil
}
