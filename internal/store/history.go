package store

import (
	"context"
	"time"

	"github.com/Voxmatic/observe/internal/platform/clock"
)

// EntityID identifies a monitored entity: a host, process, service, pod,
// database, journey and so on.
type EntityID string

// Change is one recorded change to an entity, stamped with both clocks.
type Change struct {
	Entity EntityID
	// Kind says what changed, such as "created", "deleted", "config",
	// "version" or "relation".
	Kind       string
	Attributes map[string]string
	Stamp      clock.Stamp
}

// Validate checks the entity, kind and both clocks.
func (c Change) Validate() error {
	if c.Entity == "" {
		return Invalid("change has no entity")
	}
	if c.Kind == "" {
		return Invalid("change to %q has no kind", c.Entity)
	}
	if err := c.Stamp.Validate(); err != nil {
		return Invalid("change to %q: %v", c.Entity, err)
	}
	return nil
}

// HistoryQuery selects changes to one entity whose valid time falls in Range.
type HistoryQuery struct {
	Entity EntityID
	Range  TimeRange
	// View AsItWas returns every change whose valid time is in Range.
	// View AsKnownThen also requires the change to have been recorded by
	// KnownAt, which shows what a person looking at KnownAt could have seen.
	View clock.View
	// KnownAt is required for AsKnownThen and ignored for AsItWas.
	KnownAt time.Time
}

// HistoryStore is the append-only store behind System History (the
// EntityStore's change log).
//
//   - AppendChanges writes all changes or none. Changes are never updated or
//     deleted through this interface.
//   - Changes returns matching changes sorted by valid time, then record time,
//     then kind.
type HistoryStore interface {
	AppendChanges(ctx context.Context, changes []Change) error
	Changes(ctx context.Context, q HistoryQuery) ([]Change, error)
	Close() error
}
