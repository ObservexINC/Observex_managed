package store

import (
	"context"
	"time"
)

// Baseline is a computed model of normal behaviour for one series. Data is
// opaque to the store; the Baselines module defines its encoding.
type Baseline struct {
	SeriesKey string
	Version   int64
	Computed  time.Time
	Data      []byte
}

// Validate checks key, version and time.
func (b Baseline) Validate() error {
	switch {
	case b.SeriesKey == "":
		return Invalid("baseline has no series key")
	case b.Version <= 0:
		return Invalid("baseline for %q has version %d; versions start at 1", b.SeriesKey, b.Version)
	case b.Computed.IsZero():
		return Invalid("baseline for %q has no computed time", b.SeriesKey)
	}
	return nil
}

// BaselineStore is the BaselineStore contract. Baselines can always be
// rebuilt from metrics, so the store keeps only the latest version.
//
//   - PutBaseline succeeds only if Version is greater than the stored one;
//     otherwise ErrConflict.
//   - GetBaseline returns the latest version or ErrNotFound.
type BaselineStore interface {
	PutBaseline(ctx context.Context, b Baseline) error
	GetBaseline(ctx context.Context, seriesKey string) (Baseline, error)
	Close() error
}
