// Package store defines the read and write contracts for every ObserveX data
// store (decision D1). Modules depend only on these interfaces, never on an
// engine, so an engine can change without touching ingestion or queries.
//
// Each interface has an in-memory fake in internal/store/fake and a shared
// contract suite in internal/store/storetest. A real adapter is accepted only
// when it passes the same suite as its fake. See
// docs/adr/0004-store-interfaces.md.
package store

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrNotFound is returned when a requested item does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when a compare-and-set or version check fails.
	ErrConflict = errors.New("store: conflict")
	// ErrInvalid is returned for arguments that break the contract.
	ErrInvalid = errors.New("store: invalid argument")
	// ErrClosed is returned by every method after Close.
	ErrClosed = errors.New("store: closed")
)

// Invalid wraps ErrInvalid with a reason.
func Invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// TimeRange is the half-open interval [Start, End).
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// Validate reports whether the range is usable: both ends set and Start
// strictly before End.
func (r TimeRange) Validate() error {
	if r.Start.IsZero() || r.End.IsZero() {
		return Invalid("time range needs a start and an end")
	}
	if !r.Start.Before(r.End) {
		return Invalid("time range start %v is not before end %v", r.Start, r.End)
	}
	return nil
}

// Contains reports whether t falls inside the range.
func (r TimeRange) Contains(t time.Time) bool {
	return !t.Before(r.Start) && t.Before(r.End)
}

// Limits shared by search and trace queries.
const (
	DefaultLimit = 100
	MaxLimit     = 10000
)

// NormaliseLimit applies the default and rejects limits above MaxLimit.
func NormaliseLimit(n int) (int, error) {
	switch {
	case n < 0:
		return 0, Invalid("limit %d is negative", n)
	case n == 0:
		return DefaultLimit, nil
	case n > MaxLimit:
		return 0, Invalid("limit %d is above %d", n, MaxLimit)
	default:
		return n, nil
	}
}
