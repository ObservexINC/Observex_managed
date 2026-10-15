// Package clock provides time sources and the two-clock stamp that ObserveX
// puts on every recorded change.
//
// Valid time is when something was true in the monitored system. Record time
// is when ObserveX learned it. Agents buffer data on disk when links drop, so
// record time is often later than valid time. Keeping both lets the product
// answer two different questions: "what happened" (as it was) and "what could
// we have seen at that moment" (as known then). See docs/adr/0006-two-clocks.md.
package clock

import (
	"errors"
	"sync"
	"time"
)

// Clock returns the current time. All production code takes a Clock instead of
// calling time.Now, so tests can control time.
type Clock interface {
	Now() time.Time
}

// Real is the system clock. It always returns UTC.
type Real struct{}

// Now returns the current UTC time.
func (Real) Now() time.Time { return time.Now().UTC() }

// Fake is a manually controlled clock for tests. It is safe for concurrent use.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a Fake set to t.
func NewFake(t time.Time) *Fake { return &Fake{now: t.UTC()} }

// Now returns the fake's current time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the fake clock forward by d. A negative d moves it back, which
// tests use to simulate clock skew.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// Set moves the fake clock to t.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t.UTC()
}

// View selects which clock a reader uses when looking at the past.
type View int

const (
	// AsItWas shows everything that was true at a moment, including facts that
	// ObserveX only learned later.
	AsItWas View = iota
	// AsKnownThen shows only what was true at a moment and already recorded by
	// ObserveX at that moment.
	AsKnownThen
)

// String returns a readable name for the view.
func (v View) String() string {
	switch v {
	case AsItWas:
		return "as-it-was"
	case AsKnownThen:
		return "as-known-then"
	default:
		return "unknown-view"
	}
}

// ErrZeroStamp is returned when a stamp is missing one of its times.
var ErrZeroStamp = errors.New("clock: stamp needs both valid time and record time")

// Stamp carries both clocks for one recorded change.
type Stamp struct {
	// Valid is when the change happened in the monitored system.
	Valid time.Time
	// Record is when ObserveX recorded the change.
	Record time.Time
}

// NewStamp stamps a change that happened at valid, recorded now by c.
func NewStamp(valid time.Time, c Clock) Stamp {
	return Stamp{Valid: valid.UTC(), Record: c.Now().UTC()}
}

// Validate reports whether both times are set.
func (s Stamp) Validate() error {
	if s.Valid.IsZero() || s.Record.IsZero() {
		return ErrZeroStamp
	}
	return nil
}

// Lag is how long after the change ObserveX recorded it. It is negative when
// the source's clock runs ahead of the cluster's.
func (s Stamp) Lag() time.Duration { return s.Record.Sub(s.Valid) }

// TrueAt reports whether the change had happened by t.
func (s Stamp) TrueAt(t time.Time) bool { return !s.Valid.After(t) }

// KnownAt reports whether ObserveX had recorded the change by t.
func (s Stamp) KnownAt(t time.Time) bool { return !s.Record.After(t) }

// Visible reports whether a reader looking at moment t through view v sees the
// change.
func (s Stamp) Visible(t time.Time, v View) bool {
	switch v {
	case AsItWas:
		return s.TrueAt(t)
	case AsKnownThen:
		return s.TrueAt(t) && s.KnownAt(t)
	default:
		return false
	}
}
