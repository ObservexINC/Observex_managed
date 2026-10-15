package store

import (
	"context"
	"encoding/hex"
	"time"
)

// TraceID is a W3C trace ID.
type TraceID [16]byte

// SpanID is a W3C span ID.
type SpanID [8]byte

// IsZero reports whether the ID is all zeros, which W3C treats as invalid.
func (id TraceID) IsZero() bool { return id == TraceID{} }

// IsZero reports whether the ID is all zeros.
func (id SpanID) IsZero() bool { return id == SpanID{} }

// String returns the lowercase hex form.
func (id TraceID) String() string { return hex.EncodeToString(id[:]) }

// String returns the lowercase hex form.
func (id SpanID) String() string { return hex.EncodeToString(id[:]) }

// ParseTraceID parses 32 hex characters. The all-zero ID is rejected.
func ParseTraceID(s string) (TraceID, error) {
	var id TraceID
	if len(s) != 2*len(id) {
		return id, Invalid("trace ID must be %d hex characters", 2*len(id))
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return TraceID{}, Invalid("trace ID is not hex")
	}
	if id.IsZero() {
		return id, Invalid("trace ID is all zeros")
	}
	return id, nil
}

// Span is one operation within a trace.
type Span struct {
	TraceID    TraceID
	SpanID     SpanID
	ParentID   SpanID // zero for a root span
	Service    string
	Name       string
	Start      time.Time
	End        time.Time
	Error      bool
	Attributes map[string]string
}

// Validate checks IDs, names and times.
func (s Span) Validate() error {
	switch {
	case s.TraceID.IsZero():
		return Invalid("span has no trace ID")
	case s.SpanID.IsZero():
		return Invalid("span in trace %s has no span ID", s.TraceID)
	case s.Service == "":
		return Invalid("span %s has no service", s.SpanID)
	case s.Start.IsZero() || s.End.IsZero():
		return Invalid("span %s needs a start and an end", s.SpanID)
	case s.End.Before(s.Start):
		return Invalid("span %s ends before it starts", s.SpanID)
	}
	return nil
}

// TraceQuery finds traces that have at least one span from Service whose
// start falls in Range.
type TraceQuery struct {
	Service    string
	Range      TimeRange
	ErrorsOnly bool
	Limit      int
}

// TraceSummary describes one trace in search results.
type TraceSummary struct {
	TraceID   TraceID
	Start     time.Time // earliest span start
	Duration  time.Duration
	SpanCount int
	Error     bool // any span has an error
	Services  []string
}

// TraceStore is the TraceStore contract. The real store keeps one copy per
// node (IMP-2); the contract does not promise durability across node loss.
//
//   - WriteSpans writes all spans or none; a span with the same trace and span
//     ID replaces the earlier one.
//   - GetTrace returns spans sorted by start, then span ID, or ErrNotFound.
//   - FindTraces returns newest first by trace start, at most Limit.
type TraceStore interface {
	WriteSpans(ctx context.Context, spans []Span) error
	GetTrace(ctx context.Context, id TraceID) ([]Span, error)
	FindTraces(ctx context.Context, q TraceQuery) ([]TraceSummary, error)
	Close() error
}
