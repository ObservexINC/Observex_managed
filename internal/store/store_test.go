package store

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Voxmatic/observe/internal/platform/clock"
)

var t0 = time.Date(2026, 10, 17, 2, 0, 0, 0, time.UTC)

func TestTimeRange(t *testing.T) {
	r := TimeRange{Start: t0, End: t0.Add(time.Hour)}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if !r.Contains(t0) || r.Contains(t0.Add(time.Hour)) || r.Contains(t0.Add(-time.Nanosecond)) {
		t.Fatal("Contains is not half-open [Start, End)")
	}
	for _, bad := range []TimeRange{{}, {Start: t0}, {End: t0}, {Start: t0, End: t0}, {Start: t0.Add(time.Hour), End: t0}} {
		if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("Validate(%v) = %v, want ErrInvalid", bad, err)
		}
	}
}

func TestNormaliseLimit(t *testing.T) {
	cases := map[int]int{0: DefaultLimit, 1: 1, MaxLimit: MaxLimit}
	for in, want := range cases {
		if got, err := NormaliseLimit(in); err != nil || got != want {
			t.Errorf("NormaliseLimit(%d) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []int{-1, MaxLimit + 1} {
		if _, err := NormaliseLimit(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("NormaliseLimit(%d) err = %v", bad, err)
		}
	}
}

func TestSeriesKeyIsCanonical(t *testing.T) {
	a := Series{Name: "http_requests", Labels: Labels{"service": "checkout", "code": "500"}}
	b := Series{Name: "http_requests", Labels: Labels{"code": "500", "service": "checkout"}}
	if a.Key() != b.Key() {
		t.Fatalf("label order changed the key: %s vs %s", a.Key(), b.Key())
	}
	if want := `http_requests{code="500",service="checkout"}`; a.Key() != want {
		t.Fatalf("Key = %s, want %s", a.Key(), want)
	}
	// Quotes in values cannot forge a different label set.
	c := Series{Name: "m", Labels: Labels{"a": `x",b="y`}}
	d := Series{Name: "m", Labels: Labels{"a": "x", "b": "y"}}
	if c.Key() == d.Key() {
		t.Fatal("a quoted value produced the same key as two labels")
	}
	e := Series{Name: "m", Labels: Labels{"a": `x\`, "b": "y"}}
	f := Series{Name: "m", Labels: Labels{"a": `x\",b=\"y`}}
	if e.Key() == f.Key() || e.Key() == c.Key() {
		t.Fatal("backslashes in values produced a colliding key")
	}
	if (Series{Name: "up"}).Key() != "up{}" {
		t.Fatal("key without labels")
	}
}

func TestSampleValidate(t *testing.T) {
	ok := Sample{Series: Series{Name: "cpu"}, Point: Point{Time: t0, Value: 1}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Sample{
		{Series: Series{}, Point: Point{Time: t0}},
		{Series: Series{Name: "cpu", Labels: Labels{"": "x"}}, Point: Point{Time: t0}},
		{Series: Series{Name: "cpu", Labels: Labels{`a="x",b`: "y"}}, Point: Point{Time: t0}},
		{Series: Series{Name: "cpu load"}, Point: Point{Time: t0}},
		{Series: Series{Name: "cpu"}},
		{Series: Series{Name: "cpu"}, Point: Point{Time: t0, Value: math.NaN()}},
		{Series: Series{Name: "cpu"}, Point: Point{Time: t0, Value: math.Inf(1)}},
	}
	for i, s := range bad {
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("bad sample %d accepted: %v", i, err)
		}
	}
}

func TestTraceIDParse(t *testing.T) {
	const hexID = "4bf92f3577b34da6a3ce929d0e0e4736"
	id, err := ParseTraceID(hexID)
	if err != nil || id.String() != hexID {
		t.Fatalf("ParseTraceID = %s, %v", id, err)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("0", 32), strings.Repeat("g", 32), hexID + "00"} {
		if _, err := ParseTraceID(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseTraceID(%q) err = %v", bad, err)
		}
	}
}

func TestSpanValidate(t *testing.T) {
	good := Span{TraceID: TraceID{1}, SpanID: SpanID{1}, Service: "checkout", Name: "GET /cart", Start: t0, End: t0.Add(time.Millisecond)}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	mutate := []func(*Span){
		func(s *Span) { s.TraceID = TraceID{} },
		func(s *Span) { s.SpanID = SpanID{} },
		func(s *Span) { s.Service = "" },
		func(s *Span) { s.Start = time.Time{} },
		func(s *Span) { s.End = s.Start.Add(-time.Second) },
	}
	for i, m := range mutate {
		s := good
		m(&s)
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("mutation %d accepted: %v", i, err)
		}
	}
}

func TestDocumentAndBaselineAndChangeValidate(t *testing.T) {
	if err := (Document{ID: "1", Time: t0}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []Document{{Time: t0}, {ID: "1"}} {
		if err := d.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("document %+v accepted", d)
		}
	}
	if err := (Baseline{SeriesKey: "k", Version: 1, Computed: t0}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, b := range []Baseline{{Version: 1, Computed: t0}, {SeriesKey: "k", Computed: t0}, {SeriesKey: "k", Version: 1}} {
		if err := b.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("baseline %+v accepted", b)
		}
	}
	st := clock.Stamp{Valid: t0, Record: t0}
	if err := (Change{Entity: "svc:checkout", Kind: "version", Stamp: st}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Change{{Kind: "x", Stamp: st}, {Entity: "e", Stamp: st}, {Entity: "e", Kind: "x"}} {
		if err := c.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("change %+v accepted", c)
		}
	}
}

func FuzzParseTraceID(f *testing.F) {
	f.Add("4bf92f3577b34da6a3ce929d0e0e4736")
	f.Add("")
	f.Add(strings.Repeat("0", 32))
	f.Fuzz(func(t *testing.T, s string) {
		id, err := ParseTraceID(s)
		if err != nil {
			return
		}
		if id.IsZero() {
			t.Fatal("accepted the zero trace ID")
		}
		if back, err := ParseTraceID(id.String()); err != nil || back != id {
			t.Fatalf("round trip failed for %q", s)
		}
	})
}
