package clock

import (
	"errors"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 17, 2, 12, 0, 0, time.UTC)

func TestRealIsUTC(t *testing.T) {
	if loc := (Real{}).Now().Location(); loc != time.UTC {
		t.Fatalf("Real.Now location = %v, want UTC", loc)
	}
}

func TestFakeAdvanceAndSet(t *testing.T) {
	f := NewFake(t0)
	if got := f.Now(); !got.Equal(t0) {
		t.Fatalf("Now = %v, want %v", got, t0)
	}
	f.Advance(7 * time.Minute)
	if got, want := f.Now(), t0.Add(7*time.Minute); !got.Equal(want) {
		t.Fatalf("after Advance, Now = %v, want %v", got, want)
	}
	f.Advance(-time.Hour)
	if got, want := f.Now(), t0.Add(-53*time.Minute); !got.Equal(want) {
		t.Fatalf("after negative Advance, Now = %v, want %v", got, want)
	}
	ist := time.FixedZone("IST", 5*3600+1800)
	f.Set(time.Date(2026, 10, 17, 7, 42, 0, 0, ist))
	if got := f.Now(); !got.Equal(t0) || got.Location() != time.UTC {
		t.Fatalf("Set did not normalise to UTC: %v", got)
	}
}

func TestFakeConcurrentUse(t *testing.T) {
	f := NewFake(t0)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); f.Advance(time.Second) }()
		go func() { defer wg.Done(); _ = f.Now() }()
	}
	wg.Wait()
	if got, want := f.Now(), t0.Add(50*time.Second); !got.Equal(want) {
		t.Fatalf("Now = %v, want %v", got, want)
	}
}

func TestNewStampUsesClockForRecordTime(t *testing.T) {
	f := NewFake(t0.Add(7 * time.Minute))
	s := NewStamp(t0, f)
	if !s.Valid.Equal(t0) || !s.Record.Equal(t0.Add(7*time.Minute)) {
		t.Fatalf("stamp = %+v", s)
	}
	if s.Lag() != 7*time.Minute {
		t.Fatalf("Lag = %v, want 7m", s.Lag())
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		s    Stamp
		ok   bool
	}{
		{"both set", Stamp{Valid: t0, Record: t0}, true},
		{"no valid", Stamp{Record: t0}, false},
		{"no record", Stamp{Valid: t0}, false},
		{"empty", Stamp{}, false},
	}
	for _, c := range cases {
		err := c.s.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrZeroStamp) {
			t.Errorf("%s: err = %v, want ErrZeroStamp", c.name, err)
		}
	}
}

// The retail example from the product book: a pool change happened at 02:12
// but reached ObserveX at 02:19 because the agent buffered it on disk.
func TestVisibleTwoClocks(t *testing.T) {
	change := Stamp{Valid: t0, Record: t0.Add(7 * time.Minute)}
	cases := []struct {
		at   time.Time
		view View
		want bool
	}{
		{t0.Add(-time.Minute), AsItWas, false},
		{t0.Add(-time.Minute), AsKnownThen, false},
		{t0, AsItWas, true},
		{t0, AsKnownThen, false},
		{t0.Add(2 * time.Minute), AsItWas, true},
		{t0.Add(2 * time.Minute), AsKnownThen, false},
		{t0.Add(7 * time.Minute), AsKnownThen, true},
		{t0.Add(8 * time.Minute), AsKnownThen, true},
		{t0.Add(8 * time.Minute), View(99), false},
	}
	for _, c := range cases {
		if got := change.Visible(c.at, c.view); got != c.want {
			t.Errorf("Visible(%s, %v) = %v, want %v", c.at.Format("15:04"), c.view, got, c.want)
		}
	}
}

func TestNegativeLagFromSkewedSource(t *testing.T) {
	s := Stamp{Valid: t0.Add(30 * time.Second), Record: t0}
	if s.Lag() != -30*time.Second {
		t.Fatalf("Lag = %v, want -30s", s.Lag())
	}
	// A change stamped in the future is not visible until its valid time.
	if s.Visible(t0, AsKnownThen) {
		t.Fatal("future-stamped change visible before its valid time")
	}
}

func TestViewString(t *testing.T) {
	for v, want := range map[View]string{AsItWas: "as-it-was", AsKnownThen: "as-known-then", View(7): "unknown-view"} {
		if got := v.String(); got != want {
			t.Errorf("View(%d).String() = %q, want %q", v, got, want)
		}
	}
}
