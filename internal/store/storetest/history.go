package storetest

import (
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/platform/clock"
	"github.com/ObservexINC/Observex_managed/internal/store"
)

// HistoryStore runs the System History contract against stores from open.
func HistoryStore(t *testing.T, open func(t *testing.T) store.HistoryStore) {
	at := func(min int) time.Time { return T0.Add(time.Duration(min) * time.Minute) }
	change := func(e store.EntityID, kind string, valid, record int, attrs map[string]string) store.Change {
		return store.Change{Entity: e, Kind: kind, Attributes: attrs, Stamp: clock.Stamp{Valid: at(valid), Record: at(record)}}
	}
	// The retail example: deploy and pool change both happen at 02:12; the pool
	// change is recorded 7 minutes late.
	checkout := store.EntityID("service:checkout")
	history := []store.Change{
		change(checkout, "version", 12, 12, map[string]string{"version": "v4.18"}),
		change(checkout, "config", 12, 19, map[string]string{"db.pool.max": "20"}),
		change(checkout, "version", 5, 5, map[string]string{"version": "v4.17"}),
		change("service:cart", "version", 12, 12, map[string]string{"version": "v2.3"}),
	}

	t.Run("as it was returns every change in valid-time order", func(t *testing.T) {
		h := open(t)
		noErr(t, "append", h.AppendChanges(ctx(t), history))
		got, err := h.Changes(ctx(t), store.HistoryQuery{Entity: checkout, Range: hour(), View: clock.AsItWas})
		noErr(t, "changes", err)
		if len(got) != 3 {
			t.Fatalf("got %d changes, want 3", len(got))
		}
		if got[0].Attributes["version"] != "v4.17" || got[1].Kind != "version" || got[2].Kind != "config" {
			t.Fatalf("order wrong: %+v", got)
		}
	})

	t.Run("as known then hides late records", func(t *testing.T) {
		h := open(t)
		noErr(t, "append", h.AppendChanges(ctx(t), history))
		got, err := h.Changes(ctx(t), store.HistoryQuery{Entity: checkout, Range: hour(), View: clock.AsKnownThen, KnownAt: at(14)})
		noErr(t, "changes at 02:14", err)
		if len(got) != 2 || got[1].Attributes["version"] != "v4.18" {
			t.Fatalf("at 02:14 got %+v, want v4.17 and v4.18 only", got)
		}
		got, err = h.Changes(ctx(t), store.HistoryQuery{Entity: checkout, Range: hour(), View: clock.AsKnownThen, KnownAt: at(19)})
		noErr(t, "changes at 02:19", err)
		if len(got) != 3 {
			t.Fatalf("at 02:19 got %d changes, want 3", len(got))
		}
	})

	t.Run("range filters on valid time", func(t *testing.T) {
		h := open(t)
		noErr(t, "append", h.AppendChanges(ctx(t), history))
		r := store.TimeRange{Start: at(10), End: at(20)}
		got, err := h.Changes(ctx(t), store.HistoryQuery{Entity: checkout, Range: r, View: clock.AsItWas})
		noErr(t, "changes", err)
		if len(got) != 2 {
			t.Fatalf("got %d, want the two changes at 02:12", len(got))
		}
	})

	t.Run("appending is cumulative and keeps both clocks", func(t *testing.T) {
		h := open(t)
		noErr(t, "append 1", h.AppendChanges(ctx(t), history[:1]))
		noErr(t, "append 2", h.AppendChanges(ctx(t), history[1:2]))
		got, err := h.Changes(ctx(t), store.HistoryQuery{Entity: checkout, Range: hour(), View: clock.AsItWas})
		noErr(t, "changes", err)
		if len(got) != 2 || got[1].Stamp.Lag() != 7*time.Minute {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("invalid input writes nothing", func(t *testing.T) {
		h := open(t)
		bad := history[0]
		bad.Stamp.Record = time.Time{}
		wantErr(t, "append", h.AppendChanges(ctx(t), []store.Change{history[1], bad}), store.ErrInvalid)
		got, err := h.Changes(ctx(t), store.HistoryQuery{Entity: checkout, Range: hour(), View: clock.AsItWas})
		noErr(t, "changes", err)
		if len(got) != 0 {
			t.Fatalf("partial append happened: %+v", got)
		}
		_, err = h.Changes(ctx(t), store.HistoryQuery{Entity: checkout, Range: hour(), View: clock.AsKnownThen})
		wantErr(t, "known-then without KnownAt", err, store.ErrInvalid)
		_, err = h.Changes(ctx(t), store.HistoryQuery{Range: hour()})
		wantErr(t, "no entity", err, store.ErrInvalid)
		_, err = h.Changes(ctx(t), store.HistoryQuery{Entity: checkout, Range: hour(), View: clock.View(42)})
		wantErr(t, "unknown view", err, store.ErrInvalid)
	})

	t.Run("cancelled context and closed store", func(t *testing.T) {
		h := open(t)
		if err := h.AppendChanges(cancelled(), history); err == nil {
			t.Fatal("append with cancelled context succeeded")
		}
		noErr(t, "close", h.Close())
		wantErr(t, "append after close", h.AppendChanges(ctx(t), history), store.ErrClosed)
	})
}
