package storetest

import (
	"testing"
	"time"

	"github.com/Voxmatic/observe/internal/store"
)

// TraceStore runs the TraceStore contract against stores from open.
func TraceStore(t *testing.T, open func(t *testing.T) store.TraceStore) {
	tid := func(b byte) store.TraceID { return store.TraceID{b, 1} }
	sid := func(b byte) store.SpanID { return store.SpanID{b, 1} }
	span := func(tr, sp, parent byte, svc string, startMin, durMs int, isErr bool) store.Span {
		s := store.Span{
			TraceID: tid(tr), SpanID: sid(sp), Service: svc, Name: svc + " op",
			Start: T0.Add(time.Duration(startMin) * time.Minute), Error: isErr,
			Attributes: map[string]string{"http.route": "/checkout"},
		}
		if parent != 0 {
			s.ParentID = sid(parent)
		}
		s.End = s.Start.Add(time.Duration(durMs) * time.Millisecond)
		return s
	}
	// Trace 1: checkout -> payments, healthy, starts at minute 5.
	// Trace 2: checkout -> orders-db, error in the database span, minute 10.
	// Trace 3: cart only, minute 7.
	spans := []store.Span{
		span(1, 2, 1, "payments", 5, 40, false),
		span(1, 1, 0, "checkout", 5, 120, false),
		span(2, 1, 0, "checkout", 10, 900, false),
		span(2, 2, 1, "orders-db", 10, 850, true),
		span(3, 1, 0, "cart", 7, 30, false),
	}

	t.Run("get trace returns spans in start order", func(t *testing.T) {
		s := open(t)
		noErr(t, "write", s.WriteSpans(ctx(t), spans))
		got, err := s.GetTrace(ctx(t), tid(1))
		noErr(t, "get", err)
		if len(got) != 2 || got[0].SpanID != sid(1) || got[1].SpanID != sid(2) {
			t.Fatalf("got %+v", got)
		}
		if got[1].ParentID != sid(1) || got[0].Attributes["http.route"] != "/checkout" {
			t.Fatal("span fields lost")
		}
	})

	t.Run("unknown trace is not found", func(t *testing.T) {
		s := open(t)
		_, err := s.GetTrace(ctx(t), tid(9))
		wantErr(t, "get", err, store.ErrNotFound)
	})

	t.Run("find by service, newest first, with summaries", func(t *testing.T) {
		s := open(t)
		noErr(t, "write", s.WriteSpans(ctx(t), spans))
		got, err := s.FindTraces(ctx(t), store.TraceQuery{Service: "checkout", Range: hour()})
		noErr(t, "find", err)
		if len(got) != 2 || got[0].TraceID != tid(2) || got[1].TraceID != tid(1) {
			t.Fatalf("got %+v, want trace 2 then trace 1", got)
		}
		t2 := got[0]
		if !t2.Error || t2.SpanCount != 2 || t2.Duration != 900*time.Millisecond || len(t2.Services) != 2 {
			t.Fatalf("summary of trace 2 = %+v", t2)
		}
		if t2.Services[0] != "checkout" || t2.Services[1] != "orders-db" {
			t.Fatalf("services not sorted: %v", t2.Services)
		}
	})

	t.Run("errors only and limit", func(t *testing.T) {
		s := open(t)
		noErr(t, "write", s.WriteSpans(ctx(t), spans))
		got, err := s.FindTraces(ctx(t), store.TraceQuery{Service: "checkout", Range: hour(), ErrorsOnly: true})
		noErr(t, "find errors", err)
		if len(got) != 1 || got[0].TraceID != tid(2) {
			t.Fatalf("got %+v, want only trace 2", got)
		}
		got, err = s.FindTraces(ctx(t), store.TraceQuery{Service: "checkout", Range: hour(), Limit: 1})
		noErr(t, "find limit", err)
		if len(got) != 1 || got[0].TraceID != tid(2) {
			t.Fatalf("got %+v, want newest only", got)
		}
	})

	t.Run("range filters on span start", func(t *testing.T) {
		s := open(t)
		noErr(t, "write", s.WriteSpans(ctx(t), spans))
		r := store.TimeRange{Start: T0.Add(6 * time.Minute), End: T0.Add(9 * time.Minute)}
		got, err := s.FindTraces(ctx(t), store.TraceQuery{Service: "checkout", Range: r})
		noErr(t, "find", err)
		if len(got) != 0 {
			t.Fatalf("got %+v, want none", got)
		}
	})

	t.Run("rewriting a span replaces it", func(t *testing.T) {
		s := open(t)
		noErr(t, "write", s.WriteSpans(ctx(t), spans[:2]))
		fixed := spans[0]
		fixed.Error = true
		noErr(t, "rewrite", s.WriteSpans(ctx(t), []store.Span{fixed}))
		got, err := s.GetTrace(ctx(t), tid(1))
		noErr(t, "get", err)
		if len(got) != 2 || !got[1].Error {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("invalid batch writes nothing", func(t *testing.T) {
		s := open(t)
		bad := spans[4]
		bad.Service = ""
		wantErr(t, "write", s.WriteSpans(ctx(t), []store.Span{spans[0], bad}), store.ErrInvalid)
		_, err := s.GetTrace(ctx(t), tid(1))
		wantErr(t, "get after failed write", err, store.ErrNotFound)
		_, err = s.FindTraces(ctx(t), store.TraceQuery{Range: hour()})
		wantErr(t, "no service", err, store.ErrInvalid)
	})

	t.Run("cancelled context and closed store", func(t *testing.T) {
		s := open(t)
		if err := s.WriteSpans(cancelled(), spans); err == nil {
			t.Fatal("write with cancelled context succeeded")
		}
		noErr(t, "close", s.Close())
		wantErr(t, "write after close", s.WriteSpans(ctx(t), spans), store.ErrClosed)
		_, err := s.GetTrace(ctx(t), tid(1))
		wantErr(t, "get after close", err, store.ErrClosed)
	})
}
