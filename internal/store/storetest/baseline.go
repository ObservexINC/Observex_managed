package storetest

import (
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// BaselineStore runs the BaselineStore contract against stores from open.
func BaselineStore(t *testing.T, open func(t *testing.T) store.BaselineStore) {
	key := `http_request_duration_p95{service="checkout"}`
	b := func(v int64, data string) store.Baseline {
		return store.Baseline{SeriesKey: key, Version: v, Computed: T0.Add(time.Duration(v) * time.Hour), Data: []byte(data)}
	}

	t.Run("newer versions replace older ones", func(t *testing.T) {
		s := open(t)
		noErr(t, "put v1", s.PutBaseline(ctx(t), b(1, "one")))
		noErr(t, "put v2", s.PutBaseline(ctx(t), b(2, "two")))
		got, err := s.GetBaseline(ctx(t), key)
		noErr(t, "get", err)
		if got.Version != 2 || string(got.Data) != "two" {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("same or older version conflicts", func(t *testing.T) {
		s := open(t)
		noErr(t, "put v3", s.PutBaseline(ctx(t), b(3, "three")))
		wantErr(t, "same version", s.PutBaseline(ctx(t), b(3, "dup")), store.ErrConflict)
		wantErr(t, "older version", s.PutBaseline(ctx(t), b(2, "old")), store.ErrConflict)
		got, err := s.GetBaseline(ctx(t), key)
		noErr(t, "get", err)
		if string(got.Data) != "three" {
			t.Fatalf("conflicting write changed data to %q", got.Data)
		}
	})

	t.Run("missing and invalid", func(t *testing.T) {
		s := open(t)
		_, err := s.GetBaseline(ctx(t), "nothing")
		wantErr(t, "missing", err, store.ErrNotFound)
		wantErr(t, "version 0", s.PutBaseline(ctx(t), b(0, "x")), store.ErrInvalid)
	})

	t.Run("data is copied", func(t *testing.T) {
		s := open(t)
		in := b(1, "model")
		noErr(t, "put", s.PutBaseline(ctx(t), in))
		in.Data[0] = 'X'
		got, err := s.GetBaseline(ctx(t), key)
		noErr(t, "get", err)
		if string(got.Data) != "model" {
			t.Fatalf("stored data changed to %q", got.Data)
		}
	})

	t.Run("cancelled context and closed store", func(t *testing.T) {
		s := open(t)
		if err := s.PutBaseline(cancelled(), b(1, "x")); err == nil {
			t.Fatal("put with cancelled context succeeded")
		}
		noErr(t, "close", s.Close())
		_, err := s.GetBaseline(ctx(t), key)
		wantErr(t, "get after close", err, store.ErrClosed)
	})
}
