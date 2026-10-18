package storetest

import (
	"fmt"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// SearchStore runs the SearchStore contract against stores from open.
func SearchStore(t *testing.T, open func(t *testing.T) store.SearchStore) {
	doc := func(id string, minute int, body string, fields map[string]string) store.Document {
		return store.Document{ID: id, Time: T0.Add(time.Duration(minute) * time.Minute), Body: body, Fields: fields}
	}
	logs := []store.Document{
		doc("a", 1, "Checkout failed: connection pool exhausted", map[string]string{"service": "checkout", "level": "error"}),
		doc("b", 2, "checkout succeeded", map[string]string{"service": "checkout", "level": "info"}),
		doc("c", 3, "Cart updated", map[string]string{"service": "cart", "level": "info"}),
		doc("d", 3, "connection POOL exhausted again", map[string]string{"service": "checkout", "level": "error"}),
	}

	t.Run("text terms all must match, ignoring case", func(t *testing.T) {
		s := open(t)
		noErr(t, "index", s.Index(ctx(t), "logs", logs))
		got, err := s.Search(ctx(t), store.SearchQuery{Index: "logs", Text: "pool EXHAUSTED", Range: hour()})
		noErr(t, "search", err)
		if ids(got) != "d,a" {
			t.Fatalf("got %s, want d,a (newest first)", ids(got))
		}
	})

	t.Run("filters are exact and combined", func(t *testing.T) {
		s := open(t)
		noErr(t, "index", s.Index(ctx(t), "logs", logs))
		got, err := s.Search(ctx(t), store.SearchQuery{Index: "logs", Filters: map[string]string{"service": "checkout", "level": "info"}, Range: hour()})
		noErr(t, "search", err)
		if ids(got) != "b" {
			t.Fatalf("got %s, want b", ids(got))
		}
	})

	t.Run("newest first, ties by ID, limit applies", func(t *testing.T) {
		s := open(t)
		noErr(t, "index", s.Index(ctx(t), "logs", logs))
		got, err := s.Search(ctx(t), store.SearchQuery{Index: "logs", Range: hour(), Limit: 3})
		noErr(t, "search", err)
		if ids(got) != "c,d,b" {
			t.Fatalf("got %s, want c,d,b", ids(got))
		}
	})

	t.Run("default limit", func(t *testing.T) {
		s := open(t)
		var many []store.Document
		for i := 0; i < store.DefaultLimit+20; i++ {
			many = append(many, store.Document{ID: fmt.Sprintf("m%04d", i), Time: T0.Add(time.Duration(i) * time.Second), Body: "x"})
		}
		noErr(t, "index", s.Index(ctx(t), "logs", many))
		got, err := s.Search(ctx(t), store.SearchQuery{Index: "logs", Range: hour()})
		noErr(t, "search", err)
		if len(got) != store.DefaultLimit {
			t.Fatalf("got %d documents, want %d", len(got), store.DefaultLimit)
		}
	})

	t.Run("re-index replaces by ID", func(t *testing.T) {
		s := open(t)
		noErr(t, "index", s.Index(ctx(t), "logs", logs[:1]))
		noErr(t, "re-index", s.Index(ctx(t), "logs", []store.Document{doc("a", 1, "replaced body", nil)}))
		got, err := s.Search(ctx(t), store.SearchQuery{Index: "logs", Range: hour()})
		noErr(t, "search", err)
		if len(got) != 1 || got[0].Body != "replaced body" {
			t.Fatalf("got %+v", got)
		}
	})

	t.Run("indexes are independent", func(t *testing.T) {
		s := open(t)
		noErr(t, "index logs", s.Index(ctx(t), "logs", logs[:1]))
		noErr(t, "index events", s.Index(ctx(t), "events", []store.Document{doc("e1", 1, "deploy checkout v4.18", nil)}))
		got, err := s.Search(ctx(t), store.SearchQuery{Index: "events", Text: "checkout", Range: hour()})
		noErr(t, "search", err)
		if ids(got) != "e1" {
			t.Fatalf("got %s, want e1", ids(got))
		}
		got, err = s.Search(ctx(t), store.SearchQuery{Index: "missing", Range: hour()})
		noErr(t, "search missing index", err)
		if len(got) != 0 {
			t.Fatalf("missing index returned %d documents", len(got))
		}
	})

	t.Run("invalid input writes nothing", func(t *testing.T) {
		s := open(t)
		wantErr(t, "no time", s.Index(ctx(t), "logs", []store.Document{logs[0], {ID: "bad"}}), store.ErrInvalid)
		wantErr(t, "no index", s.Index(ctx(t), "", logs), store.ErrInvalid)
		got, err := s.Search(ctx(t), store.SearchQuery{Index: "logs", Range: hour()})
		noErr(t, "search", err)
		if len(got) != 0 {
			t.Fatalf("partial write happened: %s", ids(got))
		}
		_, err = s.Search(ctx(t), store.SearchQuery{Index: "logs"})
		wantErr(t, "no range", err, store.ErrInvalid)
		_, err = s.Search(ctx(t), store.SearchQuery{Index: "logs", Range: hour(), Limit: store.MaxLimit + 1})
		wantErr(t, "limit too large", err, store.ErrInvalid)
	})

	t.Run("cancelled context and closed store", func(t *testing.T) {
		s := open(t)
		if err := s.Index(cancelled(), "logs", logs); err == nil {
			t.Fatal("index with cancelled context succeeded")
		}
		noErr(t, "close", s.Close())
		wantErr(t, "index after close", s.Index(ctx(t), "logs", logs), store.ErrClosed)
		_, err := s.Search(ctx(t), store.SearchQuery{Index: "logs", Range: hour()})
		wantErr(t, "search after close", err, store.ErrClosed)
	})
}

func ids(docs []store.Document) string {
	out := ""
	for i, d := range docs {
		if i > 0 {
			out += ","
		}
		out += d.ID
	}
	return out
}
