package opensearch

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

func TestQASearchExactNULFields(t *testing.T) {
	s := openReal(t)
	ctx := testCtx(t)
	docs := []store.Document{
		{ID: "a-wrong", Time: at(0), Fields: map[string]string{"a\x00b": "c"}},
		{ID: "z-right", Time: at(0), Fields: map[string]string{"a": "b\x00c"}},
	}
	if err := s.Index(ctx, "qa", docs); err != nil {
		t.Fatal(err)
	}
	got, err := s.Search(ctx, store.SearchQuery{Index: "qa", Range: store.TimeRange{Start: at(-time.Second), End: at(time.Second)}, Filters: map[string]string{"a": "b\x00c"}, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "z-right" {
		t.Fatalf("exact filter returned different field pair: %+v", got)
	}
}

func TestQASearchNanosecondPagination(t *testing.T) {
	s := openReal(t)
	ctx := testCtx(t)
	// The first page contains candidate matches rejected by full-body checks.
	// Nanoseconds exceed exact float64 integer precision in search_after.
	stem := strings.Repeat("a", probeBytes)
	docs := make([]store.Document, 1100)
	for i := range docs {
		body := stem + "wrong"
		if i%3 == 0 {
			body = stem + "target"
		}
		docs[i] = store.Document{ID: fmt.Sprintf("doc-%04d", i), Time: at(time.Duration(1100 - i)), Body: body}
	}
	if err := s.Index(ctx, "qa", docs); err != nil {
		t.Fatal(err)
	}
	got, err := s.Search(ctx, store.SearchQuery{Index: "qa", Text: stem + "target", Range: store.TimeRange{Start: at(-time.Second), End: at(time.Second)}, Limit: 350})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 350 {
		t.Fatalf("nanosecond pagination: got %d documents, want 350", len(got))
	}
	for i, d := range got {
		if want := fmt.Sprintf("doc-%04d", 3*i); d.ID != want {
			t.Fatalf("position %d: got %s want %s", i, d.ID, want)
		}
	}
}
