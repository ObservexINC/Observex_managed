package opensearch

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ObservexINC/Observex_managed/internal/node/selfmon"
	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
	"github.com/ObservexINC/Observex_managed/internal/store"
	"github.com/ObservexINC/Observex_managed/internal/store/enginetest"
	"github.com/ObservexINC/Observex_managed/internal/store/fake"
	"github.com/ObservexINC/Observex_managed/internal/store/storetest"
)

func testCtx(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// openReal opens a SearchStore with a prefix of its own on the test engine
// and deletes its indexes when the test ends.
func openReal(t testing.TB) *SearchStore {
	t.Helper()
	addr := enginetest.Address(t, enginetest.OpenSearch)
	user, password := enginetest.Credentials(enginetest.OpenSearchUsername, enginetest.OpenSearchPassword)
	var b [5]byte
	_, _ = rand.Read(b[:])
	cfg := Config{
		Addresses: strings.Split(addr, ","), Username: user, Password: password,
		CACertFile: os.Getenv(enginetest.OpenSearchCA), IndexPrefix: "oxtest-" + hex.EncodeToString(b[:]),
	}
	s, err := Open(cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		cleanup, err := Open(cfg)
		if err == nil {
			if err := cleanup.DeleteIndexes(context.Background()); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}
		_ = s.Close()
	})
	return s
}

func TestContract(t *testing.T) {
	enginetest.Address(t, enginetest.OpenSearch)
	storetest.SearchStore(t, func(t *testing.T) store.SearchStore { return openReal(t) })
}

func at(d time.Duration) time.Time { return storetest.T0.Add(d) }

var words = []string{"Checkout", "failed", "POOL", "exhausted", "straße", "ÜBER", "größe", "timeout", "a*b", "what?", `back\slash`, "日本語", "x"}

func randomDocs(r *mrand.Rand, n int) []store.Document {
	var docs []store.Document
	for i := 0; i < n; i++ {
		var body []string
		for j := 0; j < 1+r.Intn(8); j++ {
			body = append(body, words[r.Intn(len(words))])
		}
		d := store.Document{
			ID:   fmt.Sprintf("doc-%04d", r.Intn(n)), // some IDs repeat: re-indexing replaces
			Time: at(time.Duration(r.Intn(3600)) * time.Second).Add(time.Duration(r.Intn(1000))),
			Body: strings.Join(body, " "),
		}
		switch r.Intn(4) {
		case 0:
		case 1:
			d.Fields = map[string]string{}
		default:
			d.Fields = map[string]string{"service": []string{"checkout", "cart", "Cart"}[r.Intn(3)], "level": []string{"info", "error"}[r.Intn(2)]}
		}
		docs = append(docs, d)
	}
	return docs
}

// TestMatchesFake indexes the same random documents in OpenSearch and the
// fake and compares searches by text, filters, ranges and limits.
func TestMatchesFake(t *testing.T) {
	s := openReal(t)
	f := fake.NewSearchStore()
	ctx := testCtx(t)
	r := mrand.New(mrand.NewSource(11)) //nolint:gosec // G404: test data
	docs := randomDocs(r, 600)
	for i := 0; i < len(docs); i += 150 {
		for _, st := range []store.SearchStore{s, f} {
			if err := st.Index(ctx, "Logs/App 1", docs[i:i+150]); err != nil {
				t.Fatal(err)
			}
		}
	}
	hour := store.TimeRange{Start: storetest.T0, End: at(time.Hour)}
	queries := []store.SearchQuery{
		{Index: "Logs/App 1", Range: hour, Limit: store.MaxLimit},
		{Index: "Logs/App 1", Range: hour},
		{Index: "Logs/App 1", Text: "pool EXHAUSTED", Range: hour, Limit: 50},
		{Index: "Logs/App 1", Text: "STRASSE", Range: hour},
		{Index: "Logs/App 1", Text: "straße über", Range: hour, Limit: 1000},
		{Index: "Logs/App 1", Text: "a*b what?", Range: hour, Limit: 1000},
		{Index: "Logs/App 1", Text: `slash ck\s`, Range: hour, Limit: 1000},
		{Index: "Logs/App 1", Text: "本", Range: hour, Limit: 1000},
		{Index: "Logs/App 1", Text: "e", Range: hour, Limit: 7},
		{Index: "Logs/App 1", Filters: map[string]string{"service": "cart"}, Range: hour, Limit: 1000},
		{Index: "Logs/App 1", Filters: map[string]string{"service": "Cart", "level": "error"}, Text: "x", Range: hour, Limit: 1000},
		{Index: "Logs/App 1", Range: store.TimeRange{Start: at(10 * time.Minute), End: at(10*time.Minute + 500*time.Millisecond)}, Limit: 1000},
		{Index: "logs/app 1", Range: hour}, // another index: names are exact
	}
	for _, q := range queries {
		got, err := s.Search(ctx, q)
		if err != nil {
			t.Fatalf("search %+v: %v", q, err)
		}
		want, _ := f.Search(ctx, q)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("search %+v: %d documents, fake %d\n got %s\nwant %s", q, len(got), len(want), ids(got), ids(want))
		}
	}
}

func ids(docs []store.Document) string {
	var out []string
	for _, d := range docs {
		out = append(out, d.ID)
	}
	return strings.Join(out, ",")
}

// TestLongBodies checks substring search across chunk boundaries, including
// a term longer than the chunks' overlap.
func TestLongBodies(t *testing.T) {
	s := openReal(t)
	ctx := testCtx(t)
	filler := strings.Repeat("abcdefghij", 12_000) // 120 KB, several chunks
	needle := "ZZNEEDLEZZ"
	long := strings.Repeat("Q", 3000) // longer than the overlap
	var docs []store.Document
	for i, pos := range []int{0, chunkBytes - 5, chunkBytes - chunkOverlap - 3, 2*(chunkBytes-chunkOverlap) + 1, len(filler) - 1} {
		body := filler[:pos] + needle + filler[pos:]
		docs = append(docs, store.Document{ID: fmt.Sprintf("needle-%d", i), Time: at(time.Duration(i) * time.Second), Body: body})
	}
	docs = append(docs,
		store.Document{ID: "long-term", Time: at(time.Minute), Body: filler[:chunkBytes-100] + long + filler},
		// Shares the long term's first 2,049 bytes but not the whole term.
		store.Document{ID: "decoy", Time: at(2 * time.Minute), Body: filler[:5] + long[:2500] + "x" + filler[:100]},
		store.Document{ID: "multibyte", Time: at(3 * time.Minute), Body: strings.Repeat("ü", 20_000) + "TAIL"},
	)
	if err := s.Index(ctx, "big", docs); err != nil {
		t.Fatal(err)
	}
	r := store.TimeRange{Start: storetest.T0, End: at(time.Hour)}
	got, err := s.Search(ctx, store.SearchQuery{Index: "big", Text: strings.ToLower(needle), Range: r})
	if err != nil || ids(got) != "needle-4,needle-3,needle-2,needle-1,needle-0" {
		t.Fatalf("needle: %s, %v", ids(got), err)
	}
	if got[0].Body != docs[4].Body {
		t.Fatal("long body not returned whole")
	}
	got, err = s.Search(ctx, store.SearchQuery{Index: "big", Text: long, Range: r})
	if err != nil || ids(got) != "long-term" {
		t.Fatalf("long term: %s, %v", ids(got), err)
	}
	got, err = s.Search(ctx, store.SearchQuery{Index: "big", Text: "üüü tail", Range: r})
	if err != nil || ids(got) != "multibyte" {
		t.Fatalf("multibyte: %s, %v", ids(got), err)
	}
}

// TestPostFilterKeepsPaging makes many documents that match a long term's
// first part but not the term, so the store must page past them.
func TestPostFilterKeepsPaging(t *testing.T) {
	s := openReal(t)
	ctx := testCtx(t)
	long := strings.Repeat("w", 2100) + "END"
	var docs []store.Document
	for i := 0; i < 1200; i++ {
		docs = append(docs, store.Document{ID: fmt.Sprintf("decoy-%04d", i), Time: at(time.Duration(1200-i) * time.Second), Body: strings.Repeat("w", 2100) + "NOT"})
	}
	docs = append(docs, store.Document{ID: "real", Time: at(0), Body: long})
	if err := s.Index(ctx, "paging", docs); err != nil {
		t.Fatal(err)
	}
	got, err := s.Search(ctx, store.SearchQuery{Index: "paging", Text: long, Range: store.TimeRange{Start: storetest.T0, End: at(time.Hour)}})
	if err != nil || ids(got) != "real" {
		t.Fatalf("got %s, %v", ids(got), err)
	}
}

func TestUnusualIDsAndNames(t *testing.T) {
	s := openReal(t)
	ctx := testCtx(t)
	longID := strings.Repeat("i", 5000)
	docs := []store.Document{
		{ID: longID, Time: at(1), Body: "one"},
		{ID: "a/b?c#d e", Time: at(2), Body: "two", Fields: map[string]string{"k.with.dots": "v", "": "empty name"}},
		{ID: "ünïcödé", Time: at(3), Body: "three"},
	}
	for _, index := range []string{"UPPER", "_starts_with_underscore", "with space", strings.Repeat("n", 300), "plain-name"} {
		if err := s.Index(ctx, index, docs); err != nil {
			t.Fatalf("index %q: %v", index, err)
		}
		got, err := s.Search(ctx, store.SearchQuery{Index: index, Range: store.TimeRange{Start: storetest.T0, End: at(time.Hour)}})
		if err != nil || len(got) != 3 || got[2].ID != longID || got[1].Fields["k.with.dots"] != "v" || got[1].Fields[""] != "empty name" {
			t.Fatalf("index %q: %+v, %v", index, ids(got), err)
		}
		got, err = s.Search(ctx, store.SearchQuery{Index: index, Filters: map[string]string{"": "empty name"}, Range: store.TimeRange{Start: storetest.T0, End: at(time.Hour)}})
		if err != nil || ids(got) != "a/b?c#d e" {
			t.Fatalf("filter on an empty field name: %s, %v", ids(got), err)
		}
	}
}

func TestTimesAndInvalidInput(t *testing.T) {
	s := openReal(t)
	ctx := testCtx(t)
	t1 := at(1) // nanosecond times
	docs := []store.Document{
		{ID: "epoch", Time: minTime, Body: "first"},
		{ID: "ns1", Time: t1, Body: "x"},
		{ID: "ns2", Time: t1.Add(1), Body: "x"},
		{ID: "last", Time: maxTime, Body: "last"},
	}
	if err := s.Index(ctx, "times", docs); err != nil {
		t.Fatal(err)
	}
	got, err := s.Search(ctx, store.SearchQuery{Index: "times", Range: store.TimeRange{Start: t1, End: t1.Add(1)}})
	if err != nil || ids(got) != "ns1" || !got[0].Time.Equal(t1) {
		t.Fatalf("half-open nanosecond range: %s, %v", ids(got), err)
	}
	wide := store.TimeRange{Start: time.Date(1, 1, 2, 0, 0, 0, 0, time.UTC), End: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)}
	got, err = s.Search(ctx, store.SearchQuery{Index: "times", Range: wide})
	if err != nil || ids(got) != "last,ns2,ns1,epoch" {
		t.Fatalf("wide range: %s, %v", ids(got), err)
	}
	bad := []store.Document{
		{ID: "old", Time: time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC), Body: "x"},
		{ID: "bad-utf8", Time: at(1), Body: "x\xff"},
		{ID: "field", Time: at(1), Fields: map[string]string{"k": "\xc3"}},
		{ID: strings.Repeat("i", maxIDBytes+1), Time: at(1)},
	}
	for _, d := range bad {
		if err := s.Index(ctx, "times", []store.Document{docs[0], d}); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("document %.20q: %v", d.ID, err)
		}
	}
	if _, err := s.Search(ctx, store.SearchQuery{Index: "times", Text: "\xff", Range: wide}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("invalid search text: %v", err)
	}
}

func TestConcurrentFirstWrites(t *testing.T) {
	s := openReal(t)
	ctx := testCtx(t)
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			errs <- s.Index(ctx, "race", []store.Document{{ID: fmt.Sprint(w), Time: at(time.Duration(w)), Body: "x"}})
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Search(ctx, store.SearchQuery{Index: "race", Range: store.TimeRange{Start: storetest.T0, End: at(time.Hour)}})
	if err != nil || len(got) != 6 {
		t.Fatalf("got %d, %v", len(got), err)
	}
}

func TestSelfMonitoring(t *testing.T) {
	s := openReal(t)
	ctx := testCtx(t)
	_ = s.Index(ctx, "m", []store.Document{{ID: "1", Time: at(0), Body: "x"}})
	_, _ = s.Search(ctx, store.SearchQuery{Index: "m", Range: store.TimeRange{Start: storetest.T0, End: at(time.Hour)}})
	var r selfmon.Registry
	r.Register(s)
	var out bytes.Buffer
	if err := selfmon.WriteText(&out, r.Gather()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"observex_searchstore_up 1", "observex_searchstore_documents_indexed_total 1", "observex_searchstore_searches_total 1", "observex_searchstore_search_errors_total 0"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("metrics lack %q:\n%s", want, out.String())
		}
	}
}

// --- No engine needed below. -------------------------------------------

func TestConfigValidation(t *testing.T) {
	if _, err := Open(Config{}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("no addresses: %v", err)
	}
	for _, p := range []string{"UPPER", "-dash", "a/b", strings.Repeat("a", 33)} {
		if _, err := Open(Config{Addresses: []string{"http://127.0.0.1:9200"}, IndexPrefix: p}); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("prefix %q: %v", p, err)
		}
	}
	if _, err := Open(Config{Addresses: []string{"http://127.0.0.1:9200"}, Replicas: -1}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("negative replicas: %v", err)
	}
	if _, err := Open(Config{Addresses: []string{"http://127.0.0.1:9200"}, CACertFile: "/nonexistent/ca.pem"}); err == nil {
		t.Fatal("missing CA file accepted")
	}
}

func TestPasswordNeverLogged(t *testing.T) {
	const pw = "ZZopensearchPWmarkerZZ"
	var buf bytes.Buffer
	l := logging.New(&buf, slog.LevelDebug)
	c := Config{Addresses: []string{"https://search-1:9200"}, Username: "observex", Password: logging.Secret(pw)}
	l.Info("connecting", "config", c)
	fmt.Fprintf(&buf, "%v %+v %#v", c, c, c)
	if strings.Contains(buf.String(), pw) || strings.Contains(buf.String(), pw[:12]) {
		t.Fatalf("password reached the output:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "search-1:9200") {
		t.Fatalf("configuration not logged:\n%s", buf.String())
	}
}

func TestChunks(t *testing.T) {
	r := mrand.New(mrand.NewSource(3)) //nolint:gosec // G404: test data
	alphabet := []string{"a", "b", "ü", "日", "😀"}
	for n := 0; n < 40; n++ {
		var sb strings.Builder
		for sb.Len() < r.Intn(4*chunkBytes) {
			sb.WriteString(alphabet[r.Intn(len(alphabet))])
		}
		s := sb.String()
		cs := chunks(s)
		joined := ""
		for i, c := range cs {
			if len(c) > chunkBytes || !utf8.ValidString(c) {
				t.Fatalf("chunk %d: %d bytes, valid %v", i, len(c), utf8.ValidString(c))
			}
			joined += c
		}
		if len(cs) == 1 && cs[0] != s {
			t.Fatal("short text changed")
		}
		// Every substring up to the overlap plus one lies whole in a chunk.
		for k := 0; k < 30 && len(s) > 0; k++ {
			i := r.Intn(len(s))
			for i > 0 && !utf8.RuneStart(s[i]) {
				i--
			}
			j := i + 1 + r.Intn(chunkOverlap+1)
			if j > len(s) {
				j = len(s)
			}
			for j < len(s) && !utf8.RuneStart(s[j]) {
				j--
			}
			if j <= i {
				continue
			}
			sub, found := s[i:j], false
			for _, c := range cs {
				if strings.Contains(c, sub) {
					found = true
				}
			}
			if !found {
				t.Fatalf("substring [%d,%d) of %d bytes in no chunk", i, j, len(s))
			}
		}
		_ = joined
	}
}

func TestIndexNames(t *testing.T) {
	s, err := Open(Config{Addresses: []string{"http://127.0.0.1:9200"}})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, name := range []string{"logs", "Logs", "logs ", "6c6f6773", "a/b", strings.Repeat("x", 128), strings.Repeat("x", 129)} {
		got := s.indexName(name)
		if other, dup := seen[got]; dup {
			t.Fatalf("%q and %q map to %s", name, other, got)
		}
		seen[got] = name
		if len(got) > 255 || strings.ToLower(got) != got || strings.ContainsAny(got, `\/*?"<>| ,#:`) {
			t.Fatalf("%q maps to an invalid index name %q", name, got)
		}
	}
}
