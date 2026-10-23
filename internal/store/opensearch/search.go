// Package opensearch is the SearchStore on OpenSearch 3 (technology row T6,
// ADR 0004, ADR 0011), through the opensearch-go v4 client.
//
// Each SearchStore index is an OpenSearch index named from a prefix and the
// index name. A document is stored with:
//
//	id       keyword     the document ID, for sorting ties
//	time     date_nanos  nanosecond time
//	body_lc  wildcard    the body lowercased, in overlapping chunks, for the
//	                     contract's substring search
//	pairs    keyword     a SHA-256 of each field's name and value, for filter
//	                     candidates checked against the original fields
//	doc      not indexed the body and fields as given, returned by searches
//
// The OpenSearch _id is a SHA-256 of the document ID, so any ID can be used
// and re-indexing an ID replaces the document.
package opensearch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	opensearchgo "github.com/opensearch-project/opensearch-go/v4"

	"github.com/ObservexINC/Observex_managed/internal/node/selfmon"
	"github.com/ObservexINC/Observex_managed/internal/platform/logging"
	"github.com/ObservexINC/Observex_managed/internal/store"
)

// Config describes the connection.
type Config struct {
	// Addresses are node URLs, for example https://10.0.0.11:9200.
	Addresses []string
	// Username and Password for HTTP basic authentication. The password is
	// a logging.Secret, so it never prints.
	Username string
	Password logging.Secret
	// CACertFile is a PEM file of the CA that signed the nodes' HTTP
	// certificates. Empty means the system's roots.
	CACertFile string
	// IndexPrefix starts every index name: lowercase letters, digits, dashes
	// and underscores, at most 32 characters. Default "observex".
	IndexPrefix string
	// Shards and Replicas for indexes the store creates; defaults 1 and 0.
	Shards   int
	Replicas int
	// Timeout per request; default 30 s.
	Timeout time.Duration
}

// LogValue keeps the configuration loggable, the password redacted by its
// type.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("addresses", c.Addresses), slog.String("username", c.Username),
		slog.Any("password", c.Password), slog.String("index_prefix", c.IndexPrefix),
	)
}

var (
	prefixRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	plainNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
)

const (
	// Lucene keeps one doc value of at most 32,766 bytes. Bodies are indexed
	// in chunks below that, overlapping by chunkOverlap bytes, so any text
	// up to chunkOverlap+1 bytes long lies whole in some chunk.
	chunkBytes   = 30_000
	chunkOverlap = 2_048
	maxIDBytes   = 32_766
	bulkBytes    = 8 << 20
	searchPage   = 500
	// probeBytes caps the part of a term sent as a wildcard pattern:
	// OpenSearch refuses patterns whose automaton is too costly to build
	// (about 300 repeated characters). Longer terms are checked in full
	// against each hit.
	probeBytes = 128
)

// date_nanos holds 1970 to 2262.
var (
	minTime = time.Unix(0, 0).UTC()
	maxTime = time.Date(2262, 4, 11, 23, 47, 16, 854775807, time.UTC)
)

// SearchStore is a store.SearchStore on OpenSearch.
type SearchStore struct {
	client   *opensearchgo.Client
	prefix   string
	shards   int
	replicas int
	timeout  time.Duration
	closed   atomic.Bool

	mu      sync.Mutex
	created map[string]bool

	indexed, indexErrors, searches, searchErrors atomic.Uint64
}

var _ store.SearchStore = (*SearchStore)(nil)

// Open connects to OpenSearch.
func Open(c Config) (*SearchStore, error) {
	if len(c.Addresses) == 0 {
		return nil, store.Invalid("opensearch: no addresses")
	}
	if c.IndexPrefix == "" {
		c.IndexPrefix = "observex"
	}
	if !prefixRE.MatchString(c.IndexPrefix) {
		return nil, store.Invalid("opensearch: index prefix %q must be up to 32 lowercase letters, digits, dashes or underscores", c.IndexPrefix)
	}
	if c.Shards <= 0 {
		c.Shards = 1
	}
	if c.Replicas < 0 {
		return nil, store.Invalid("opensearch: replicas %d is negative", c.Replicas)
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CACertFile != "" {
		pem, err := os.ReadFile(c.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("opensearch: CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, store.Invalid("opensearch: %s holds no PEM certificate", c.CACertFile)
		}
		tlsCfg.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	no := false
	client, err := opensearchgo.NewClient(opensearchgo.Config{
		Addresses: c.Addresses, Username: c.Username, Password: c.Password.Reveal(),
		Transport: transport, RequestTimeout: c.Timeout,
		DiscoverNodesOnStart: &no,
	})
	if err != nil {
		return nil, fmt.Errorf("opensearch: client: %w", err)
	}
	return &SearchStore{
		client: client, prefix: c.IndexPrefix, shards: c.Shards, replicas: c.Replicas,
		timeout: c.Timeout, created: map[string]bool{},
	}, nil
}

// indexName maps a SearchStore index name to an OpenSearch index name.
// Names OpenSearch accepts as they are keep their text; others become a
// SHA-256, under a different infix so the two kinds never collide.
func (s *SearchStore) indexName(name string) string {
	if plainNameRE.MatchString(name) {
		return s.prefix + "-n-" + name
	}
	sum := sha256.Sum256([]byte(name))
	return s.prefix + "-h-" + hex.EncodeToString(sum[:20])
}

func docID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func pairHash(k, v string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, k)
	_, _ = h.Write([]byte{0})
	_, _ = io.WriteString(h, v)
	return hex.EncodeToString(h.Sum(nil))
}

// chunks splits s into pieces of at most chunkBytes, each starting
// chunkBytes-chunkOverlap after the previous one, cut at rune boundaries.
func chunks(s string) []string {
	if len(s) <= chunkBytes {
		return []string{s}
	}
	var out []string
	for start := 0; ; {
		end := start + chunkBytes
		if end >= len(s) {
			return append(out, s[start:])
		}
		for end > start && !utf8.RuneStart(s[end]) {
			end--
		}
		out = append(out, s[start:end])
		next := end - chunkOverlap
		for next > start && !utf8.RuneStart(s[next]) {
			next--
		}
		if next <= start {
			next = end
		}
		start = next
	}
}

func (s *SearchStore) begin(ctx context.Context) error {
	if s.closed.Load() {
		return store.ErrClosed
	}
	return ctx.Err()
}

func (s *SearchStore) fail(err error) error {
	if s.closed.Load() {
		return store.ErrClosed
	}
	return err
}

// do sends one request and decodes a JSON answer into out. Status codes
// listed in ok are accepted besides 2xx.
func (s *SearchStore) do(ctx context.Context, method, path string, body []byte, out any, ok ...int) error {
	req, err := http.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		ct := "application/json"
		if strings.Contains(path, "_bulk") {
			ct = "application/x-ndjson"
		}
		req.Header.Set("Content-Type", ct)
	}
	resp, err := s.client.Stream(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return err
	}
	good := resp.StatusCode >= 200 && resp.StatusCode < 300
	for _, c := range ok {
		good = good || resp.StatusCode == c
	}
	if !good {
		return fmt.Errorf("%s %s: status %d: %s", method, strings.SplitN(path, "?", 2)[0], resp.StatusCode, reason(data))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s %s: decode answer: %w", method, path, err)
		}
	}
	return nil
}

// reason extracts OpenSearch's error type and reason, without echoing
// request data.
func reason(data []byte) string {
	var e struct {
		Error struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &e) == nil && e.Error.Type != "" {
		return e.Error.Type + ": " + truncate(e.Error.Reason, 300)
	}
	return truncate(string(data), 300)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ensureIndex creates an index with the store's mapping, once.
func (s *SearchStore) ensureIndex(ctx context.Context, name string) error {
	s.mu.Lock()
	done := s.created[name]
	s.mu.Unlock()
	if done {
		return nil
	}
	mapping := map[string]any{
		"settings": map[string]any{"number_of_shards": s.shards, "number_of_replicas": s.replicas},
		"mappings": map[string]any{
			"dynamic": "strict",
			"_source": map[string]any{"excludes": []string{"body_lc", "pairs"}},
			"properties": map[string]any{
				"id":      map[string]any{"type": "keyword"},
				"time":    map[string]any{"type": "date_nanos"},
				"body_lc": map[string]any{"type": "wildcard"},
				"pairs":   map[string]any{"type": "keyword"},
				"doc":     map[string]any{"type": "object", "enabled": false},
			},
		},
	}
	body, _ := json.Marshal(mapping)
	// "Already exists" means another writer, or an earlier run, created it.
	if err := s.do(ctx, http.MethodPut, "/"+name, body, nil); err != nil && !strings.Contains(err.Error(), "resource_already_exists_exception") {
		return fmt.Errorf("create index %s: %w", name, err)
	}
	s.mu.Lock()
	s.created[name] = true
	s.mu.Unlock()
	return nil
}

type source struct {
	ID     string   `json:"id"`
	Time   string   `json:"time"`
	BodyLC []string `json:"body_lc,omitempty"`
	Pairs  []string `json:"pairs,omitempty"`
	Doc    docPart  `json:"doc"`
}

type docPart struct {
	Body   string            `json:"body"`
	Fields map[string]string `json:"fields,omitempty"`
	// HasFields tells an empty field map from none, so documents read back
	// exactly as written.
	HasFields bool `json:"has_fields,omitempty"`
}

func validText(what, s string) error {
	if !utf8.ValidString(s) {
		return store.Invalid("%s is not valid UTF-8", what)
	}
	return nil
}

func checkDoc(d store.Document) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if len(d.ID) > maxIDBytes {
		return store.Invalid("document ID of %d bytes; the SearchStore takes at most %d", len(d.ID), maxIDBytes)
	}
	if d.Time.Before(minTime) || d.Time.After(maxTime) {
		return store.Invalid("document %q has a time outside 1970 to 2262, which the SearchStore cannot hold", d.ID)
	}
	if err := validText("document ID", d.ID); err != nil {
		return err
	}
	if err := validText("body of document "+d.ID, d.Body); err != nil {
		return err
	}
	for k, v := range d.Fields {
		if err := validText("field name of document "+d.ID, k); err != nil {
			return err
		}
		if err := validText("field "+k+" of document "+d.ID, v); err != nil {
			return err
		}
	}
	return nil
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// Index implements store.SearchStore. Every document is checked before
// anything is written; the call returns once the documents are searchable
// (refresh=wait_for). If OpenSearch fails part way the error is returned, and
// repeating the call converges, since documents are keyed by ID.
func (s *SearchStore) Index(ctx context.Context, index string, docs []store.Document) error {
	if err := s.begin(ctx); err != nil {
		return err
	}
	if index == "" {
		return store.Invalid("index name is empty")
	}
	for _, d := range docs {
		if err := checkDoc(d); err != nil {
			return err
		}
	}
	if len(docs) == 0 {
		return nil
	}
	name := s.indexName(index)
	if err := s.ensureIndex(ctx, name); err != nil {
		s.indexErrors.Add(1)
		return s.fail(fmt.Errorf("opensearch: index %q: %w", index, err))
	}
	var buf bytes.Buffer
	flush := func() error {
		if buf.Len() == 0 {
			return nil
		}
		var resp struct {
			Errors bool `json:"errors"`
			Items  []map[string]struct {
				Status int `json:"status"`
				Error  *struct {
					Type   string `json:"type"`
					Reason string `json:"reason"`
				} `json:"error"`
			} `json:"items"`
		}
		err := s.do(ctx, http.MethodPost, "/"+name+"/_bulk?refresh=wait_for", buf.Bytes(), &resp)
		buf.Reset()
		if err != nil {
			return err
		}
		if resp.Errors {
			for _, item := range resp.Items {
				for _, r := range item {
					if r.Error != nil {
						return fmt.Errorf("bulk item failed with status %d: %s: %s", r.Status, r.Error.Type, truncate(r.Error.Reason, 300))
					}
				}
			}
			return errors.New("bulk request reported errors")
		}
		return nil
	}
	for _, d := range docs {
		src := source{ID: d.ID, Time: formatTime(d.Time), BodyLC: chunks(strings.ToLower(d.Body)), Doc: docPart{Body: d.Body}}
		if d.Fields != nil {
			src.Doc.Fields, src.Doc.HasFields = d.Fields, true
			keys := make([]string, 0, len(d.Fields))
			for k := range d.Fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				src.Pairs = append(src.Pairs, pairHash(k, d.Fields[k]))
			}
		}
		meta, _ := json.Marshal(map[string]any{"index": map[string]string{"_id": docID(d.ID)}})
		line, err := json.Marshal(src)
		if err != nil {
			return err
		}
		buf.Write(meta)
		buf.WriteByte('\n')
		buf.Write(line)
		buf.WriteByte('\n')
		if buf.Len() >= bulkBytes {
			if err := flush(); err != nil {
				s.indexErrors.Add(1)
				return s.fail(fmt.Errorf("opensearch: index %q: %w", index, err))
			}
		}
	}
	if err := flush(); err != nil {
		s.indexErrors.Add(1)
		return s.fail(fmt.Errorf("opensearch: index %q: %w", index, err))
	}
	s.indexed.Add(uint64(len(docs)))
	return nil
}

// wildcardEscape escapes the characters that are special in a wildcard
// query.
var wildcardEscape = strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`)

// Search implements store.SearchStore. Text terms are matched as
// substrings of the lowercased body, exactly as the contract states: each
// term is a wildcard query on the body's chunks (a term longer than
// probeBytes is searched by its first part) and every hit is checked
// against the whole body before it is returned.
func (s *SearchStore) Search(ctx context.Context, q store.SearchQuery) ([]store.Document, error) {
	if err := s.begin(ctx); err != nil {
		return nil, err
	}
	if q.Index == "" {
		return nil, store.Invalid("search needs an index")
	}
	if err := q.Range.Validate(); err != nil {
		return nil, err
	}
	limit, err := store.NormaliseLimit(q.Limit)
	if err != nil {
		return nil, err
	}
	if err := validText("search text", q.Text); err != nil {
		return nil, err
	}
	s.searches.Add(1)
	out, err := s.search(ctx, q, limit)
	if err != nil {
		s.searchErrors.Add(1)
		return nil, s.fail(fmt.Errorf("opensearch: search %q: %w", q.Index, err))
	}
	return out, nil
}

func (s *SearchStore) search(ctx context.Context, q store.SearchQuery, limit int) ([]store.Document, error) {
	start, end := q.Range.Start, q.Range.End
	out := []store.Document{}
	if !end.After(minTime) || start.After(maxTime) {
		return out, nil // nothing can be stored there
	}
	rng := map[string]any{"format": "strict_date_optional_time_nanos"}
	if start.After(minTime) {
		rng["gte"] = formatTime(start)
	}
	if !end.After(maxTime) {
		rng["lt"] = formatTime(end)
	}
	filters := []any{map[string]any{"range": map[string]any{"time": rng}}}
	keys := make([]string, 0, len(q.Filters))
	for k := range q.Filters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		filters = append(filters, map[string]any{"term": map[string]any{"pairs": pairHash(k, q.Filters[k])}})
	}
	terms := strings.Fields(strings.ToLower(q.Text))
	for _, t := range terms {
		probe := t
		if len(probe) > probeBytes {
			probe = probe[:probeBytes]
			for len(probe) > 0 && !utf8.ValidString(probe) {
				probe = probe[:len(probe)-1]
			}
		}
		filters = append(filters, map[string]any{"wildcard": map[string]any{"body_lc": map[string]any{"value": "*" + wildcardEscape.Replace(probe) + "*"}}})
	}
	// Keep cursor values opaque. A date_nanos integer exceeds float64's
	// exact range; rounding it can skip or repeat hits on the next page.
	var after []json.RawMessage
	for len(out) < limit {
		size := limit - len(out)
		if size < searchPage && len(terms) > 0 {
			size = searchPage
		}
		body := map[string]any{
			"size": size, "track_total_hits": false,
			"query": map[string]any{"bool": map[string]any{"filter": filters}},
			"sort":  []any{map[string]any{"time": map[string]any{"order": "desc"}}, map[string]any{"id": map[string]any{"order": "asc"}}},
		}
		if after != nil {
			body["search_after"] = after
		}
		raw, _ := json.Marshal(body)
		var resp struct {
			Hits struct {
				Hits []struct {
					Source source            `json:"_source"`
					Sort   []json.RawMessage `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if err := s.do(ctx, http.MethodPost, "/"+s.indexName(q.Index)+"/_search?ignore_unavailable=true&allow_no_indices=true", raw, &resp); err != nil {
			return nil, err
		}
		hits := resp.Hits.Hits
		for _, h := range hits {
			d, err := toDoc(h.Source)
			if err != nil {
				return nil, err
			}
			if !hasTerms(d.Body, terms) || !hasFields(d.Fields, q.Filters) {
				continue
			}
			out = append(out, d)
			if len(out) == limit {
				break
			}
		}
		if len(hits) < size {
			break
		}
		after = hits[len(hits)-1].Sort
	}
	return out, nil
}

// The hash narrows candidates; only the original fields establish an exact
// match. In particular, NUL in a name or value can cross the hash's separator.
func hasFields(fields, want map[string]string) bool {
	for k, v := range want {
		if got, ok := fields[k]; !ok || got != v {
			return false
		}
	}
	return true
}

func toDoc(src source) (store.Document, error) {
	t, err := time.Parse(time.RFC3339Nano, src.Time)
	if err != nil {
		return store.Document{}, fmt.Errorf("stored time %q: %w", src.Time, err)
	}
	d := store.Document{ID: src.ID, Time: t.UTC(), Body: src.Doc.Body}
	if src.Doc.HasFields {
		d.Fields = src.Doc.Fields
		if d.Fields == nil {
			d.Fields = map[string]string{}
		}
	}
	return d, nil
}

func hasTerms(body string, terms []string) bool {
	lower := strings.ToLower(body)
	for _, t := range terms {
		if !strings.Contains(lower, t) {
			return false
		}
	}
	return true
}

// Close implements store.SearchStore.
func (s *SearchStore) Close() error {
	s.closed.Store(true)
	return nil
}

// DeleteIndexes deletes every index this store's prefix covers. Tests use it
// to clean up.
func (s *SearchStore) DeleteIndexes(ctx context.Context) error {
	var rows []struct {
		Index string `json:"index"`
	}
	if err := s.do(ctx, http.MethodGet, "/_cat/indices/"+s.prefix+"-*?format=json&h=index", nil, &rows); err != nil {
		return err
	}
	for _, r := range rows {
		if !strings.HasPrefix(r.Index, s.prefix+"-") {
			continue
		}
		if err := s.do(ctx, http.MethodDelete, "/"+r.Index, nil, nil, http.StatusNotFound); err != nil {
			return err
		}
	}
	return nil
}

// Name implements selfmon.Collector.
func (s *SearchStore) Name() string { return "searchstore" }

// Collect implements selfmon.Collector.
func (s *SearchStore) Collect(b *selfmon.Batch) {
	up := 1.0
	if s.closed.Load() {
		up = 0
	}
	b.Gauge("observex_searchstore_up", "1 until the store is closed.", up)
	b.Counter("observex_searchstore_documents_indexed_total", "Documents indexed.", float64(s.indexed.Load()))
	b.Counter("observex_searchstore_index_errors_total", "Index calls that failed in OpenSearch.", float64(s.indexErrors.Load()))
	b.Counter("observex_searchstore_searches_total", "Search calls that reached OpenSearch.", float64(s.searches.Load()))
	b.Counter("observex_searchstore_search_errors_total", "Search calls that failed in OpenSearch.", float64(s.searchErrors.Load()))
}
