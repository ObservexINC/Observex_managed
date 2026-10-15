package store

import (
	"context"
	"time"
)

// Document is one searchable record: a log line, an event, a session or a
// synthetic result.
type Document struct {
	ID     string
	Time   time.Time
	Body   string
	Fields map[string]string
}

// Validate checks the document has an ID and a time.
func (d Document) Validate() error {
	if d.ID == "" {
		return Invalid("document needs an ID")
	}
	if d.Time.IsZero() {
		return Invalid("document %q has no time", d.ID)
	}
	return nil
}

// SearchQuery finds documents in one index.
type SearchQuery struct {
	Index string
	// Text holds words that must all appear in the body, ignoring case.
	// Empty matches every document.
	Text string
	// Filters are exact field matches; all must hold.
	Filters map[string]string
	Range   TimeRange
	// Limit caps the result; 0 means DefaultLimit.
	Limit int
}

// SearchStore is the SearchStore contract.
//
//   - Index writes all documents or none; re-indexing an ID replaces it.
//   - Search returns newest first, ties broken by ID ascending, at most Limit.
//   - Indexes are independent: a document is only found in its own index.
type SearchStore interface {
	Index(ctx context.Context, index string, docs []Document) error
	Search(ctx context.Context, q SearchQuery) ([]Document, error)
	Close() error
}
