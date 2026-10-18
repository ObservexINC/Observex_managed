package store

import "context"

// Revision orders changes in a ConfigStore. Revisions increase across the
// whole store, so a newer write always has a larger revision.
type Revision int64

const (
	// MustNotExist as the expected revision makes Put create-only.
	MustNotExist Revision = 0
	// AnyRevision as the expected revision makes Put or Delete unconditional.
	AnyRevision Revision = -1
)

// KV is one configuration entry.
type KV struct {
	Key      string
	Value    []byte
	Revision Revision
}

// ConfigStore is the ConfigurationStore contract: small, strongly consistent
// configuration and coordination data (users, rules, tokens, leases).
//
//   - Put with MustNotExist fails with ErrConflict if the key exists; with a
//     positive revision it succeeds only if the key's current revision matches;
//     with AnyRevision it always writes. It returns the new revision.
//   - Delete takes a positive revision or AnyRevision. MustNotExist and
//     revisions below AnyRevision are ErrInvalid, whether or not the key
//     exists; deleting a missing key with a valid revision is ErrNotFound; a
//     positive revision that does not match is ErrConflict.
//   - An empty key is ErrInvalid for Put and Delete.
//   - Errors are checked in this order: a closed store (ErrClosed) or an
//     ended context, then invalid arguments (ErrInvalid), then the key's
//     state (ErrNotFound, ErrConflict). A rejected call changes nothing and
//     does not advance the revision.
//   - List returns entries whose key starts with prefix, sorted by key.
//   - Values are copied in and out; callers cannot change stored bytes.
type ConfigStore interface {
	Get(ctx context.Context, key string) (KV, error)
	Put(ctx context.Context, key string, value []byte, expected Revision) (Revision, error)
	Delete(ctx context.Context, key string, expected Revision) error
	List(ctx context.Context, prefix string) ([]KV, error)
	Close() error
}
