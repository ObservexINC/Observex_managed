package etcdstore

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/namespace"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// Store is a store.ConfigStore over etcd. Revisions are etcd's: they
// increase across the whole cluster, also across stores with different
// prefixes, so a store sees gaps where other stores wrote.
type Store struct {
	kv     clientv3.KV
	close  func() error
	closed atomic.Bool
}

var _ store.ConfigStore = (*Store)(nil)

// New returns a Store over an etcd client, for example one connected to the
// cluster from another process. Keys are stored under prefix. Closing the
// store closes the client.
func New(c *clientv3.Client, prefix string) *Store {
	return newStore(c, prefix, c.Close)
}

func newStore(c *clientv3.Client, prefix string, closeFn func() error) *Store {
	kv := c.KV
	if prefix != "" {
		kv = namespace.NewKV(c.KV, prefix)
	}
	return &Store{kv: kv, close: closeFn}
}

// begin applies the contract's first checks: a closed store, then an ended
// context.
func (s *Store) begin(ctx context.Context) error {
	if s.closed.Load() {
		return store.ErrClosed
	}
	return ctx.Err()
}

// fail maps an etcd error to the contract's errors.
func (s *Store) fail(op, key string, err error) error {
	switch {
	case s.closed.Load():
		return store.ErrClosed
	case errors.Is(err, rpctypes.ErrRequestTooLarge), errors.Is(err, rpctypes.ErrGRPCRequestTooLarge):
		return store.Invalid("%s %q: the request is larger than etcd accepts", op, key)
	default:
		return fmt.Errorf("etcdstore: %s %q: %w", op, key, err)
	}
}

// Get implements store.ConfigStore.
func (s *Store) Get(ctx context.Context, key string) (store.KV, error) {
	if err := s.begin(ctx); err != nil {
		return store.KV{}, err
	}
	if key == "" {
		return store.KV{}, store.ErrNotFound // no entry can have an empty key
	}
	resp, err := s.kv.Get(ctx, key)
	if err != nil {
		return store.KV{}, s.fail("get", key, err)
	}
	if len(resp.Kvs) == 0 {
		return store.KV{}, store.ErrNotFound
	}
	kv := resp.Kvs[0]
	return store.KV{Key: key, Value: append([]byte{}, kv.Value...), Revision: store.Revision(kv.ModRevision)}, nil
}

// Put implements store.ConfigStore.
func (s *Store) Put(ctx context.Context, key string, value []byte, expected store.Revision) (store.Revision, error) {
	if err := s.begin(ctx); err != nil {
		return 0, err
	}
	if key == "" {
		return 0, store.Invalid("config key is empty")
	}
	if expected < store.AnyRevision {
		return 0, store.Invalid("expected revision %d is not valid", expected)
	}
	val := string(value) // copies the caller's bytes
	if expected == store.AnyRevision {
		resp, err := s.kv.Put(ctx, key, val)
		if err != nil {
			return 0, s.fail("put", key, err)
		}
		return store.Revision(resp.Header.Revision), nil
	}
	cmp := clientv3.Compare(clientv3.ModRevision(key), "=", int64(expected))
	if expected == store.MustNotExist {
		cmp = clientv3.Compare(clientv3.CreateRevision(key), "=", 0)
	}
	resp, err := s.kv.Txn(ctx).If(cmp).Then(clientv3.OpPut(key, val)).Commit()
	if err != nil {
		return 0, s.fail("put", key, err)
	}
	if !resp.Succeeded {
		return 0, store.ErrConflict
	}
	return store.Revision(resp.Header.Revision), nil
}

// Delete implements store.ConfigStore.
func (s *Store) Delete(ctx context.Context, key string, expected store.Revision) error {
	if err := s.begin(ctx); err != nil {
		return err
	}
	switch {
	case key == "":
		return store.Invalid("config key is empty")
	case expected == store.MustNotExist:
		return store.Invalid("delete cannot use MustNotExist")
	case expected < store.AnyRevision:
		return store.Invalid("expected revision %d is not valid", expected)
	}
	if expected == store.AnyRevision {
		resp, err := s.kv.Txn(ctx).
			If(clientv3.Compare(clientv3.CreateRevision(key), ">", 0)).
			Then(clientv3.OpDelete(key)).Commit()
		if err != nil {
			return s.fail("delete", key, err)
		}
		if !resp.Succeeded {
			return store.ErrNotFound
		}
		return nil
	}
	resp, err := s.kv.Txn(ctx).
		If(clientv3.Compare(clientv3.ModRevision(key), "=", int64(expected))).
		Then(clientv3.OpDelete(key)).
		Else(clientv3.OpGet(key, clientv3.WithCountOnly())).Commit()
	if err != nil {
		return s.fail("delete", key, err)
	}
	if resp.Succeeded {
		return nil
	}
	if r := resp.Responses[0].GetResponseRange(); r == nil || r.Count == 0 {
		return store.ErrNotFound
	}
	return store.ErrConflict
}

// List implements store.ConfigStore.
func (s *Store) List(ctx context.Context, prefix string) ([]store.KV, error) {
	if err := s.begin(ctx); err != nil {
		return nil, err
	}
	resp, err := s.kv.Get(ctx, prefix, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend))
	if err != nil {
		return nil, s.fail("list", prefix, err)
	}
	out := make([]store.KV, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		out = append(out, store.KV{Key: string(kv.Key), Value: append([]byte{}, kv.Value...), Revision: store.Revision(kv.ModRevision)})
	}
	return out, nil
}

// Close implements store.ConfigStore. Calls after Close return ErrClosed.
func (s *Store) Close() error {
	if s.closed.Swap(true) || s.close == nil {
		return nil
	}
	return s.close()
}
