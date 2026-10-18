package fake

import (
	"bytes"
	"context"
	"sort"
	"strings"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// ConfigStore is an in-memory store.ConfigStore with a store-wide revision
// counter, like etcd.
type ConfigStore struct {
	lifecycle
	rev     store.Revision
	entries map[string]store.KV
}

var _ store.ConfigStore = (*ConfigStore)(nil)

// NewConfigStore returns an empty ConfigStore.
func NewConfigStore() *ConfigStore {
	return &ConfigStore{entries: map[string]store.KV{}}
}

func copyKV(kv store.KV) store.KV {
	kv.Value = bytes.Clone(kv.Value)
	if kv.Value == nil {
		kv.Value = []byte{}
	}
	return kv
}

// Get implements store.ConfigStore.
func (c *ConfigStore) Get(ctx context.Context, key string) (store.KV, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if err := c.check(ctx); err != nil {
		return store.KV{}, err
	}
	kv, ok := c.entries[key]
	if !ok {
		return store.KV{}, store.ErrNotFound
	}
	return copyKV(kv), nil
}

func checkExpected(cur store.KV, exists bool, expected store.Revision) error {
	switch {
	case expected == store.AnyRevision:
		return nil
	case expected == store.MustNotExist:
		if exists {
			return store.ErrConflict
		}
		return nil
	case expected < store.AnyRevision:
		return store.Invalid("expected revision %d is not valid", expected)
	default:
		if !exists || cur.Revision != expected {
			return store.ErrConflict
		}
		return nil
	}
}

// Put implements store.ConfigStore.
func (c *ConfigStore) Put(ctx context.Context, key string, value []byte, expected store.Revision) (store.Revision, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(ctx); err != nil {
		return 0, err
	}
	if key == "" {
		return 0, store.Invalid("config key is empty")
	}
	cur, exists := c.entries[key]
	if err := checkExpected(cur, exists, expected); err != nil {
		return 0, err
	}
	c.rev++
	c.entries[key] = copyKV(store.KV{Key: key, Value: value, Revision: c.rev})
	return c.rev, nil
}

// Delete implements store.ConfigStore.
func (c *ConfigStore) Delete(ctx context.Context, key string, expected store.Revision) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(ctx); err != nil {
		return err
	}
	// Arguments first, so the answer does not depend on whether the key
	// exists.
	switch {
	case key == "":
		return store.Invalid("config key is empty")
	case expected == store.MustNotExist:
		return store.Invalid("delete cannot use MustNotExist")
	case expected < store.AnyRevision:
		return store.Invalid("expected revision %d is not valid", expected)
	}
	cur, exists := c.entries[key]
	if !exists {
		return store.ErrNotFound
	}
	if err := checkExpected(cur, exists, expected); err != nil {
		return err
	}
	delete(c.entries, key)
	c.rev++
	return nil
}

// List implements store.ConfigStore.
func (c *ConfigStore) List(ctx context.Context, prefix string) ([]store.KV, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if err := c.check(ctx); err != nil {
		return nil, err
	}
	out := []store.KV{}
	for k, kv := range c.entries {
		if strings.HasPrefix(k, prefix) {
			out = append(out, copyKV(kv))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Close implements store.ConfigStore.
func (c *ConfigStore) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.close()
	return nil
}
