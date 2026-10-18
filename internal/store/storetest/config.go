package storetest

import (
	"fmt"
	"sync"
	"testing"

	"github.com/ObservexINC/Observex_managed/internal/store"
)

// ConfigStore runs the ConfigurationStore contract against stores from open.
func ConfigStore(t *testing.T, open func(t *testing.T) store.ConfigStore) {
	t.Run("create, read, compare-and-set update", func(t *testing.T) {
		c := open(t)
		r1, err := c.Put(ctx(t), "users/akash", []byte(`{"role":"owner"}`), store.MustNotExist)
		noErr(t, "create", err)
		kv, err := c.Get(ctx(t), "users/akash")
		noErr(t, "get", err)
		if kv.Revision != r1 || string(kv.Value) != `{"role":"owner"}` {
			t.Fatalf("got %+v", kv)
		}
		r2, err := c.Put(ctx(t), "users/akash", []byte(`{"role":"admin"}`), r1)
		noErr(t, "update", err)
		if r2 <= r1 {
			t.Fatalf("revision did not increase: %d then %d", r1, r2)
		}
		_, err = c.Put(ctx(t), "users/akash", []byte("stale"), r1)
		wantErr(t, "stale update", err, store.ErrConflict)
		_, err = c.Put(ctx(t), "users/akash", []byte("again"), store.MustNotExist)
		wantErr(t, "create existing", err, store.ErrConflict)
		_, err = c.Put(ctx(t), "users/nobody", []byte("x"), r2)
		wantErr(t, "update missing", err, store.ErrConflict)
	})

	t.Run("revisions increase across keys", func(t *testing.T) {
		c := open(t)
		a, err := c.Put(ctx(t), "a", []byte("1"), store.AnyRevision)
		noErr(t, "put a", err)
		b, err := c.Put(ctx(t), "b", []byte("1"), store.AnyRevision)
		noErr(t, "put b", err)
		if b <= a {
			t.Fatalf("revision of b (%d) not above a (%d)", b, a)
		}
	})

	t.Run("only one concurrent create wins", func(t *testing.T) {
		c := open(t)
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if _, err := c.Put(ctx(t), "tokens/used/abc", []byte(fmt.Sprint(i)), store.MustNotExist); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}(i)
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d creates succeeded, want exactly 1", wins)
		}
	})

	t.Run("delete with revision", func(t *testing.T) {
		c := open(t)
		r, err := c.Put(ctx(t), "rules/r1", []byte("x"), store.MustNotExist)
		noErr(t, "put", err)
		wantErr(t, "wrong revision", c.Delete(ctx(t), "rules/r1", r+100), store.ErrConflict)
		wantErr(t, "must-not-exist", c.Delete(ctx(t), "rules/r1", store.MustNotExist), store.ErrInvalid)
		noErr(t, "delete", c.Delete(ctx(t), "rules/r1", r))
		_, err = c.Get(ctx(t), "rules/r1")
		wantErr(t, "get deleted", err, store.ErrNotFound)
		wantErr(t, "delete missing", c.Delete(ctx(t), "rules/r1", store.AnyRevision), store.ErrNotFound)
	})

	t.Run("delete validates arguments before the key's state", func(t *testing.T) {
		c := open(t)
		r, err := c.Put(ctx(t), "present", []byte("x"), store.MustNotExist)
		noErr(t, "put", err)
		for _, key := range []string{"present", "absent"} {
			for _, bad := range []store.Revision{store.MustNotExist, store.Revision(-2), store.Revision(-100)} {
				wantErr(t, fmt.Sprintf("delete %s with revision %d", key, bad), c.Delete(ctx(t), key, bad), store.ErrInvalid)
			}
		}
		wantErr(t, "delete empty key", c.Delete(ctx(t), "", store.AnyRevision), store.ErrInvalid)
		wantErr(t, "delete absent with any revision", c.Delete(ctx(t), "absent", store.AnyRevision), store.ErrNotFound)
		wantErr(t, "delete absent with a positive revision", c.Delete(ctx(t), "absent", r), store.ErrNotFound)
		// Rejected calls changed nothing and did not advance the revision.
		kv, err := c.Get(ctx(t), "present")
		noErr(t, "get", err)
		if kv.Revision != r {
			t.Fatalf("revision moved from %d to %d after rejected deletes", r, kv.Revision)
		}
		next, err := c.Put(ctx(t), "other", []byte("y"), store.MustNotExist)
		noErr(t, "put other", err)
		if next != r+1 {
			t.Fatalf("next revision %d, want %d: a rejected call advanced the counter", next, r+1)
		}
		noErr(t, "delete with any revision", c.Delete(ctx(t), "present", store.AnyRevision))
	})

	t.Run("closed store wins over invalid arguments", func(t *testing.T) {
		c := open(t)
		noErr(t, "close", c.Close())
		wantErr(t, "delete after close", c.Delete(ctx(t), "absent", store.MustNotExist), store.ErrClosed)
		_, err := c.Put(ctx(t), "", nil, store.Revision(-7))
		wantErr(t, "put after close", err, store.ErrClosed)
	})

	t.Run("list by prefix, sorted", func(t *testing.T) {
		c := open(t)
		for _, k := range []string{"nodes/3", "nodes/1", "nodes/2", "nodesX", "users/a"} {
			_, err := c.Put(ctx(t), k, []byte(k), store.AnyRevision)
			noErr(t, "put "+k, err)
		}
		got, err := c.List(ctx(t), "nodes/")
		noErr(t, "list", err)
		if len(got) != 3 || got[0].Key != "nodes/1" || got[2].Key != "nodes/3" {
			t.Fatalf("got %+v", got)
		}
		all, err := c.List(ctx(t), "")
		noErr(t, "list all", err)
		if len(all) != 5 {
			t.Fatalf("list all returned %d", len(all))
		}
	})

	t.Run("values are copied", func(t *testing.T) {
		c := open(t)
		v := []byte("original")
		_, err := c.Put(ctx(t), "k", v, store.AnyRevision)
		noErr(t, "put", err)
		v[0] = 'X'
		kv, err := c.Get(ctx(t), "k")
		noErr(t, "get", err)
		kv.Value[1] = 'Y'
		again, err := c.Get(ctx(t), "k")
		noErr(t, "get again", err)
		if string(again.Value) != "original" {
			t.Fatalf("stored value changed to %q", again.Value)
		}
	})

	t.Run("invalid input", func(t *testing.T) {
		c := open(t)
		_, err := c.Put(ctx(t), "", []byte("x"), store.AnyRevision)
		wantErr(t, "empty key", err, store.ErrInvalid)
		_, err = c.Put(ctx(t), "k", []byte("x"), store.Revision(-5))
		wantErr(t, "bad revision", err, store.ErrInvalid)
		_, err = c.Get(ctx(t), "missing")
		wantErr(t, "missing", err, store.ErrNotFound)
	})

	t.Run("cancelled context and closed store", func(t *testing.T) {
		c := open(t)
		if _, err := c.Put(cancelled(), "k", []byte("x"), store.AnyRevision); err == nil {
			t.Fatal("put with cancelled context succeeded")
		}
		noErr(t, "close", c.Close())
		_, err := c.Get(ctx(t), "k")
		wantErr(t, "get after close", err, store.ErrClosed)
		_, err = c.Put(ctx(t), "k", []byte("x"), store.AnyRevision)
		wantErr(t, "put after close", err, store.ErrClosed)
	})
}
